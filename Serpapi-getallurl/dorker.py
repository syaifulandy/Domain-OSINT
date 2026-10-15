#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import sys
import time

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import serpapi
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo


APP_NAME = "SerpApi Multi-Domain URL Harvester"
APP_VERSION = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "config.toml"


# ============================================================
# CONFIGURATION
# ============================================================

def load_toml(path: Path) -> dict:
    """
    Load TOML using tomllib on Python >= 3.11.
    Falls back to tomli for older Python versions.
    """
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            print(
                "[!] Python < 3.11 terdeteksi dan modul tomli belum terpasang.\n"
                "    Jalankan: pip install tomli"
            )
            sys.exit(1)

    if not path.exists():
        print(f"[!] Config tidak ditemukan: {path}")
        sys.exit(1)

    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except Exception as exc:
        print(f"[!] Gagal membaca config: {exc}")
        sys.exit(1)


def get_config(path: Path) -> dict:
    raw = load_toml(path)

    serpapi_cfg = raw.get("serpapi", {})
    search_cfg = raw.get("search", {})
    output_cfg = raw.get("output", {})
    cache_cfg = raw.get("cache", {})

    api_key = str(serpapi_cfg.get("api_key", "")).strip()

    if not api_key or api_key == "YOUR_SERPAPI_KEY":
        print(f"[!] Isi api_key terlebih dahulu di {path}")
        sys.exit(1)

    max_pages = int(search_cfg.get("max_pages", 10))
    max_pages = max(1, min(max_pages, 10))

    engines = search_cfg.get(
        "engines",
        ["google", "duckduckgo"],
    )

    engines = [
        str(engine).lower().strip()
        for engine in engines
        if str(engine).lower().strip()
        in {"google", "duckduckgo"}
    ]

    if not engines:
        print(
            "[!] Tidak ada engine valid. "
            "Gunakan google dan/atau duckduckgo."
        )
        sys.exit(1)

    return {
        "api_key": api_key,
        "engines": engines,
        "max_pages": max_pages,
        "delay_seconds": max(
            0.0,
            float(search_cfg.get("delay_seconds", 1.0)),
        ),
        "google_gl": str(
            search_cfg.get("google_gl", "id")
        ).strip(),
        "google_hl": str(
            search_cfg.get("google_hl", "id")
        ).strip(),
        "duckduckgo_kl": str(
            search_cfg.get("duckduckgo_kl", "id-en")
        ).strip(),
        "safe_search": bool(
            search_cfg.get("safe_search", True)
        ),
        "use_cache": bool(
            cache_cfg.get("enabled", True)
        ),
        "cache_days": max(
            0,
            int(cache_cfg.get("days", 7)),
        ),
        "output_file": str(
            output_cfg.get("filename", "results.xlsx")
        ),
    }

# ============================================================
# TARGET HANDLING
# ============================================================

def normalize_domain(value: str) -> str | None:
    """
    Normalisasi input target menjadi hostname.

    Input yang didukung:
      abc.co.id
      https://abc.co.id/
      *.abc.co.id
      site:abc.co.id
    """
    value = value.strip().lower()

    if not value:
        return None

    # Bersihkan operator/query dan wildcard.
    value = re.sub(r"^site:", "", value, flags=re.IGNORECASE)
    value = re.sub(r"^\*\.", "", value)

    # Tambahkan scheme agar urlsplit dapat membaca hostname.
    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return None

        hostname = hostname.lower().rstrip(".")

        # Batasi panjang total hostname.
        if len(hostname) > 253:
            return None

        labels = hostname.split(".")

        # Minimal harus memiliki domain dan TLD.
        if len(labels) < 2:
            return None

        for label in labels:
            # Setiap label DNS maksimal 63 karakter.
            if not label or len(label) > 63:
                return None

            # Label hanya boleh berisi huruf, angka, dan tanda minus.
            if not re.fullmatch(r"[a-z0-9-]+", label):
                return None

            # Label tidak boleh diawali atau diakhiri tanda minus.
            if label.startswith("-") or label.endswith("-"):
                return None

        return hostname

    except ValueError:
        return None


def load_targets(values: list[str]) -> list[str]:
    """
    Input dapat berupa:
      python dorker.py abc.co.id xyz.co.id
      python dorker.py domains.txt
      python dorker.py abc.co.id domains.txt
    """
    targets = []

    for value in values:
        candidate = Path(value)

        if candidate.is_file():
            try:
                lines = candidate.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).splitlines()
            except OSError as exc:
                print(f"[!] Gagal membaca {candidate}: {exc}")
                continue

            for line in lines:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                # Support comma-separated input too.
                for item in line.split(","):
                    domain = normalize_domain(item)

                    if domain:
                        targets.append(domain)
                    else:
                        print(f"[!] Target tidak valid, dilewati: {item.strip()}")
        else:
            domain = normalize_domain(value)

            if domain:
                targets.append(domain)
            else:
                print(f"[!] Target tidak valid, dilewati: {value}")

    return sorted(set(targets))


# ============================================================
# URL HANDLING
# ============================================================

def normalize_url(url: str) -> str | None:
    """
    Canonicalization ringan:
    - Hanya HTTP/HTTPS.
    - Scheme dan hostname lowercase.
    - Fragment dihapus.
    - Default port dihapus.
    - Root path dibuat '/'.
    """
    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url:
        return None

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return None

        hostname = parsed.hostname

        if not hostname:
            return None

        scheme = parsed.scheme.lower()
        hostname = hostname.lower().rstrip(".")

        try:
            port = parsed.port
        except ValueError:
            return None

        if port and not (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        path = parsed.path or "/"

        return urlunsplit(
            (
                scheme,
                netloc,
                path,
                parsed.query,
                "",  # Remove fragment.
            )
        )

    except ValueError:
        return None


def get_hostname(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_in_scope(url: str, root_domain: str) -> bool:
    hostname = get_hostname(url)

    return (
        hostname == root_domain
        or hostname.endswith(f".{root_domain}")
    )


def url_fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def page_signature(urls: list[str]) -> str:
    """
    Mendeteksi halaman identik walaupun posisi result berubah.
    """
    joined = "\n".join(sorted(set(urls)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


# ============================================================
# CACHE
# ============================================================

def cache_file_path(cache_dir: Path, domain: str, engine: str) -> Path:
    safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    return cache_dir / f"{safe_domain}_{engine}.json"


def load_cache(
    cache_dir: Path,
    domain: str,
    engine: str,
    cache_days: int,
) -> dict | None:
    path = cache_file_path(cache_dir, domain, engine)

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        created_at = datetime.fromisoformat(data["created_at"])

        if datetime.now() - created_at > timedelta(days=cache_days):
            return None

        if data.get("domain") != domain:
            return None

        if data.get("engine") != engine:
            return None

        return data

    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def save_cache(
    cache_dir: Path,
    domain: str,
    engine: str,
    records: list[dict],
    pages_checked: int,
    api_calls: int,
    stop_reason: str,
) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "domain": domain,
        "engine": engine,
        "pages_checked": pages_checked,
        "api_calls": api_calls,
        "stop_reason": stop_reason,
        "records": records,
    }

    path = cache_file_path(cache_dir, domain, engine)

    try:
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"[!] Gagal menyimpan cache {path}: {exc}")


# ============================================================
# SERPAPI SEARCH
# ============================================================

def build_search_params(
    domain: str,
    engine: str,
    config: dict,
) -> dict:
    query = f"site:{domain}"

    params = {
        "engine": engine,
        "q": query,
        "device": "desktop",
        "no_cache": False,
    }

    if engine == "google":
        params.update(
            {
                "google_domain": "google.com",
                "gl": config["google_gl"],
                "hl": config["google_hl"],
                "safe": (
                    "active"
                    if config["safe_search"]
                    else "off"
                ),
                "filter": "0",
                "num": 100,
            }
        )

    elif engine == "duckduckgo":
        params.update(
            {
                # Region Indonesia, bahasa Inggris.
                "kl": config.get("duckduckgo_kl", "id-en"),

                # DuckDuckGo:
                #  1 = Strict
                # -1 = Moderate
                # -2 = Off
                "safe": (
                    1
                    if config["safe_search"]
                    else -2
                ),

                # Maksimum hasil per request.
                "m": 50,
            }
        )

    else:
        raise ValueError(f"Engine tidak didukung: {engine}")

    return params


def extract_records(
    results,
    domain: str,
    engine: str,
    page_number: int,
) -> tuple[list[dict], int]:
    organic_results = results.get("organic_results", []) or []
    extracted = []

    for item in organic_results:
        raw_url = item.get("link") or item.get("url")
        normalized = normalize_url(raw_url)

        if not normalized:
            continue

        # site: kadang tetap menghasilkan URL eksternal. Buang yang out-of-scope.
        if not is_in_scope(normalized, domain):
            continue

        extracted.append(
            {
                "domain": domain,
                "subdomain": get_hostname(normalized),
                "engine": engine,
                "page": page_number,
                "position": item.get("position", ""),
                "url": normalized,
                "title": str(item.get("title", "") or ""),
                "snippet": str(item.get("snippet", "") or ""),
                "displayed_link": str(
                    item.get("displayed_link", "") or ""
                ),
                "date": str(item.get("date", "") or ""),
            }
        )

    return extracted, len(organic_results)


def has_next_page(results) -> bool:
    """
    Support SerpResults modern dan fallback dictionary response.
    """
    try:
        next_url = results.next_page_url

        if next_url:
            return True
    except (AttributeError, TypeError):
        pass

    pagination = results.get("serpapi_pagination", {}) or {}

    return bool(
        pagination.get("next")
        or pagination.get("next_link")
    )


def get_next_page(results):
    """
    Menggunakan next_page() agar offset Google/duckduckgo diurus oleh SerpApi.
    """
    try:
        return results.next_page()
    except AttributeError as exc:
        raise RuntimeError(
            "Library serpapi yang terpasang tidak mendukung next_page(). "
            "Pastikan package 'serpapi' versi terbaru terpasang."
        ) from exc


def search_engine(
    client,
    domain: str,
    engine: str,
    config: dict,
) -> dict:
    max_pages = config["max_pages"]
    delay = config["delay_seconds"]

    all_records = []
    seen_urls = set()
    seen_page_signatures = set()

    pages_checked = 0
    api_calls = 0
    stop_reason = "maximum page limit reached"
    error_message = ""

    params = build_search_params(domain, engine, config)

    print(f"\n  [{engine.upper()}] Query: {params['q']}")

    try:
        results = client.search(params)
        api_calls += 1

        for page_number in range(1, max_pages + 1):
            pages_checked += 1

            if results is None:
                stop_reason = "no response"
                print(
                    f"    Page {page_number:02d}: no response"
                    f" | STOP"
                )
                break

            if results.get("error"):
                error_text = str(results.get("error"))
                error_lower = error_text.lower()

                # Beberapa engine mengembalikan pesan ini ketika pagination
                # sudah mencapai akhir. Ini bukan error fatal apabila halaman
                # sebelumnya sudah menghasilkan URL.
                no_result_messages = (
                    "hasn't returned any results",
                    "has not returned any results",
                    "no results",
                    "no organic results",
                )

                is_no_result = any(
                    message in error_lower
                    for message in no_result_messages
                )

                if is_no_result:
                    if all_records:
                        stop_reason = "end of results"
                        error_message = ""

                        print(
                            f"    Page {page_number:02d}: 0 result"
                            f" | STOP: akhir hasil pencarian"
                        )
                    else:
                        stop_reason = "no results found"
                        error_message = ""

                        print(
                            f"    Page {page_number:02d}: 0 result"
                            f" | STOP: tidak ditemukan hasil"
                        )

                    break

                # Error sesungguhnya, misalnya API key, quota, atau request failure.
                error_message = error_text
                stop_reason = "SerpApi error"

                print(
                    f"    Page {page_number:02d}: ERROR"
                    f" | {error_message}"
                )
                break

            records, organic_count = extract_records(
                results=results,
                domain=domain,
                engine=engine,
                page_number=page_number,
            )

            page_urls = [record["url"] for record in records]

            if organic_count == 0:
                stop_reason = "empty organic results"
                print(
                    f"    Page {page_number:02d}:"
                    f" 0 result | STOP: empty page"
                )
                break

            if not page_urls:
                stop_reason = "no in-scope URL"
                print(
                    f"    Page {page_number:02d}:"
                    f" {organic_count} result"
                    f" | 0 in-scope"
                    f" | STOP"
                )
                break

            signature = page_signature(page_urls)

            if signature in seen_page_signatures:
                stop_reason = "repeated result page"
                print(
                    f"    Page {page_number:02d}:"
                    f" {organic_count} result"
                    f" | STOP: repeated page"
                )
                break

            seen_page_signatures.add(signature)

            new_count = 0

            for record in records:
                fingerprint = url_fingerprint(record["url"])

                if fingerprint in seen_urls:
                    continue

                seen_urls.add(fingerprint)
                all_records.append(record)
                new_count += 1

            print(
                f"    Page {page_number:02d}:"
                f" {organic_count} result"
                f" | +{new_count} URL baru"
                f" | total {len(all_records)}"
            )

            if new_count == 0:
                stop_reason = "no new URLs"
                print("    STOP: tidak ada URL baru")
                break

            if page_number >= max_pages:
                stop_reason = "maximum page limit reached"
                break

            if not has_next_page(results):
                stop_reason = "no next page"
                print("    STOP: pagination berikutnya tidak tersedia")
                break

            # Delay hanya sebelum request halaman berikutnya.
            if delay > 0:
                time.sleep(delay)

            try:
                results = get_next_page(results)
                api_calls += 1
            except Exception as exc:
                error_message = str(exc)
                stop_reason = "next page error"
                print(f"    STOP: gagal mengambil page berikutnya: {exc}")
                break

    except Exception as exc:
        error_message = str(exc)
        stop_reason = "search error"
        print(f"    [!] Search error: {exc}")

    return {
        "domain": domain,
        "engine": engine,
        "records": all_records,
        "pages_checked": pages_checked,
        "api_calls": api_calls,
        "stop_reason": stop_reason,
        "error": error_message,
        "from_cache": False,
    }


# ============================================================
# DEDUPLICATION
# ============================================================

def merge_records(records: list[dict]) -> list[dict]:
    """
    Satu URL dapat ditemukan oleh Google dan duckduckgo.

    Output utama dibuat satu baris per URL:
      engine = google,duckduckgo
      sources = jumlah engine yang menemukan URL
    """
    merged = {}

    for record in records:
        key = record["url"]

        if key not in merged:
            merged[key] = {
                **record,
                "_engines": {record["engine"]},
                "_pages": {str(record["page"])},
            }
            continue

        existing = merged[key]
        existing["_engines"].add(record["engine"])
        existing["_pages"].add(str(record["page"]))

        if not existing.get("title") and record.get("title"):
            existing["title"] = record["title"]

        if not existing.get("snippet") and record.get("snippet"):
            existing["snippet"] = record["snippet"]

        if not existing.get("displayed_link") and record.get(
            "displayed_link"
        ):
            existing["displayed_link"] = record["displayed_link"]

        if not existing.get("date") and record.get("date"):
            existing["date"] = record["date"]

    output = []

    for record in merged.values():
        record["engine"] = ",".join(sorted(record.pop("_engines")))
        record["page"] = ",".join(
            sorted(
                record.pop("_pages"),
                key=lambda value: int(value),
            )
        )
        output.append(record)

    return sorted(
        output,
        key=lambda item: (
            item["domain"],
            item["subdomain"],
            item["url"],
        ),
    )


# ============================================================
# EXCEL
# ============================================================

HEADER_FILL = PatternFill(
    fill_type="solid",
    fgColor="1F4E78",
)

HEADER_FONT = Font(
    color="FFFFFF",
    bold=True,
)

LINK_FONT = Font(
    color="0563C1",
    underline="single",
)


def style_sheet(
    worksheet,
    table_name: str,
    widths: dict[str, int],
) -> None:
    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions

    for cell in worksheet[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(
            horizontal="center",
            vertical="center",
        )

    worksheet.row_dimensions[1].height = 22

    for column, width in widths.items():
        worksheet.column_dimensions[column].width = width

    for row in worksheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(
                vertical="top",
                wrap_text=True,
            )

    if worksheet.max_row >= 2 and worksheet.max_column >= 1:
        table = Table(
            displayName=table_name,
            ref=worksheet.dimensions,
        )

        style = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )

        table.tableStyleInfo = style
        worksheet.add_table(table)


def create_excel(
    output_path: Path,
    records: list[dict],
    run_logs: list[dict],
    started_at: datetime,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    workbook = Workbook()

    # --------------------------------------------------------
    # URLs SHEET
    # --------------------------------------------------------
    url_sheet = workbook.active
    url_sheet.title = "URLs"

    url_headers = [
        "No",
        "Domain",
        "Subdomain",
        "Engine",
        "Page",
        "Position",
        "URL",
        "Title",
        "Snippet",
        "Displayed Link",
        "Result Date",
    ]

    url_sheet.append(url_headers)

    for index, record in enumerate(records, start=1):
        url_sheet.append(
            [
                index,
                record["domain"],
                record["subdomain"],
                record["engine"],
                record["page"],
                record["position"],
                record["url"],
                record["title"],
                record["snippet"],
                record["displayed_link"],
                record["date"],
            ]
        )

        url_cell = url_sheet.cell(
            row=url_sheet.max_row,
            column=7,
        )
        url_cell.hyperlink = record["url"]
        url_cell.font = LINK_FONT

    style_sheet(
        url_sheet,
        "URLResults",
        {
            "A": 8,
            "B": 25,
            "C": 35,
            "D": 18,
            "E": 10,
            "F": 10,
            "G": 80,
            "H": 45,
            "I": 80,
            "J": 50,
            "K": 18,
        },
    )

    # --------------------------------------------------------
    # SUBDOMAINS SHEET
    # --------------------------------------------------------
    subdomain_sheet = workbook.create_sheet("Subdomains")
    subdomain_sheet.append(
        [
            "No",
            "Domain",
            "Subdomain",
            "URL Count",
            "Engines",
        ]
    )

    subdomain_data = defaultdict(
        lambda: {
            "urls": set(),
            "engines": set(),
        }
    )

    for record in records:
        key = (record["domain"], record["subdomain"])
        subdomain_data[key]["urls"].add(record["url"])

        for engine in record["engine"].split(","):
            subdomain_data[key]["engines"].add(engine.strip())

    for index, ((domain, subdomain), data) in enumerate(
        sorted(subdomain_data.items()),
        start=1,
    ):
        subdomain_sheet.append(
            [
                index,
                domain,
                subdomain,
                len(data["urls"]),
                ",".join(sorted(data["engines"])),
            ]
        )

    style_sheet(
        subdomain_sheet,
        "SubdomainResults",
        {
            "A": 8,
            "B": 30,
            "C": 40,
            "D": 15,
            "E": 20,
        },
    )

    # --------------------------------------------------------
    # SUMMARY SHEET
    # --------------------------------------------------------
    summary_sheet = workbook.create_sheet("Summary")
    summary_sheet.append(
        [
            "Domain",
            "Unique URLs",
            "Subdomains",
            "Google URLs",
            "duckduckgo URLs",
            "Pages Checked",
            "API Calls",
            "Cache Used",
            "Errors",
        ]
    )

    summary = defaultdict(
        lambda: {
            "urls": set(),
            "subdomains": set(),
            "google": set(),
            "duckduckgo": set(),
            "pages_checked": 0,
            "api_calls": 0,
            "cache_used": False,
            "errors": [],
        }
    )

    for record in records:
        domain_data = summary[record["domain"]]
        domain_data["urls"].add(record["url"])
        domain_data["subdomains"].add(record["subdomain"])

        engines = {
            engine.strip()
            for engine in record["engine"].split(",")
        }

        if "google" in engines:
            domain_data["google"].add(record["url"])

        if "duckduckgo" in engines:
            domain_data["duckduckgo"].add(record["url"])

    for log in run_logs:
        domain_data = summary[log["domain"]]
        domain_data["pages_checked"] += log["pages_checked"]
        domain_data["api_calls"] += log["api_calls"]
        domain_data["cache_used"] |= log["from_cache"]

        if log.get("error"):
            domain_data["errors"].append(
                f"{log['engine']}: {log['error']}"
            )

    for domain in sorted(summary):
        data = summary[domain]

        summary_sheet.append(
            [
                domain,
                len(data["urls"]),
                len(data["subdomains"]),
                len(data["google"]),
                len(data["duckduckgo"]),
                data["pages_checked"],
                data["api_calls"],
                "Yes" if data["cache_used"] else "No",
                " | ".join(data["errors"]),
            ]
        )

    style_sheet(
        summary_sheet,
        "DomainSummary",
        {
            "A": 30,
            "B": 15,
            "C": 15,
            "D": 15,
            "E": 15,
            "F": 18,
            "G": 15,
            "H": 15,
            "I": 60,
        },
    )

    # --------------------------------------------------------
    # RUN LOG SHEET
    # --------------------------------------------------------
    log_sheet = workbook.create_sheet("Run Log")
    log_sheet.append(
        [
            "Domain",
            "Engine",
            "Pages Checked",
            "API Calls",
            "URLs Collected",
            "From Cache",
            "Stop Reason",
            "Error",
        ]
    )

    for log in run_logs:
        log_sheet.append(
            [
                log["domain"],
                log["engine"],
                log["pages_checked"],
                log["api_calls"],
                len(log["records"]),
                "Yes" if log["from_cache"] else "No",
                log["stop_reason"],
                log.get("error", ""),
            ]
        )

    style_sheet(
        log_sheet,
        "ExecutionLog",
        {
            "A": 30,
            "B": 15,
            "C": 18,
            "D": 15,
            "E": 20,
            "F": 15,
            "G": 40,
            "H": 70,
        },
    )

    # --------------------------------------------------------
    # INFO SHEET
    # --------------------------------------------------------
    info_sheet = workbook.create_sheet("Info")
    finished_at = datetime.now()

    info_rows = [
        ("Application", APP_NAME),
        ("Version", APP_VERSION),
        ("Started At", started_at.isoformat(timespec="seconds")),
        ("Finished At", finished_at.isoformat(timespec="seconds")),
        (
            "Elapsed Seconds",
            round((finished_at - started_at).total_seconds(), 2),
        ),
        ("Unique URLs", len(records)),
        (
            "Total API Calls",
            sum(log["api_calls"] for log in run_logs),
        ),
        (
            "Note",
            "Gunakan hanya untuk domain yang diizinkan untuk diuji.",
        ),
    ]

    for key, value in info_rows:
        info_sheet.append([key, value])

    info_sheet.column_dimensions["A"].width = 25
    info_sheet.column_dimensions["B"].width = 80

    for cell in info_sheet["A"]:
        cell.font = Font(bold=True)

    workbook.save(output_path)


# ============================================================
# CLI
# ============================================================
def parse_arguments():
    examples = """
Contoh penggunaan:

  # Cari satu domain
  python3 dorker.py abc.co.id

  # Cari beberapa domain sekaligus
  python3 dorker.py abc.co.id xyz.co.id example.com

  # Baca target dari file
  python3 dorker.py domains.txt

  # Gabungkan file target dan domain langsung
  python3 dorker.py domains.txt additional.co.id

  # Batasi maksimal 3 halaman per engine
  python3 dorker.py domains.txt --max-pages 3

  # Abaikan cache dan lakukan pencarian ulang
  python3 dorker.py domains.txt --no-cache

  # Hapus cache sebelum melakukan pencarian
  python3 dorker.py domains.txt --clear-cache

  # Tentukan nama file output
  python3 dorker.py domains.txt -o hasil_dorking.xlsx

  # Gunakan file config lain
  python3 dorker.py domains.txt -c config-production.toml

Format domains.txt:

  abc.co.id
  xyz.co.id
  example.com

Output default:

  output/results.xlsx
"""

    parser = argparse.ArgumentParser(
        description=(
            "Mengumpulkan URL terindeks dari Google dan duckduckgo melalui "
            "SerpApi, lalu menyimpan seluruh hasil ke satu file Excel."
        ),
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help=(
            "Domain atau file berisi daftar domain. "
            "Dapat memasukkan satu atau beberapa target."
        ),
    )

    parser.add_argument(
        "-c",
        "--config",
        default=str(DEFAULT_CONFIG),
        help=(
            "Lokasi file konfigurasi TOML. "
            "Default: config.toml"
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Lokasi file output Excel. "
            "Default: output/results.xlsx"
        ),
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Abaikan cache lokal dan lakukan pencarian baru.",
    )

    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Hapus seluruh cache sebelum melakukan pencarian.",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        choices=range(1, 11),
        metavar="1-10",
        help=(
            "Maksimum halaman yang diperiksa per engine dan domain. "
            "Default: mengikuti config.toml, maksimal 10."
        ),
    )

    args = parser.parse_args()

    if not args.targets:
        parser.print_help()
        print(
            "\n[!] Masukkan minimal satu domain "
            "atau file berisi daftar domain."
        )
        sys.exit(1)

    return args


def main():
    args = parse_arguments()
    started_at = datetime.now()

    print("=" * 68)
    print(f"{APP_NAME} v{APP_VERSION}")
    print("=" * 68)

    config_path = Path(args.config).expanduser().resolve()
    config = get_config(config_path)

    if args.max_pages is not None:
        config["max_pages"] = args.max_pages

    if args.no_cache:
        config["use_cache"] = False

    targets = load_targets(args.targets)

    if not targets:
        print("[!] Tidak ada target valid.")
        sys.exit(1)

    cache_dir = BASE_DIR / "cache"
    default_output_dir = BASE_DIR / "output"

    if args.clear_cache and cache_dir.exists():
        for cache_file in cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except OSError as exc:
                print(f"[!] Gagal menghapus {cache_file}: {exc}")

        print("[+] Cache telah dibersihkan.")

    if args.output:
        output_path = Path(args.output).expanduser()

        if not output_path.is_absolute():
            output_path = BASE_DIR / output_path
    else:
        output_path = default_output_dir / config["output_file"]

    if output_path.suffix.lower() != ".xlsx":
        output_path = output_path.with_suffix(".xlsx")

    print(f"[+] Target       : {len(targets)}")
    print(f"[+] Engines     : {', '.join(config['engines'])}")
    print(f"[+] Max pages   : {config['max_pages']} per engine/domain")
    print(f"[+] Local cache : {'ON' if config['use_cache'] else 'OFF'}")
    print(f"[+] Output      : {output_path}")

    client = serpapi.Client(api_key=config["api_key"])

    collected_records = []
    run_logs = []

    for target_index, domain in enumerate(targets, start=1):
        print("\n" + "=" * 68)
        print(f"[{target_index}/{len(targets)}] DOMAIN: {domain}")
        print("=" * 68)

        for engine in config["engines"]:
            cached = None

            if config["use_cache"]:
                cached = load_cache(
                    cache_dir=cache_dir,
                    domain=domain,
                    engine=engine,
                    cache_days=config["cache_days"],
                )

            if cached:
                print(
                    f"\n  [{engine.upper()}] CACHE:"
                    f" {len(cached.get('records', []))} URL"
                )

                result = {
                    "domain": domain,
                    "engine": engine,
                    "records": cached.get("records", []),
                    "pages_checked": cached.get("pages_checked", 0),
                    "api_calls": 0,
                    "stop_reason": "loaded from local cache",
                    "error": "",
                    "from_cache": True,
                }
            else:
                result = search_engine(
                    client=client,
                    domain=domain,
                    engine=engine,
                    config=config,
                )

                if config["use_cache"] and not result["error"]:
                    save_cache(
                        cache_dir=cache_dir,
                        domain=domain,
                        engine=engine,
                        records=result["records"],
                        pages_checked=result["pages_checked"],
                        api_calls=result["api_calls"],
                        stop_reason=result["stop_reason"],
                    )

            collected_records.extend(result["records"])
            run_logs.append(result)

    merged_records = merge_records(collected_records)

    print("\n" + "=" * 68)
    print("[*] Membuat Excel...")
    print("=" * 68)

    try:
        create_excel(
            output_path=output_path,
            records=merged_records,
            run_logs=run_logs,
            started_at=started_at,
        )
    except PermissionError:
        print(
            f"[!] Gagal menulis {output_path}\n"
            "    Kemungkinan file sedang dibuka di Excel. Tutup file lalu ulangi."
        )
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Gagal membuat Excel: {exc}")
        sys.exit(1)

    total_calls = sum(log["api_calls"] for log in run_logs)
    total_subdomains = len(
        {
            (record["domain"], record["subdomain"])
            for record in merged_records
        }
    )

    print(f"[+] Domain       : {len(targets)}")
    print(f"[+] Unique URLs  : {len(merged_records)}")
    print(f"[+] Subdomains   : {total_subdomains}")
    print(f"[+] API calls    : {total_calls}")
    print(f"[+] Excel output : {output_path}")
    print("[+] Selesai.")


if __name__ == "__main__":
    main()
