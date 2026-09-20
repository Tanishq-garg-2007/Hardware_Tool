import os
import sys
import json
import lzma
import sqlite3
import datetime
import threading
import shutil
import urllib.request
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Global State Tracker for real-time frontend monitoring
_update_state = {
    "is_updating": False,
    "current_step": "idle",
    "progress_percent": 0,
    "status_message": "Ready",
    "error": None,
    "last_download_time": None,
}
_state_lock = threading.RLock()
_abort_event = threading.Event()

def is_internet_available(timeout: float = 2.0) -> bool:
    """
    Checks if an active internet connection is available.
    Uses socket connections to reliable DNS/HTTP endpoints with a short timeout.
    Returns False when offline, air-gapped, or network unreachable.
    """
    import socket
    test_endpoints = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("github.com", 443),
    ]
    for host, port in test_endpoints:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.timeout, OSError):
            continue
    return False

def auto_sync_if_online(force: bool = False) -> dict:
    """
    Intelligent sync logic for CVE scanning:
    1. Detects if an active internet connection is available.
    2. If NOT available: returns offline status, no download/sync is attempted,
       allowing the scan to proceed 100% offline with the existing local database.
    3. If available: checks if the database needs an update or sync.
       If missing, downloads/initializes. If outdated, triggers background sync.
    """
    online = is_internet_available(timeout=2.0)
    if not online:
        return {
            "online": False,
            "action": "offline_mode",
            "message": "Offline mode active: No internet connection detected. Continuing scan with local offline database.",
            "total_records": count_cves(),
        }

    cve_count = count_cves()
    check = check_should_update()

    if cve_count == 0:
        # Database is completely missing - perform download and sync
        try:
            print("[+] Online: CVE database missing, starting download...")
            _download_and_extract_task(force=True)
            return {
                "online": True,
                "action": "downloaded",
                "message": "Online: CVE database was missing. Downloaded and indexed NIST NVD database.",
                "total_records": count_cves(),
            }
        except Exception as err:
            return {
                "online": True,
                "action": "error",
                "message": f"Online: Error downloading initial CVE database: {err}",
                "total_records": count_cves(),
            }

    if check["needs_update"] or force:
        print(f"[+] Online: Database update needed ({check['reason']}). Triggering auto-sync in background...")
        trigger_database_update(force=force)
        return {
            "online": True,
            "action": "sync_triggered",
            "message": f"Online: Automatic database sync triggered in background ({check['reason']}).",
            "total_records": cve_count,
        }

    # Initialize EPSS dataset if online and table is unpopulated
    if count_epss_records() == 0:
        try:
            print("[+] Online: EPSS table is empty. Auto-initializing FIRST EPSS dataset...")
            sync_epss_database(force=False)
        except Exception as epss_err:
            print(f"[!] Note: Could not auto-initialize EPSS: {epss_err}")

    return {
        "online": True,
        "action": "up_to_date",
        "message": f"Online: Database is already up to date ({cve_count:,} records).",
        "total_records": cve_count,
    }

def get_cve_db_dir() -> Path:
    env_path = os.getenv("NVD_DB_DIR", "../data/nvd_db")
    base_dir = Path(__file__).resolve().parent
    resolved = (base_dir / env_path).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved

def get_nvd_db_path() -> Path:
    return get_cve_db_dir() / "nvd_cves.db"

def init_nvd_sqlite(db_path: Path):
    """Ensures tables and indexes exist in the NVD database."""
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode = WAL")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        base_score REAL,
        cvss_version TEXT,
        vector TEXT,
        published TEXT,
        last_modified TEXT,
        references_json TEXT,
        weaknesses_json TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cpe_matches (
        cve_id TEXT,
        vendor TEXT,
        product TEXT,
        version_start_inc TEXT,
        version_end_inc TEXT,
        version_start_exc TEXT,
        version_end_exc TEXT,
        vulnerable INTEGER,
        criteria TEXT,
        target_hw TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS epss_scores (
        cve_id TEXT PRIMARY KEY,
        epss REAL,
        percentile REAL,
        score_date TEXT
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_id ON cves(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(base_score)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vp ON cpe_matches(product, vendor)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_p ON cpe_matches(product)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_epss_cve ON epss_scores(cve_id)")
    conn.commit()
    conn.close()

def count_cves(db_dir: Path = None) -> int:
    """Returns the total number of indexed CVEs in the SQLite database."""
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return 0
    try:
        conn = sqlite3.connect(str(db_file), timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        val = cur.fetchone()[0]
        conn.close()
        return val
    except Exception:
        return 0

def check_should_update(db_dir: Path = None) -> dict:
    if db_dir is None:
        db_dir = get_cve_db_dir()

    db_file = get_nvd_db_path()
    date_file = db_dir / "last_updated_date.txt"
    last_updated_str = None
    last_updated_date = None

    if date_file.exists():
        try:
            with open(date_file, "r", encoding="utf-8") as f:
                last_updated_str = f.read().strip()
                last_updated_date = datetime.datetime.strptime(last_updated_str, "%Y-%m-%d").date()
        except Exception:
            last_updated_date = None

    cve_count = count_cves(db_dir)

    if not db_file.exists() or cve_count == 0:
        return {
            "needs_update": True,
            "reason": "NVD Database is empty or missing CVE records.",
            "last_updated": last_updated_str or "Never",
            "days_old": None,
        }

    if last_updated_date is None:
        return {
            "needs_update": True,
            "reason": "No update timestamp recorded on disk.",
            "last_updated": "Unknown",
            "days_old": None,
        }

    current_date = datetime.date.today()
    days_old = (current_date - last_updated_date).days

    if days_old >= 7:
        return {
            "needs_update": True,
            "reason": f"Database is {days_old} days old (update policy is > 7 days).",
            "last_updated": last_updated_str,
            "days_old": days_old,
        }

    return {
        "needs_update": False,
        "reason": f"Database is up to date (updated {days_old} days ago with {cve_count:,} CVEs).",
        "last_updated": last_updated_str,
        "days_old": days_old,
    }

def get_database_status() -> dict:
    db_dir = get_cve_db_dir()
    db_file = get_nvd_db_path()
    check = check_should_update(db_dir)

    with _state_lock:
        state_copy = dict(_update_state)

    cve_count = count_cves(db_dir)
    online = is_internet_available(timeout=1.5)

    return {
        "database_type": "NIST National Vulnerability Database (NVD 2.0)",
        "source_provider": "NIST / Fraunhofer FKIE High-Speed Mirror",
        "explanation": (
            "Official NIST NVD 2.0 vulnerability catalog enriched with full CVSS v2.0, "
            "v3.0, v3.1, and v4.0 metrics and standardized CPE 2.3 hardware/software configurations. "
            "100% complete and offline capable."
        ),
        "db_directory": str(db_dir),
        "db_file": str(db_file),
        "total_cves_loaded": cve_count,
        "last_updated": check["last_updated"],
        "days_old": check["days_old"],
        "should_update": check["needs_update"],
        "update_reason": check["reason"],
        "is_online": online,
        "connectivity_mode": "Online (Auto-Sync)" if online else "Offline (Local DB)",
        "updater_state": state_copy,
    }

def _extract_metrics(metrics: dict):
    """
    Extracts (base_score, severity, version, vector) from NVD 2.0 metrics block.
    Prioritizes CVSS v3.1, then v3.0, then v4.0, then v2.0.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            score = cd.get("baseScore", 0.0)
            sev = m.get("baseSeverity") or cd.get("baseSeverity") or ("HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW"))
            return (
                score,
                str(sev).upper(),
                cd.get("version", key[-2:]),
                cd.get("vectorString", "")
            )
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0]
        cd = m.get("cvssData", {})
        score = cd.get("baseScore", 0.0)
        sev = m.get("baseSeverity") or ("HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW"))
        return score, str(sev).upper(), "2.0", cd.get("vectorString", "")

    return 0.0, "UNRATED", "", ""

def _stream_cve_items(file_obj):
    """
    Memory-efficient streaming parser for NVD JSON format.
    Yields individual CVE dictionary items without loading the whole file into RAM.
    """
    buffer = []
    in_item = False
    for line in file_obj:
        if line.startswith("    {"):
            in_item = True
            buffer = ["{"]
        elif in_item:
            if line.startswith("    }") or line.startswith("    },"):
                buffer.append("}")
                try:
                    yield json.loads("\n".join(buffer))
                except Exception:
                    pass
                in_item = False
                buffer = []
            else:
                buffer.append(line)

def _download_and_extract_task(force: bool):
    global _update_state
    db_dir = get_cve_db_dir()
    db_file = get_nvd_db_path()
    temp_xz = db_dir / "CVE-all.json.xz.tmp"
    temp_db = db_dir / "nvd_cves.db.tmp"

    try:
        if not is_internet_available(timeout=2.0):
            with _state_lock:
                _update_state["is_updating"] = False
                _update_state["current_step"] = "offline"
                _update_state["status_message"] = "Offline Mode: No internet connection detected. Continuing with local offline database."
                _update_state["error"] = "No internet connection detected."
            print("[!] NVD update cancelled: Offline mode (no internet connection).")
            return

        with _state_lock:
            _update_state["is_updating"] = True
            _update_state["current_step"] = "locating"
            _update_state["progress_percent"] = 5
            _update_state["status_message"] = "Locating latest official NIST NVD release package..."
            _update_state["error"] = None

        download_url = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"
        total_size = 0

        # Try to resolve latest release asset from GitHub API
        try:
            api_resp = requests.get(
                "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest",
                headers={"User-Agent": "IoT-Hardware-Security-Tool"},
                timeout=15,
            )
            if api_resp.status_code == 200:
                rel_data = api_resp.json()
                for asset in rel_data.get("assets", []):
                    name = asset.get("name", "")
                    if name == "CVE-all.json.xz":
                        download_url = asset.get("browser_download_url")
                        total_size = asset.get("size", 0)
                        break
        except Exception as api_err:
            print(f"[!] GitHub API check notice: {api_err}, using direct URL.")

        with _state_lock:
            _update_state["current_step"] = "downloading"
            _update_state["progress_percent"] = 10
            _update_state["status_message"] = "Downloading complete NIST NVD 2.0 Database (~98MB compressed)..."

        # 1. Download xz stream with chunking and progress reporting
        resp = requests.get(download_url, stream=True, timeout=120)
        resp.raise_for_status()

        if total_size == 0 and "Content-Length" in resp.headers:
            total_size = int(resp.headers["Content-Length"])

        downloaded = 0
        with open(temp_xz, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024 * 2): # 2MB chunks
                if _abort_event.is_set():
                    raise InterruptedError("Update was cancelled by the user.")
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        pct = int(10 + (downloaded / total_size) * 40) # 10% to 50%
                        with _state_lock:
                            _update_state["progress_percent"] = min(pct, 50)
                            _update_state["status_message"] = (
                                f"Downloaded {downloaded // (1024*1024)} MB of {total_size // (1024*1024)} MB..."
                            )

        # 2. Decompress & Stream-Ingest into SQLite Database
        with _state_lock:
            _update_state["current_step"] = "indexing"
            _update_state["progress_percent"] = 55
            _update_state["status_message"] = "Indexing 380,000+ NIST NVD records into SQLite store..."

        if temp_db.exists():
            temp_db.unlink()

        conn = sqlite3.connect(str(temp_db))
        cur = conn.cursor()
        cur.execute("PRAGMA synchronous = OFF")
        cur.execute("PRAGMA journal_mode = OFF")
        cur.execute("PRAGMA cache_size = -64000")
        cur.execute("PRAGMA temp_store = MEMORY")
        cur.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            base_score REAL,
            cvss_version TEXT,
            vector TEXT,
            published TEXT,
            last_modified TEXT,
            references_json TEXT,
            weaknesses_json TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE cpe_matches (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            version_start_inc TEXT,
            version_end_inc TEXT,
            version_start_exc TEXT,
            version_end_exc TEXT,
            vulnerable INTEGER,
            criteria TEXT,
            target_hw TEXT
        )
        """)

        cve_batch = []
        cpe_batch = []
        total_ingested = 0
        BATCH_SIZE = 2500

        with lzma.open(temp_xz, "rt", encoding="utf-8", errors="replace") as xz_file:
            for it in _stream_cve_items(xz_file):
                if _abort_event.is_set():
                    raise InterruptedError("Update was cancelled by the user.")
                cid = it.get("id")
                if not cid:
                    continue

                desc = ""
                for d in it.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                score, sev, cvss_ver, vec = _extract_metrics(it.get("metrics", {}))
                pub = it.get("published", "")
                mod = it.get("lastModified", "")
                refs = json.dumps([r.get("url") for r in it.get("references", []) if r.get("url")])
                weaknesses = []
                for w in it.get("weaknesses", []):
                    for desc_obj in w.get("description", []):
                        if desc_obj.get("value"):
                            weaknesses.append(desc_obj["value"])
                wns = json.dumps(weaknesses)

                cve_batch.append((cid, desc, sev, score, cvss_ver, vec, pub, mod, refs, wns))

                for cfg in it.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for cm in node.get("cpeMatch", []):
                            crit = cm.get("criteria", "")
                            parts = crit.split(":")
                            vendor = parts[3].lower() if len(parts) > 3 else ""
                            product = parts[4].lower() if len(parts) > 4 else ""
                            target_hw = parts[10].lower() if len(parts) > 10 else "*"
                            cpe_batch.append((
                                cid, vendor, product,
                                cm.get("versionStartIncluding"),
                                cm.get("versionEndIncluding"),
                                cm.get("versionStartExcluding"),
                                cm.get("versionEndExcluding"),
                                1 if cm.get("vulnerable", True) else 0,
                                crit, target_hw
                            ))

                if len(cve_batch) >= BATCH_SIZE:
                    cur.executemany("INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cve_batch)
                    cur.executemany("INSERT INTO cpe_matches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cpe_batch)
                    conn.commit()
                    total_ingested += len(cve_batch)
                    cve_batch = []
                    cpe_batch = []
                    pct = min(55 + int((total_ingested / 390000) * 35), 90)
                    with _state_lock:
                        _update_state["progress_percent"] = pct
                        _update_state["status_message"] = f"Indexed {total_ingested:,} of ~390,000 CVEs into offline database..."

        if cve_batch:
            cur.executemany("INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cve_batch)
            total_ingested += len(cve_batch)
        if cpe_batch:
            cur.executemany("INSERT INTO cpe_matches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cpe_batch)
        conn.commit()

        # 3. Create indices
        with _state_lock:
            _update_state["progress_percent"] = 92
            _update_state["status_message"] = "Optimizing search indexes for zero-latency lookups..."

        cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_id ON cves(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(base_score)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vp ON cpe_matches(product, vendor)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_p ON cpe_matches(product)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id)")
        conn.commit()
        conn.close()

        # 4. Atomic file replacement
        if db_file.exists():
            db_file.unlink()
        temp_db.replace(db_file)

        # 5. Clean up temporary .xz
        if temp_xz.exists():
            temp_xz.unlink()

        # 6. Purge old MITRE db_temp directory and update.zip to reclaim disk space
        old_mitre_dirs = [
            db_dir.parent / "db_temp",
            Path("db_temp").resolve(),
            Path("../data/db_temp").resolve()
        ]
        for md in old_mitre_dirs:
            if md.exists():
                try:
                    shutil.rmtree(md, ignore_errors=True)
                    print(f"[+] Purged obsolete MITRE folder: {md}")
                except Exception:
                    pass

        old_zips = [
            Path("update.zip"),
            Path("../data/update.zip"),
            db_dir / "update.zip",
            Path(__file__).resolve().parent / "update.zip",
        ]
        for oz in old_zips:
            if oz.exists():
                try: 
                    oz.unlink()
                    print(f"[+] Purged obsolete zip: {oz}")
                except Exception: pass

        # 7. Write timestamp
        today_str = datetime.date.today().strftime("%Y-%m-%d")
        with open(db_dir / "last_updated_date.txt", "w", encoding="utf-8") as f:
            f.write(today_str)

        with _state_lock:
            _update_state["is_updating"] = False
            _update_state["current_step"] = "completed"
            _update_state["progress_percent"] = 100
            _update_state["status_message"] = f"NVD 2.0 Database successfully updated on {today_str} ({total_ingested:,} CVEs indexed)."
            _update_state["last_download_time"] = today_str

        print(f"[+] NIST NVD Database update completed successfully ({total_ingested:,} CVEs).")

    except (InterruptedError, Exception) as e:
        if temp_xz.exists():
            try: temp_xz.unlink()
            except Exception: pass
        if temp_db.exists():
            try: temp_db.unlink()
            except Exception: pass
        is_cancel = isinstance(e, InterruptedError) or _abort_event.is_set() or "cancelled" in str(e).lower()
        with _state_lock:
            _update_state["is_updating"] = False
            _update_state["current_step"] = "cancelled" if is_cancel else "error"
            _update_state["error"] = None if is_cancel else str(e)
            _update_state["status_message"] = "Update was cancelled by the user." if is_cancel else f"Update failed: {str(e)}"
            _update_state["progress_percent"] = 0
        if is_cancel:
            print("[+] NVD update cancelled by user and temporary files cleaned up.")
        else:
            print(f"[!] NVD update error: {str(e)}")

def cancel_database_update() -> dict:
    """Signals any running update or sync task to abort and cleans up temporary files."""
    global _update_state, _abort_event
    with _state_lock:
        is_running = _update_state["is_updating"]
        if not is_running:
            pass
        else:
            _update_state["status_message"] = "Cancelling update and cleaning up..."
            _update_state["current_step"] = "cancelling"

    if not is_running:
        return {
            "success": False,
            "message": "No active database update is currently running.",
            "state": get_database_status(),
        }

    _abort_event.set()
    return {
        "success": True,
        "message": "Update cancellation requested.",
        "state": get_database_status(),
    }

def trigger_database_update(force: bool = False) -> dict:
    global _update_state, _abort_event
    if not is_internet_available(timeout=2.0):
        return {
            "success": False,
            "message": "Offline Mode: No active internet connection detected. Continuing with existing local database.",
            "state": get_database_status(),
        }

    with _state_lock:
        if _update_state["is_updating"]:
            return {
                "success": False,
                "message": "An update task is already actively executing.",
                "state": dict(_update_state),
            }

    db_dir = get_cve_db_dir()
    check = check_should_update(db_dir)

    if not check["needs_update"] and not force:
        return {
            "success": True,
            "message": f"NVD Database is already up to date ({check['reason']}). Pass force=true to force re-download.",
            "state": get_database_status(),
        }

    # Clear any previous abort signal
    _abort_event.clear()

    # Start update in background daemon thread
    t = threading.Thread(target=_download_and_extract_task, args=(force,), daemon=True)
    t.start()

    return {
        "success": True,
        "message": "NVD 2.0 Database update started in background.",
        "state": get_database_status(),
    }

# ----------------- HIGH-PERFORMANCE QUERY HELPERS ----------------- #

def get_cve_by_id(cve_id: str) -> dict | None:
    """Fetches a single CVE from the local NVD SQLite store in < 1ms."""
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_file), timeout=5)
        cur = conn.cursor()
        cur.execute("""
        SELECT cve_id, description, severity, base_score, cvss_version, vector,
               published, last_modified, references_json, weaknesses_json
        FROM cves WHERE cve_id = ?
        """, (cve_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return None

        # Fetch CPE matches for this CVE
        cur.execute("""
        SELECT vendor, product, version_start_inc, version_end_inc,
               version_start_exc, version_end_exc, vulnerable, criteria, target_hw
        FROM cpe_matches WHERE cve_id = ?
        """, (cve_id,))
        cpe_rows = cur.fetchall()
        conn.close()

        cpes = []
        for c in cpe_rows:
            cpes.append({
                "vendor": c[0],
                "product": c[1],
                "versionStartIncluding": c[2],
                "versionEndIncluding": c[3],
                "versionStartExcluding": c[4],
                "versionEndExcluding": c[5],
                "vulnerable": bool(c[6]),
                "criteria": c[7],
                "target_hw": c[8],
            })

        return {
            "id": row[0],
            "description": row[1],
            "severity": row[2] or "UNRATED",
            "base_score": row[3] if row[3] is not None else 0.0,
            "cvss_version": row[4],
            "vector": row[5],
            "published": row[6],
            "last_modified": row[7],
            "references": json.loads(row[8]) if row[8] else [],
            "weaknesses": json.loads(row[9]) if row[9] else [],
            "cpe_matches": cpes,
        }
    except Exception as e:
        print(f"[!] SQLite query error: {e}")
        return None

def get_cvss(cve_id: str) -> dict:
    """Returns CVSS metrics dictionary for a given CVE ID."""
    cve = get_cve_by_id(cve_id)
    if not cve:
        return {
            "CVE_ID": cve_id,
            "Base_Score": None,
            "Severity": "UNRATED",
            "CVSS_Version": "",
            "Vector": "",
            "Error": "CVE not found in local NVD database"
        }
    return {
        "CVE_ID": cve_id,
        "Base_Score": cve.get("base_score"),
        "Severity": cve.get("severity"),
        "CVSS_Version": cve.get("cvss_version"),
        "Vector": cve.get("vector"),
        "Error": None
    }

def count_epss_records(db_dir: Path = None) -> int:
    """Returns the total number of indexed EPSS records in the SQLite database."""
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return 0
    try:
        conn = sqlite3.connect(str(db_file), timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM epss_scores")
        val = cur.fetchone()[0]
        conn.close()
        return val
    except Exception:
        return 0

def sync_epss_database(force: bool = False, timeout: int = 40) -> dict:
    """
    Downloads and ingests the official FIRST EPSS daily feed (epss_scores-current.csv.gz)
    into the local SQLite database.
    Offline safe: if no internet, skips gracefully with appropriate status message.
    """
    import gzip
    import csv
    import io

    db_path = get_nvd_db_path()
    init_nvd_sqlite(db_path)

    existing_count = count_epss_records()
    if existing_count > 0 and not force:
        return {
            "success": True,
            "action": "up_to_date",
            "message": f"EPSS database is already populated ({existing_count:,} records).",
            "total_records": existing_count,
        }

    if not is_internet_available(timeout=2.0):
        return {
            "success": False,
            "action": "offline",
            "message": f"Offline mode: Unable to download EPSS feed. Continuing with {existing_count:,} local records.",
            "total_records": existing_count,
        }

    epss_url = os.getenv("EPSS_FEED_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz")
    print(f"[+] Downloading FIRST EPSS dataset from {epss_url}...")

    try:
        req = urllib.request.Request(
            epss_url,
            headers={"User-Agent": "Hardware-Auditing-Tool/1.0 (Embedded Security Research)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            compressed_data = response.read()

        print(f"[+] Downloaded {len(compressed_data) / 1024 / 1024:.2f} MB. Parsing and inserting into SQLite...")

        conn = sqlite3.connect(str(db_path), timeout=60)
        cur = conn.cursor()
        cur.execute("PRAGMA synchronous = OFF")
        cur.execute("PRAGMA journal_mode = MEMORY")

        score_date = datetime.date.today().isoformat()
        rows_to_insert = []

        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
            text_stream = io.TextIOWrapper(gz, encoding="utf-8", errors="ignore")
            first_line = text_stream.readline()
            if first_line.startswith("#") and "score_date:" in first_line:
                try:
                    score_date = first_line.split("score_date:")[1].split(",")[0].strip()[:10]
                except Exception:
                    pass

            while first_line.startswith("#"):
                first_line = text_stream.readline()

            reader = csv.reader(text_stream)
            for row in reader:
                if len(row) >= 3 and row[0].startswith("CVE-"):
                    try:
                        cve = row[0].strip()
                        epss_val = float(row[1])
                        pct_val = float(row[2])
                        rows_to_insert.append((cve, epss_val, pct_val, score_date))
                    except (ValueError, TypeError):
                        continue

        cur.executemany("""
            INSERT OR REPLACE INTO epss_scores (cve_id, epss, percentile, score_date)
            VALUES (?, ?, ?, ?)
        """, rows_to_insert)

        conn.commit()
        conn.close()

        total = count_epss_records()
        print(f"[+] Successfully indexed {len(rows_to_insert):,} EPSS records into SQLite (total: {total:,}).")
        return {
            "success": True,
            "action": "synced",
            "message": f"Successfully indexed {len(rows_to_insert):,} EPSS scores.",
            "total_records": total,
        }
    except Exception as e:
        print(f"[!] Error synchronizing EPSS database: {e}")
        return {
            "success": False,
            "action": "error",
            "message": f"Error syncing EPSS database: {str(e)}",
            "total_records": existing_count,
        }

def get_epss_from_db(cve_id: str) -> dict:
    """Returns EPSS exploitability score and percentile for a given CVE ID."""
    if not cve_id or not isinstance(cve_id, str):
        return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": "Invalid CVE ID"}

    cve_clean = cve_id.strip().upper()
    db_file = get_nvd_db_path()
    if db_file.exists():
        try:
            conn = sqlite3.connect(str(db_file), timeout=5)
            cur = conn.cursor()
            cur.execute("SELECT epss, percentile, score_date FROM epss_scores WHERE cve_id = ?", (cve_clean,))
            row = cur.fetchone()
            conn.close()
            if row:
                return {
                    "EPSS_Score": row[0],
                    "EPSS_Percentile": row[1],
                    "Date": row[2],
                    "Error": None
                }
        except Exception as e:
            print(f"[!] SQLite EPSS lookup error: {e}")

    # Online fallback for single newly-disclosed CVE if missing in local DB
    if is_internet_available(timeout=1.0):
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_clean}"
            req = urllib.request.Request(url, headers={"User-Agent": "Hardware-Auditing-Tool/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode())
                    items = payload.get("data", [])
                    if items:
                        item = items[0]
                        epss_val = float(item.get("epss", 0.0))
                        pct_val = float(item.get("percentile", 0.0))
                        date_val = item.get("date", "")
                        try:
                            conn = sqlite3.connect(str(db_file), timeout=5)
                            cur = conn.cursor()
                            cur.execute("INSERT OR REPLACE INTO epss_scores VALUES (?, ?, ?, ?)",
                                        (cve_clean, epss_val, pct_val, date_val))
                            conn.commit()
                            conn.close()
                        except Exception:
                            pass
                        return {
                            "EPSS_Score": epss_val,
                            "EPSS_Percentile": pct_val,
                            "Date": date_val,
                            "Error": None
                        }
        except Exception:
            pass

    return {
        "EPSS_Score": None,
        "EPSS_Percentile": None,
        "Error": "CVE not found in local EPSS dataset"
    }

def get_epss_batch_from_db(cve_ids: list) -> dict:
    """High-speed batch retrieval of EPSS scores for a list of CVE IDs."""
    if not cve_ids:
        return {}
    results = {}
    clean_ids = [c.strip().upper() for c in cve_ids if c and isinstance(c, str)]
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return {c: {"EPSS_Score": None, "EPSS_Percentile": None, "Error": "Database not found"} for c in clean_ids}

    try:
        conn = sqlite3.connect(str(db_file), timeout=10)
        cur = conn.cursor()
        chunk_size = 500
        for i in range(0, len(clean_ids), chunk_size):
            chunk = clean_ids[i:i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cur.execute(f"SELECT cve_id, epss, percentile, score_date FROM epss_scores WHERE cve_id IN ({placeholders})", chunk)
            for r in cur.fetchall():
                results[r[0]] = {
                    "EPSS_Score": r[1],
                    "EPSS_Percentile": r[2],
                    "Date": r[3],
                    "Error": None
                }
        conn.close()
    except Exception as e:
        print(f"[!] Batch EPSS lookup error: {e}")

    # Fill in missing IDs
    for c in clean_ids:
        if c not in results:
            results[c] = {
                "EPSS_Score": None,
                "EPSS_Percentile": None,
                "Error": "CVE not found in local EPSS dataset"
            }
    return results

def get_cvss_batch(cve_ids: list) -> dict:
    """High-speed batch retrieval of CVSS metrics from SQLite NVD."""
    if not cve_ids:
        return {}
    results = {}
    clean_ids = [c.strip().upper() for c in cve_ids if c and isinstance(c, str)]
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return {c: {"CVE_ID": c, "Base_Score": None, "Severity": "UNRATED", "Error": "DB missing"} for c in clean_ids}

    try:
        conn = sqlite3.connect(str(db_file), timeout=10)
        cur = conn.cursor()
        chunk_size = 500
        for i in range(0, len(clean_ids), chunk_size):
            chunk = clean_ids[i:i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cur.execute(f"SELECT cve_id, base_score, severity, cvss_version, vector FROM cves WHERE cve_id IN ({placeholders})", chunk)
            for r in cur.fetchall():
                results[r[0]] = {
                    "CVE_ID": r[0],
                    "Base_Score": r[1],
                    "Severity": r[2] or "UNRATED",
                    "CVSS_Version": r[3],
                    "Vector": r[4],
                    "Error": None
                }
        conn.close()
    except Exception as e:
        print(f"[!] Batch CVSS lookup error: {e}")

    for c in clean_ids:
        if c not in results:
            results[c] = {
                "CVE_ID": c,
                "Base_Score": None,
                "Severity": "UNRATED",
                "CVSS_Version": "",
                "Vector": "",
                "Error": "CVE not found in local NVD database"
            }
    return results

def query_cves_by_product(vendor: str, product: str) -> list:
    """Fetches all CVEs matching a vendor and product from the NVD database."""
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_file), timeout=10)
        cur = conn.cursor()
        cur.execute("""
        SELECT DISTINCT c.cve_id, c.description, c.severity, c.base_score, c.cvss_version,
                        c.vector, c.published, c.last_modified, c.references_json, c.weaknesses_json
        FROM cves c
        JOIN cpe_matches cm ON c.cve_id = cm.cve_id
        WHERE cm.vendor = ? AND cm.product = ?
        """, (vendor.lower(), product.lower()))
        rows = cur.fetchall()

        results = []
        for r in rows:
            cur.execute("""
            SELECT vendor, product, version_start_inc, version_end_inc,
                   version_start_exc, version_end_exc, vulnerable, criteria, target_hw
            FROM cpe_matches WHERE cve_id = ?
            """, (r[0],))
            cpe_rows = cur.fetchall()
            cpes = [{
                "vendor": c[0],
                "product": c[1],
                "versionStartIncluding": c[2],
                "versionEndIncluding": c[3],
                "versionStartExcluding": c[4],
                "versionEndExcluding": c[5],
                "vulnerable": bool(c[6]),
                "criteria": c[7],
                "target_hw": c[8],
            } for c in cpe_rows]

            results.append({
                "id": r[0],
                "description": r[1],
                "severity": r[2] or "UNRATED",
                "base_score": r[3] if r[3] is not None else 0.0,
                "cvss_version": r[4],
                "vector": r[5],
                "published": r[6],
                "last_modified": r[7],
                "references": json.loads(r[8]) if r[8] else [],
                "weaknesses": json.loads(r[9]) if r[9] else [],
                "cpe_matches": cpes,
            })
        conn.close()
        return results
    except Exception as e:
        print(f"[!] SQLite query error: {e}")
        return []

def query_firmware_cves(product_pairs: list) -> list:
    """
    Fetches all CVEs matching any (vendor, product) pair in product_pairs.
    Used by BootLog_Analysis to load only relevant CVE entries in ~0.05 seconds.
    """
    db_file = get_nvd_db_path()
    if not db_file.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_file), timeout=10)
        cur = conn.cursor()

        # Build parameterized IN clause
        conditions = []
        params = []
        for v, p in product_pairs:
            conditions.append("(cm.vendor = ? AND cm.product = ?)")
            params.extend([v.lower(), p.lower()])

        if not conditions:
            conn.close()
            return []

        where_clause = " OR ".join(conditions)
        sql = f"""
        SELECT DISTINCT c.cve_id, c.description, c.severity, c.base_score, c.cvss_version,
                        c.vector, c.published, c.last_modified, c.references_json, c.weaknesses_json
        FROM cves c
        JOIN cpe_matches cm ON c.cve_id = cm.cve_id
        WHERE {where_clause}
        """
        cur.execute(sql, params)
        cve_rows = cur.fetchall()

        if not cve_rows:
            conn.close()
            return []

        cve_ids = [r[0] for r in cve_rows]
        placeholders = ",".join(["?"] * len(cve_ids))
        cur.execute(f"""
        SELECT cve_id, vendor, product, version_start_inc, version_end_inc,
               version_start_exc, version_end_exc, vulnerable, criteria, target_hw
        FROM cpe_matches WHERE cve_id IN ({placeholders})
        """, cve_ids)
        cpe_rows = cur.fetchall()
        conn.close()

        cpe_map = {}
        for c in cpe_rows:
            cid = c[0]
            if cid not in cpe_map:
                cpe_map[cid] = []
            cpe_map[cid].append({
                "vendor": c[1],
                "product": c[2],
                "versionStartIncluding": c[3],
                "versionEndIncluding": c[4],
                "versionStartExcluding": c[5],
                "versionEndExcluding": c[6],
                "vulnerable": bool(c[7]),
                "criteria": c[8],
                "target_hw": c[9],
            })

        results = []
        for r in cve_rows:
            cid = r[0]
            results.append({
                "id": cid,
                "description": r[1],
                "severity": r[2] or "UNRATED",
                "base_score": r[3] if r[3] is not None else 0.0,
                "cvss_version": r[4],
                "vector": r[5],
                "published": r[6],
                "last_modified": r[7],
                "references": json.loads(r[8]) if r[8] else [],
                "weaknesses": json.loads(r[9]) if r[9] else [],
                "cpe_matches": cpe_map.get(cid, []),
            })

        return results
    except Exception as e:
        print(f"[!] Query firmware CVEs error: {e}")
        return []
