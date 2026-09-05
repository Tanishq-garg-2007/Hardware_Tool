import os
import sys
import time
import json
import datetime

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_dir)

from collect_files import collect_all_files
from ChatBot import (
    reindex_database,
    check_and_purge_expired_index,
    safe_delete_path,
    get_index_metadata,
    save_index_metadata,
    generate_answer,
    DB_DIR,
    METADATA_FILE
)

SAMPLE_DIR = os.path.join(backend_dir, "../data/uploads")
MERGED_OUTPUT = os.path.join(backend_dir, "combined_files_output.txt")
TEST_FILE = os.path.join(SAMPLE_DIR, "retention_test_log.txt")

TEST_CONTENT = """
[0.000000] Linux version 5.10.120-armv7l IoT-Gateway
[0.000010] CPU: ARM Cortex-A76 Broadcom BCM2712
[1.200000] Insecure service: telnetd active on port 23
[1.300000] SSH: dropbear active on port 22
[2.000000] Password check: root:$6$salt$hashedpassword123
"""

def test_retention_and_caching():
    print("=" * 65)
    print("TEST 1: First Upload -> Should perform fresh indexing")
    print("=" * 65)
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    with open(TEST_FILE, "w", encoding="utf-8") as f:
        f.write(TEST_CONTENT.strip())

    collect_all_files(SAMPLE_DIR, MERGED_OUTPUT)
    res1 = reindex_database(force=True)
    print("Result 1:", res1)
    assert res1["is_cached"] is False, "First index should not be cached!"
    assert os.path.exists(METADATA_FILE), "Metadata file must be created!"
    
    meta1 = get_index_metadata()
    expiry1 = datetime.datetime.fromisoformat(meta1["expires_at"])
    now1 = datetime.datetime.now(datetime.timezone.utc)
    remaining_days = (expiry1 - now1).days
    print(f"Index created at {meta1['created_at']}, expires at {meta1['expires_at']} (~{remaining_days} days)")
    assert remaining_days >= 29, f"Expected 30-day retention, got {remaining_days} days"

    print("\n" + "=" * 65)
    print("TEST 2: Second Upload of identical file -> Should use cached index")
    print("=" * 65)
    # Simulate a brief delay
    time.sleep(1.5)
    res2 = reindex_database(force=False)
    print("Result 2:", res2)
    assert res2["is_cached"] is True, "Second index of same file MUST be cached!"
    assert "Re-indexing skipped" in res2["message"], "Message should report re-indexing skipped"

    meta2 = get_index_metadata()
    print(f"Updated metadata: last_updated={meta2['last_updated_at']}, expires_at={meta2['expires_at']}")
    assert meta2["last_updated_at"] > meta1["last_updated_at"], "last_updated_at must be refreshed!"
    assert meta2["expires_at"] >= meta1["expires_at"], "30-day timer must be refreshed!"

    print("\n" + "=" * 65)
    print("TEST 3: Querying the cached RAG index")
    print("=" * 65)
    t0 = time.time()
    ans = generate_answer("What insecure service and port is active?")
    print(f"Answer (generated in {time.time() - t0:.2f}s):\n{ans}")
    assert "23" in ans or "telnet" in ans.lower(), "Answer should mention telnet on port 23"

    print("\n" + "=" * 65)
    print("TEST 4: Simulated 30-Day Expiration -> Should auto-purge index")
    print("=" * 65)
    # Set expiration to 1 hour in the past
    past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
    meta2["expires_at"] = past_time
    save_index_metadata(meta2)
    print(f"Manually set expires_at to past: {past_time}")

    purged = check_and_purge_expired_index()
    print(f"Purge result: {purged}")
    assert purged is True, "Expired index must be automatically purged!"
    assert not os.path.exists(METADATA_FILE), "Metadata file should be deleted on purge"
    if os.path.exists(DB_DIR) and os.listdir(DB_DIR):
        import chromadb
        client = chromadb.PersistentClient(path=DB_DIR)
        assert len(client.list_collections()) == 0, "Chroma collections must be completely cleared on purge!"
    else:
        assert not os.path.exists(DB_DIR) or not os.listdir(DB_DIR), "ChromaDB directory should be removed"

    print("\n" + "=" * 65)
    print("TEST 5: Verify Sudo & Safe Deletion Resilience")
    print("=" * 65)
    test_dummy_dir = os.path.join(backend_dir, "temp_sudo_test_dir")
    os.makedirs(test_dummy_dir, exist_ok=True)
    with open(os.path.join(test_dummy_dir, "file.txt"), "w") as f:
        f.write("dummy")
    
    del_ok = safe_delete_path(test_dummy_dir)
    print(f"Safe delete result on test dir: {del_ok}")
    assert del_ok is True, "safe_delete_path should succeed"
    assert not os.path.exists(test_dummy_dir), "Dummy dir must be deleted"

    print("\n>>> ALL 30-DAY RETENTION & SUDO HANDLING TESTS PASSED! <<<")

if __name__ == "__main__":
    test_retention_and_caching()
