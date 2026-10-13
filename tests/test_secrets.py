"""密钥库与 Web 配置接口。库是明文 SQLite，没有主密钥文件。"""

from __future__ import annotations

import json
import sqlite3
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from irtrace.intel.providers.threatbook import ThreatBookProvider
from irtrace.intel.registry import intel_registry
from irtrace.secrets import SecretStore, mask_secret
from irtrace.web.server import create_server


def test_sqlite_stores_plaintext_without_key_file(workspace):
    store = SecretStore(workspace)
    store.set("virustotal", "vt-secret-token-1234", enabled=True)

    db = sqlite3.connect(store.db_path)
    row = db.execute("SELECT api_key FROM provider_secrets WHERE name='virustotal'").fetchone()
    assert row[0] == "vt-secret-token-1234"
    assert store.db_path.name == "secrets.db"
    assert not (workspace / "data" / ".secrets.key").exists()

    again = SecretStore(workspace)
    assert again.api_key_for("virustotal") == "vt-secret-token-1234"
    assert mask_secret("vt-secret-token-1234") == "vt-s••••••1234"


def test_provider_reads_store_before_environment(workspace, monkeypatch):
    intel_registry.discover()
    SecretStore(workspace).set("threatbook", "tb-from-db-0001", enabled=True)
    monkeypatch.setenv("THREATBOOK_API_KEY", "tb-from-env")
    provider = ThreatBookProvider({"workspace": str(workspace)})
    assert provider.api_key == "tb-from-db-0001"
    assert provider.available

    SecretStore(workspace).update("threatbook", enabled=False)
    disabled = ThreatBookProvider({"workspace": str(workspace)})
    assert disabled.api_key == "tb-from-env"


def test_web_key_api_never_returns_plaintext(workspace):
    intel_registry.discover()
    server = create_server(workspace, "127.0.0.1", 0)
    port = server.server_address[1]
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        body = json.dumps({
            "name": "virustotal",
            "api_key": "super-secret-vt-key",
            "enabled": True,
        }).encode()
        saved = _post(base + "/api/intel/keys", body)
        blob = json.dumps(saved)
        assert "super-secret-vt-key" not in blob
        item = next(p for p in saved["providers"] if p["name"] == "virustotal")
        assert item["configured"] is True
        assert item["hint"].startswith("supe")
        assert item["enabled"] is True

        listed = json.loads(urlopen(base + "/api/intel/keys", timeout=5).read())
        assert "super-secret-vt-key" not in json.dumps(listed)

        cleared = _post(base + "/api/intel/keys", json.dumps({
            "name": "virustotal", "action": "delete",
        }).encode())
        gone = next(p for p in cleared["providers"] if p["name"] == "virustotal")
        assert gone["configured"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_web_rejects_unknown_provider(workspace):
    intel_registry.discover()
    server = create_server(workspace, "127.0.0.1", 0)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        try:
            _post(base + "/api/intel/keys", json.dumps({
                "name": "not-a-provider", "api_key": "x",
            }).encode())
        except HTTPError as exc:
            assert exc.code == 400
        else:
            raise AssertionError("未知平台应当被拒绝")
    finally:
        server.shutdown()
        server.server_close()


def _post(url: str, body: bytes) -> dict:
    req = Request(url, data=body, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())
