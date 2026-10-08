"""Vendor data must resolve from runtime assets after package installation."""
import json


def test_oui_database_uses_configured_project_root(tmp_path, monkeypatch):
    from marlinspike import config
    from marlinspike.engine import TopologyBuilder

    monkeypatch.setattr(config, "PROJECT_ROOT", str(tmp_path))
    (tmp_path / "oui.json").write_text(json.dumps({"12:34:56": "Fixture Vendor"}))
    assert TopologyBuilder._load_oui_db()["12:34:56"]["vendor"] == "Fixture Vendor"
