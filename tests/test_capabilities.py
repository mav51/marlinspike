"""Regression coverage for the catalog after the engine package migration."""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-capabilities")


def test_findings_catalog_includes_modbus_from_packaged_engine():
    from marlinspike.app import _build_findings_catalog

    _build_findings_catalog.cache_clear()
    catalog = _build_findings_catalog()
    assert any(
        entry["source"] == "dpi" and "modbus" in entry["title"].lower()
        for entry in catalog["entries"]
    )
