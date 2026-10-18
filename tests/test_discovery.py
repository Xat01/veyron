"""Repository discovery: inventory, exclusions, manifests, limits."""

from pathlib import Path

from veyron.discovery import Discovery

VULN = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_app"
CLEAN = Path(__file__).resolve().parent.parent / "fixtures" / "clean_app"


def test_discovers_files_and_manifests():
    res = Discovery(VULN).run()
    names = {p.name for p in res.files}
    assert "app.py" in names
    assert "requirements.txt" in names
    manifest_names = {c.name for c in res.components if c.type == "manifest"}
    assert "requirements.txt" in manifest_names
    assert "package.json" in manifest_names


def test_excludes_configured_directories(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x=1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("var a=1;")
    res = Discovery(tmp_path).run()
    rel = {p.relative_to(tmp_path).as_posix() for p in res.files}
    assert "src/a.py" in rel
    assert not any(r.startswith("node_modules") for r in rel)


def test_glob_exclusions(tmp_path):
    (tmp_path / "keep.py").write_text("x=1")
    (tmp_path / "skip_test.py").write_text("x=1")
    res = Discovery(tmp_path, exclusions=["skip_*.py"]).run()
    names = {p.name for p in res.files}
    assert "keep.py" in names
    assert "skip_test.py" not in names


def test_file_size_limit(tmp_path):
    big = tmp_path / "big.py"
    big.write_bytes(b"x" * 100)
    small = tmp_path / "small.py"
    small.write_text("x=1")
    res = Discovery(tmp_path, max_file_size=50).run()
    names = {p.name for p in res.files}
    assert "small.py" in names
    assert "big.py" not in names
    assert any(p.name == "big.py" for p in res.skipped_files)


def test_unsupported_extensions_reported(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    (tmp_path / "code.py").write_text("x=1")
    res = Discovery(tmp_path).run()
    assert ".png" in res.unsupported_extensions
    # honest coverage: PNG counted as unsupported, still inventoried
    assert any(p.name == "image.png" for p in res.files)


def test_summary_json_serialisable():
    import json

    res = Discovery(VULN).run()
    payload = json.dumps(res.summary())
    assert "file_count" in payload


def test_does_not_execute_project_scripts(tmp_path):
    """Discovery must only read files — no subprocess calls happen."""
    marker = tmp_path / "executed.marker"
    (tmp_path / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('ran')\nraise SystemExit(1)\n"
    )
    Discovery(tmp_path).run()
    assert not marker.exists()
