import os
import tempfile
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mailer_v01 import load_lines, log


def test_load_lines_reads_file_correctly():
    # Buat file sementara dengan isi beberapa baris
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("line1\nline2\n\nline3\n")
        tmp_path = tmp.name

    lines = load_lines(tmp_path)
    assert lines == ["line1", "line2", "line3"]

    os.remove(tmp_path)

def test_load_lines_missing_file_returns_empty_list():
    lines = load_lines("nonexistent.txt")
    assert lines == []

def test_log_writes_to_file(tmp_path):
    log_file = tmp_path / "test.log"
    # panggil log dengan file output
    log("Hello World", level="INFO", log_to_file=True)
    # cek isi file log default
    with open("simulation.log", "r", encoding="utf-8") as f:
        content = f.read()
    assert "Hello World" in content
