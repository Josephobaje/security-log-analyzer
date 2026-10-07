from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from rich.console import Console

from seclog.analyzer import analyze
from seclog.parsers import load_logs
from seclog.reports import render_html, render_terminal, write_csv, write_html, write_json
from tests.conftest import access_event


def _sample_report(samples: Path):  # type: ignore[no-untyped-def]
    logs = load_logs(sorted(samples.glob("*.log")), year=2026)
    return analyze(logs.auth, logs.access, stats=logs.stats)


def test_json_export_structure(tmp_path: Path, samples: Path) -> None:
    report = _sample_report(samples)
    path = write_json(report, tmp_path / "out" / "report.json")
    data = json.loads(path.read_text())
    assert data["tool"] == "security-log-analyzer"
    assert data["summary"]["findings"] == len(report.findings)
    assert data["findings"][0]["severity"] == "critical"
    assert {"ip", "score", "severity", "network"} <= data["suspicious_ips"][0].keys()


def test_csv_export(tmp_path: Path, samples: Path) -> None:
    report = _sample_report(samples)
    path = write_csv(report, tmp_path / "findings.csv")
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    assert len(rows) == len(report.findings)
    assert rows[0]["severity"] == "critical"
    assert {r["rule_id"] for r in rows} >= {"SSH-BRUTE-FORCE", "WEB-SQLI"}


def test_csv_neutralises_formula_injection(tmp_path: Path) -> None:
    event = access_event("/?x=1%20or%201=1", ip="192.0.2.1")
    report = analyze([], [event])
    report.findings[0].description = '=HYPERLINK("http://evil")'
    path = write_csv(report, tmp_path / "f.csv")
    row = next(csv.DictReader(path.open(newline="", encoding="utf-8")))
    assert row["description"].startswith("'=")


def test_html_report_escapes_log_content(tmp_path: Path) -> None:
    event = access_event("/search?q=<script>alert('x')</script>", ip="192.0.2.66")
    report = analyze([], [event])
    html = render_html(report)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
    assert html.startswith("<!doctype html>")
    path = write_html(report, tmp_path / "r.html")
    assert path.read_text(encoding="utf-8") == html


def test_html_report_with_no_findings() -> None:
    html = render_html(analyze([], []))
    assert "No findings." in html
    assert "No suspicious IPs." in html


def test_terminal_report_renders(samples: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")  # "dumb" terminals force 80 columns
    console = Console(record=True, width=120, color_system=None)
    render_terminal(_sample_report(samples), console, top=5)
    text = console.export_text()
    assert "Security Log Analyzer" in text
    assert "CRITICAL" in text
    assert "Suspicious IPs" in text
    assert "Showing 5 of" in text
    assert "Top targeted SSH users" in text


def test_terminal_report_without_findings() -> None:
    console = Console(record=True, width=100, color_system=None)
    render_terminal(analyze([], []), console)
    assert "No threats detected" in console.export_text()
