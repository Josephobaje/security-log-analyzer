from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from seclog import __version__
from seclog.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def test_analyze_writes_all_reports(
    tmp_path: Path, samples: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "analyze",
            str(samples / "auth.log"),
            str(samples / "access.log"),
            "--year",
            "2026",
            "--json",
            str(tmp_path / "r.json"),
            "--csv",
            str(tmp_path / "r.csv"),
            "--html",
            str(tmp_path / "r.html"),
            "--no-color",
        ]
    )
    assert code == EXIT_OK
    out, err = capsys.readouterr()
    assert "Findings" in out
    assert "Report written" in err
    assert json.loads((tmp_path / "r.json").read_text())["summary"]["findings"] > 0
    assert (tmp_path / "r.csv").read_text().startswith("severity,rule_id")
    assert "<table>" in (tmp_path / "r.html").read_text()


def test_fail_on_sets_exit_code(samples: Path) -> None:
    args = ["analyze", str(samples / "auth.log"), "--year", "2026", "--quiet"]
    assert main([*args, "--fail-on", "critical"]) == EXIT_FINDINGS
    assert main([*args, "--min-severity", "critical", "--fail-on", "high"]) == EXIT_FINDINGS


def test_fail_on_not_triggered_for_clean_log(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        '198.51.100.20 - - [06/Oct/2026:08:00:00 +0100] "GET / HTTP/1.1" 200 512 '
        '"-" "Mozilla/5.0"\n'
    )
    assert main(["analyze", str(log), "--quiet", "--fail-on", "low"]) == EXIT_OK


def test_threshold_options_change_detection(samples: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    main(
        [
            "analyze",
            str(samples / "auth.log"),
            "--year",
            "2026",
            "-q",
            "--json",
            str(out),
            "--ssh-failures",
            "100",
        ]
    )
    rules = {f["rule_id"] for f in json.loads(out.read_text())["findings"]}
    assert "SSH-BRUTE-FORCE" not in rules


def test_missing_file_returns_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(tmp_path / "nope.log")]) == EXIT_ERROR
    assert "not found" in capsys.readouterr().err


def test_invalid_arguments_exit_with_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "x.log", "--min-severity", "extreme"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit):
        main(["analyze", "x.log", "--top", "0"])


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "SSH-BRUTE-FORCE" in out
    assert "WEB-LOG4SHELL" in out


def test_module_entry_point_reports_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "seclog", "--version"], capture_output=True, text=True, check=True
    )
    assert __version__ in result.stdout
