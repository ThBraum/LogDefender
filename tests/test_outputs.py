from __future__ import annotations

import json
from pathlib import Path

from logdefender.analyze import run_analysis


def test_run_analysis_writes_outputs(tmp_path: Path):
    sample = tmp_path / "sample.jsonl"
    sample.write_text(
        "\n".join(
            [
                '{"time_iso8601":"2026-01-03T01:00:00Z","remote_addr":"1.2.3.4","request_method":"GET","request_uri":"/admin","status":403,"http_user_agent":"Mozilla/5.0"}',
                '{"time_iso8601":"2026-01-03T01:00:12Z","remote_addr":"5.6.7.8","request_method":"GET","request_uri":"/does-not-exist","status":404,"http_user_agent":"python-requests/2.31"}',
                "",
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    result = run_analysis(sample, out_dir)

    assert result.alerts_path.exists()
    assert result.report_path.exists()

    alerts_text = result.alerts_path.read_text(encoding="utf-8")
    report_text = result.report_path.read_text(encoding="utf-8")

    assert alerts_text.strip().startswith("[")
    assert "# Relatório LogDefender" in report_text

    alerts = json.loads(alerts_text)
    assert isinstance(alerts, list)

    for a in alerts:
        assert "alert_id" in a
        assert "rule_id" in a
        assert "severity" in a
        assert "confidence" in a
        assert "time_window" in a
        assert "event_count" in a
        assert "entities" in a
        assert "evidence" in a
        assert "recommended_actions" in a

        assert a["severity"] in {"low", "medium", "high"}
        assert 0.0 <= float(a["confidence"]) <= 1.0
        assert isinstance(a["entities"], dict)
        assert isinstance(a["evidence"], list)
        assert isinstance(a["recommended_actions"], list)
