"""Test per autobb.report.generate_finding_report."""

from __future__ import annotations

from autobb.config import Target
from autobb.report import generate_finding_report
from autobb.scan import Finding


def test_generate_finding_report_creates_expected_markdown_file(tmp_path):
    target = Target(
        name="example-corp",
        domains=["example-corp.com"],
        authorized=True,
        program_url="https://bugbounty.example-corp.com",
    )
    finding = Finding(
        template_id="exposed-panel",
        name="Exposed Admin Panel",
        severity="high",
        host="https://admin.example-corp.com",
        matched_at="https://admin.example-corp.com/login",
        description="Un pannello di amministrazione risulta esposto pubblicamente.",
        reference=["https://example.com/advisory"],
    )

    report_path = generate_finding_report(target, finding, tmp_path)

    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")

    assert "BOZZA" in content
    assert finding.template_id in content
    assert target.program_url in content
    assert "Checklist di verifica manuale" in content
    assert "VERO POSITIVO" in content
