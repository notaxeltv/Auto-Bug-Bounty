"""Test per autobb.diff.compute_diff."""

from __future__ import annotations

from autobb.diff import compute_diff
from autobb.scan import Finding


def _finding(template_id="t1", matched_at="https://a.example.com/") -> Finding:
    return Finding(
        template_id=template_id,
        name="Test finding",
        severity="medium",
        host="https://a.example.com",
        matched_at=matched_at,
        description="desc",
        reference=[],
    )


def test_first_run_marks_everything_as_new(tmp_path):
    subdomains = ["a.example.com", "b.example.com"]
    findings = [_finding()]

    result = compute_diff(tmp_path, "target1", subdomains, findings)

    assert sorted(result.new_subdomains) == sorted(subdomains)
    assert len(result.new_findings) == 1
    assert result.new_findings[0].template_id == "t1"
    assert result.total_subdomains == 2
    assert result.total_findings == 1


def test_second_run_without_changes_finds_no_novelty(tmp_path):
    subdomains = ["a.example.com", "b.example.com"]
    findings = [_finding()]

    compute_diff(tmp_path, "target1", subdomains, findings)
    result = compute_diff(tmp_path, "target1", subdomains, findings)

    assert result.new_subdomains == []
    assert result.new_findings == []
    assert result.total_subdomains == 2
    assert result.total_findings == 1


def test_new_subdomain_and_finding_are_detected(tmp_path):
    subdomains_run1 = ["a.example.com"]
    findings_run1 = [_finding(template_id="t1", matched_at="https://a.example.com/")]

    compute_diff(tmp_path, "target1", subdomains_run1, findings_run1)

    subdomains_run2 = ["a.example.com", "new.example.com"]
    findings_run2 = [
        _finding(template_id="t1", matched_at="https://a.example.com/"),
        _finding(template_id="t2", matched_at="https://new.example.com/"),
    ]

    result = compute_diff(tmp_path, "target1", subdomains_run2, findings_run2)

    assert result.new_subdomains == ["new.example.com"]
    assert len(result.new_findings) == 1
    assert result.new_findings[0].template_id == "t2"
    assert result.total_subdomains == 2
    assert result.total_findings == 2


def test_state_persists_on_disk_between_separate_calls(tmp_path):
    subdomains = ["a.example.com"]
    findings = [_finding()]

    compute_diff(tmp_path, "target1", subdomains, findings)

    state_path = tmp_path / "target1" / "state.json"
    assert state_path.exists()

    # Simula una nuova esecuzione "a freddo": nessuno stato in memoria,
    # solo quello persistito su disco viene riletto da compute_diff.
    result = compute_diff(tmp_path, "target1", subdomains, findings)

    assert result.new_subdomains == []
    assert result.new_findings == []
