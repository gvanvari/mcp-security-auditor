"""
Suppression — P2-2: accept known findings so one FP doesn't break CI.

Two independent mechanisms, applied in order by the CLI:

  1. Inline ignore comments — `# mcp-auditor: ignore[RULE-ID]` (or a bare
     `# mcp-auditor: ignore` for every rule) on the source line a finding's
     `location` resolves to.
  2. Baseline file — a JSON snapshot of finding fingerprints accepted as
     "already known"; anything not in the baseline is a new finding and
     still fails CI.

Suppressed findings are never dropped from the returned list — they're kept
with `suppressed=True` / `suppression_reason` set so reporters can still
show them (just marked), and callers can exclude them from CI-failure logic.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from mcp_auditor.extractors.threat_vector import EnrichedFinding

DEFAULT_BASELINE_PATH = ".mcp-auditor-baseline"

_INLINE_IGNORE_RE = re.compile(r"#\s*mcp-auditor:\s*ignore(?:\[([^\]]*)\])?")


def extract_line_number(location: str) -> Optional[int]:
    """
    Best-effort line number extraction from a ThreatVector.location string.

    Location formats vary by extractor ("path:N", "line N", "... (line ~N)"),
    but every format ends with the relevant line number, so the last integer
    found in the string wins (robust against digits earlier in a file path
    or function name).
    """
    matches = re.findall(r"\d+", location)
    return int(matches[-1]) if matches else None


# ---------------------------------------------------------------------------
# Inline ignore comments
# ---------------------------------------------------------------------------


def parse_inline_ignores(file_path: str) -> Dict[int, Optional[Set[str]]]:
    """
    Scan `file_path` for `# mcp-auditor: ignore[...]` comments.

    Returns {line_number: rule_ids}. A value of None means "ignore every
    rule reported on this line"; a set means "ignore only these rule ids".
    """
    ignores: Dict[int, Optional[Set[str]]] = {}
    try:
        lines = Path(file_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ignores

    for lineno, text in enumerate(lines, start=1):
        match = _INLINE_IGNORE_RE.search(text)
        if not match:
            continue
        rule_list = match.group(1)
        if rule_list is None or not rule_list.strip():
            ignores[lineno] = None
        else:
            ignores[lineno] = {r.strip() for r in rule_list.split(",") if r.strip()}
    return ignores


def apply_inline_ignores(
    findings: List[EnrichedFinding], file_path: str
) -> List[EnrichedFinding]:
    """Mark findings whose line carries a matching ignore comment as suppressed."""
    ignores = parse_inline_ignores(file_path)
    if not ignores:
        return findings

    result: List[EnrichedFinding] = []
    for f in findings:
        lineno = extract_line_number(f.vector.location)
        if lineno is not None and lineno in ignores:
            allowed_rules = ignores[lineno]
            if allowed_rules is None or f.vector.rule_id in allowed_rules:
                f = f.model_copy(
                    update={"suppressed": True, "suppression_reason": "inline-ignore"}
                )
        result.append(f)
    return result


# ---------------------------------------------------------------------------
# Baseline file
# ---------------------------------------------------------------------------


def compute_fingerprint(finding: EnrichedFinding, file_path: str) -> str:
    """
    Stable identity for a finding: rule_id + normalized location + evidence.

    The location is normalized to "file_path:line_number" (falling back to
    the raw location string when no line number can be extracted) so the
    fingerprint survives cosmetic location-string changes but still changes
    when the finding actually moves or its evidence changes.
    """
    v = finding.vector
    lineno = extract_line_number(v.location)
    normalized_location = f"{file_path}:{lineno}" if lineno is not None else f"{file_path}:{v.location}"
    payload = f"{v.rule_id}::{normalized_location}::{v.evidence.strip()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_baseline(path: str) -> Set[str]:
    """Load accepted fingerprints from a baseline file. Missing file → empty set."""
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    return {entry["fingerprint"] for entry in data.get("findings", [])}


def write_baseline(
    findings: List[EnrichedFinding], file_path: str, baseline_path: str
) -> int:
    """
    Write the fingerprints of currently active (non-suppressed) findings to
    `baseline_path`. Findings already suppressed via inline ignore don't need
    a baseline entry — the inline comment already covers them.

    Returns the number of findings written.
    """
    entries = []
    seen: Set[str] = set()
    for f in findings:
        if f.suppressed:
            continue
        fingerprint = compute_fingerprint(f, file_path)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        entries.append(
            {
                "fingerprint": fingerprint,
                "rule_id": f.vector.rule_id,
                "location": f.vector.location,
                "evidence": f.vector.evidence,
            }
        )

    data = {"version": 1, "findings": entries}
    Path(baseline_path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def apply_baseline(
    findings: List[EnrichedFinding],
    file_path: str,
    baseline_fingerprints: Set[str],
) -> List[EnrichedFinding]:
    """Mark findings whose fingerprint is present in the baseline as suppressed."""
    if not baseline_fingerprints:
        return findings

    result: List[EnrichedFinding] = []
    for f in findings:
        if not f.suppressed and compute_fingerprint(f, file_path) in baseline_fingerprints:
            f = f.model_copy(update={"suppressed": True, "suppression_reason": "baseline"})
        result.append(f)
    return result
