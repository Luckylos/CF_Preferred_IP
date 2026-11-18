"""B3/D behavior contracts: confidence-aware ranking and off-peak discovery screening."""

from __future__ import annotations

import math
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _screen_threshold(hour: int) -> str:
    proc = subprocess.run(
        [
            "/usr/bin/bash",
            "-c",
            f"source {ROOT / 'config.sh'}; vless_screen_admit_ttfb {hour}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@pytest.mark.parametrize(
    ("hour", "expected"),
    [(0, "100"), (3, "100"), (4, "60"), (9, "60"), (10, "100"), (23, "100")],
)
def test_off_peak_threshold_only_changes_discovery_screen(hour: int, expected: str) -> None:
    """Given the configured peak ranges, discovery screen gets the correct threshold."""
    assert _screen_threshold(hour) == expected


def test_cycle_screen_uses_effective_off_peak_threshold() -> None:
    """cycle.sh（取代 run.sh）只把时段门槛传给 --screen；audit 不受影响。"""
    body = (ROOT / "cycle.sh").read_text(encoding="utf-8")
    assert "vless_screen_admit_ttfb" in body
    assert 'VLESS_SCREEN_ADMIT_TTFB="$SCREEN_ADMIT_TTFB"' in body
    assert "--admit-ttfb" not in body
    verifier = (ROOT / "verify_vless.sh").read_text(encoding="utf-8")
    assert 'VLESS_ADMIT_TTFB="${VLESS_SCREEN_ADMIT_TTFB:-$VLESS_ADMIT_TTFB}"' in verifier
