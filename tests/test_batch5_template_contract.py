"""Batch 5 D-TEMPLATE-OWNER: cross-entry VLESS template contract.

The test uses only a temporary config and local fake executables.  It exercises
verify_vless.sh's real config projection and compares its xray stream settings
with the URL emitted by push_to_misub.py.  No production secret or network is
used.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
TEST_UUID = "00000000-0000-4000-8000-000000000000"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _write_config(sandbox: Path) -> Path:
    config = sandbox / "config.sh"
    config.write_text(
        f'''CFST_DIR={sandbox}
RESULT_DIR="$CFST_DIR/results"
BYPASS_GID=0
VLESS_SECRET_FILE="$CFST_DIR/vless.env"
VLESS_HISTORY="$CFST_DIR/vless_history.tsv"
VERIFY_TMPDIR_BASE="$CFST_DIR/shm"
VLESS_TEMPLATE=HK
VLESS_TRIES=1
VLESS_VERIFY_TIMEOUT=1
VLESS_BATCH_SIZE=1
VLESS_MAX_TTFB=500
VLESS_HISTORY_DAYS=7
SCORE_TOP_N=1
VLESS_UUID=$(sed -n 's/^VLESS_UUID=//p' "$VLESS_SECRET_FILE" | tail -n1)

# Canonical template values for this isolated contract fixture.
CFST_TEMPLATE_HK_KEY=HK
CFST_TEMPLATE_HK_NAME_PREFIX="🧪 HK Golden"
CFST_TEMPLATE_HK_SNI="hk-golden.example"
CFST_TEMPLATE_HK_HOST="hk-golden.example"
CFST_TEMPLATE_HK_PATH="/golden?ed=512"
CFST_TEMPLATE_HK_FP="firefox"
CFST_TEMPLATE_HK_ALPN="h2"
CFST_TEMPLATE_HK_LEGACY_INSECURE_FLAGS=0
CFST_TEMPLATE_SG_KEY=SG
CFST_TEMPLATE_SG_NAME_PREFIX="🧪 SG Golden"
CFST_TEMPLATE_SG_SNI="sg-golden.example"
CFST_TEMPLATE_SG_HOST="sg-golden.example"
CFST_TEMPLATE_SG_PATH="/golden?ed=1024"
CFST_TEMPLATE_SG_FP="safari"
CFST_TEMPLATE_SG_ALPN=""
CFST_TEMPLATE_SG_LEGACY_INSECURE_FLAGS=1

declare -A NODE_HK=(
  [key]="$CFST_TEMPLATE_HK_KEY"
  [sni]="$CFST_TEMPLATE_HK_SNI"
  [host]="$CFST_TEMPLATE_HK_HOST"
  [path]="$CFST_TEMPLATE_HK_PATH"
  [uuid]="$VLESS_UUID"
  [fp]="$CFST_TEMPLATE_HK_FP"
  [alpn]="$CFST_TEMPLATE_HK_ALPN"
  [prefix]="$CFST_TEMPLATE_HK_NAME_PREFIX"
  [legacy_insecure_flags]="$CFST_TEMPLATE_HK_LEGACY_INSECURE_FLAGS"
)
declare -A NODE_SG=(
  [key]="$CFST_TEMPLATE_SG_KEY"
  [sni]="$CFST_TEMPLATE_SG_SNI"
  [host]="$CFST_TEMPLATE_SG_HOST"
  [path]="$CFST_TEMPLATE_SG_PATH"
  [uuid]="$VLESS_UUID"
  [fp]="$CFST_TEMPLATE_SG_FP"
  [alpn]="$CFST_TEMPLATE_SG_ALPN"
  [prefix]="$CFST_TEMPLATE_SG_NAME_PREFIX"
  [legacy_insecure_flags]="$CFST_TEMPLATE_SG_LEGACY_INSECURE_FLAGS"
)
''',
        encoding="utf-8",
    )
    return config


def _run_local_verifier(sandbox: Path) -> tuple[subprocess.CompletedProcess[str], Path]:
    (sandbox / "results").mkdir()
    (sandbox / "shm").mkdir()
    (sandbox / "vless.env").write_text(f"VLESS_UUID={TEST_UUID}\n", encoding="utf-8")
    (sandbox / "vless.env").chmod(0o600)
    (sandbox / "vless_history.tsv").write_text("", encoding="utf-8")
    input_file = sandbox / "ips.txt"
    input_file.write_text("1.1.1.1\n", encoding="utf-8")
    capture = sandbox / "xray-config.json"

    shutil.copy2(ROOT / "verify_vless.sh", sandbox / "vcheck.sh")
    shutil.copy2(ROOT / "ip_validation.py", sandbox / "ip_validation.py")
    (sandbox / "vcheck.sh").chmod(
        (sandbox / "vcheck.sh").stat().st_mode | stat.S_IXUSR
    )
    bindir = sandbox / "bin"
    bindir.mkdir()
    _write_executable(
        bindir / "setpriv",
        '''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pdeathsig|--regid) shift 2 ;;
    --clear-groups) shift ;;
    *) break ;;
  esac
done
exec "$@"
''',
    )
    _write_executable(
        bindir / "xray",
        '''#!/bin/sh
config=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-c" ]; then config="$2"; shift 2; else shift; fi
done
cp "$config" "$XRAY_CONFIG_CAPTURE"
trap 'exit 0' TERM INT
while :; do sleep 1; done
''',
    )
    _write_executable(
        bindir / "ss",
        "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 127.0.0.1:41000 0.0.0.0:*'\n",
    )
    _write_executable(
        bindir / "curl",
        '''#!/bin/sh
case "$*" in
  *http_code*) printf '200\t0.010000\n200\t0.010000\n' ;;
  *) printf '0.010000\n0.010000\n' ;;
esac
''',
    )
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["XRAY_CONFIG_CAPTURE"] = str(capture)
    proc = subprocess.run(
        [str(sandbox / "vcheck.sh"), "--audit", str(input_file)],
        cwd=sandbox,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return proc, capture


def _run_python_builder(config: Path) -> subprocess.CompletedProcess[str]:
    script = """
import push_to_misub as push
from unittest.mock import patch
region = next(item for item in push.REGIONS if item["key"] == "HK")
with patch.object(push, "get_vless_uuid", return_value=TEST_UUID):
    print(push.build_vless_url(region, "1.1.1.1", "CM"))
""".replace("TEST_UUID", repr(TEST_UUID))
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CFST_CONFIG_FILE"] = str(config)
    return subprocess.run(
        [os.environ.get("PYTHON", "python3"), "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_shell_and_python_consumers_share_canonical_template(tmp_path: Path) -> None:
    """A changed canonical template must reach both real consumers identically."""
    config = _write_config(tmp_path)
    verifier, captured = _run_local_verifier(tmp_path)
    assert verifier.returncode == 0, verifier.stderr
    assert "1.1.1.1  PASS 10" in verifier.stdout

    xray = json.loads(captured.read_text(encoding="utf-8"))
    stream = xray["outbounds"][0]["streamSettings"]
    tls = stream["tlsSettings"]
    ws = stream["wsSettings"]
    assert tls == {"serverName": "hk-golden.example", "fingerprint": "firefox"}
    assert ws == {"path": "/golden?ed=512", "headers": {"Host": "hk-golden.example"}}

    builder = _run_python_builder(config)
    assert builder.returncode == 0, builder.stderr
    url = builder.stdout.strip()
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    assert query["sni"] == [tls["serverName"]]
    assert query["host"] == [ws["headers"]["Host"]]
    assert query["path"] == [ws["path"]]
    assert query["fp"] == [tls["fingerprint"]]
    assert query["alpn"] == ["h2"]
    assert unquote(parsed.fragment) == "🧪 HK Golden CM"
    assert "insecure" not in query
    assert "allowInsecure" not in query


def test_production_config_exposes_every_pusher_template_field() -> None:
    """The canonical source must be explicit, not only a test-fixture convention."""
    text = (ROOT / "config.sh").read_text(encoding="utf-8")
    for region in ("HK", "SG"):
        for field in (
            "KEY",
            "NAME_PREFIX",
            "SNI",
            "HOST",
            "PATH",
            "FP",
            "ALPN",
            "LEGACY_INSECURE_FLAGS",
        ):
            assert f"CFST_TEMPLATE_{region}_{field}=" in text
        assert f'[host]="$CFST_TEMPLATE_{region}_HOST"' in text
        assert f'[path]="$CFST_TEMPLATE_{region}_PATH"' in text
        assert f'[fp]="$CFST_TEMPLATE_{region}_FP"' in text
        assert f'[prefix]="$CFST_TEMPLATE_{region}_NAME_PREFIX"' in text
