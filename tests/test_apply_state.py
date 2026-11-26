"""状态指纹必须覆盖"节点 URL 的内容"，否则改模板不会触发重新推送。"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(tmp_path: Path, *, hk_query: str) -> Path:
    """把 config.sh 搬进沙箱：CFST_DIR 指向临时目录，依赖文件全部自造。"""
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = (ROOT / "config.sh").read_text().replace("CFST_DIR=/opt/cfst", f"CFST_DIR={tmp_path}")
    config = config.replace("CFST_TEMPLATE_HK_QUERY='" + find_hk_query(config) + "'",
                            "CFST_TEMPLATE_HK_QUERY='" + hk_query + "'")
    (tmp_path / "config.sh").write_text(config, encoding="utf-8")
    (tmp_path / "push_to_misub.py").write_text("# stub\n", encoding="utf-8")
    (tmp_path / "best_ips.txt").write_text(
        "# header\n# --- BEST_IPS (machine-readable, one IP per line) ---\n"
        "203.0.113.1\n203.0.113.2\n203.0.113.3\n",
        encoding="utf-8")
    from publication_snapshot import migrate

    for name in ("publication_snapshot.py", "dns_selection.py", "ip_validation.py", "atomic_io.py"):
        shutil.copy2(ROOT / name, tmp_path)
    migrate(tmp_path / "best_ips.txt", 3)
    return tmp_path / "config.sh"


def find_hk_query(config: str) -> str:
    line = next(l for l in config.splitlines() if l.startswith("CFST_TEMPLATE_HK_QUERY="))
    return line.split("=", 1)[1].strip().strip("'")


def state(config: Path) -> str:
    out = subprocess.run(
        ["bash", "-c", f'set -e; source "{config}" >/dev/null 2>&1; compute_apply_state'],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_template_change_changes_the_state(tmp_path: Path) -> None:
    first = state(build(tmp_path / "a", hk_query="type=ws&sni=a.example.com"))
    second = state(build(tmp_path / "b", hk_query="type=xhttp&sni=b.example.com"))
    assert first and second and first != second


def test_identical_templates_produce_the_same_state(tmp_path: Path) -> None:
    first = state(build(tmp_path / "c", hk_query="type=ws&sni=same.example.com"))
    second = state(build(tmp_path / "d", hk_query="type=ws&sni=same.example.com"))
    assert first == second
