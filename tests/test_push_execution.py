"""Observable reconcile contracts through the real execution seam, without helper patches."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from misub_fake_api import FakeMiSub

SPEC = importlib.util.spec_from_file_location(
    "push_execution_contract", Path(__file__).resolve().parents[1] / "push_to_misub.py"
)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)

NAMES = [f"{region['prefix']} {suffix}" for region in push.REGIONS for suffix in push.SUFFIXES]
DESIRED = {name: f"vless://test@192.0.2.{index + 1}:443#test" for index, name in enumerate(NAMES)}
PROFILE = "target"
PERSONAL_URL = "vless://test@192.0.2.254:443#personal"


def make_fake(*, current: bool = False) -> FakeMiSub:
    return FakeMiSub(
        subscriptions=[
            {"id": f"node-{index}", "name": name,
             "url": DESIRED[name] if current else f"vless://test@198.51.100.{index + 1}:443#old"}
            for index, name in enumerate(NAMES)
        ] + [{"id": "personal", "name": "Personal", "url": PERSONAL_URL}],
        profiles=[{"id": PROFILE, "name": push.PROFILE_NAME,
                   "manualNodes": ["personal", *[f"node-{i}" for i in range(len(NAMES))]]}],
    )


def run_push(fake: FakeMiSub, pending: Path, *, prepare=None, request=None, sleep=None) -> None:
    push.execute_push(
        prepare=prepare if prepare is not None else lambda managed: dict(DESIRED),
        request=request if request is not None else fake.request,
        pending_path=pending,
        sleep=sleep if sleep is not None else lambda seconds: None,
    )


def writes(fake: FakeMiSub) -> list[tuple[str, str]]:
    return [call for call in fake.calls if call[0] != "GET"]


def assert_converged(fake: FakeMiSub) -> None:
    refs = fake.profile_refs(PROFILE)
    assert refs[0] == "personal"
    assert len(refs) == len(NAMES) + 1
    assert [fake.subs[node_id]["name"] for node_id in refs[1:]] == NAMES
    assert all(fake.subs[node_id]["url"] == DESIRED[fake.subs[node_id]["name"]] for node_id in refs[1:])
    assert fake.subs["personal"]["url"] == PERSONAL_URL


def test_steady_state_uses_only_explicit_dependencies(tmp_path: Path) -> None:
    fake = make_fake(current=True)
    run_push(fake, tmp_path / "pending.json")
    assert not writes(fake)
    assert_converged(fake)
    assert not (tmp_path / "pending.json").exists()


def test_partial_update_keeps_pending_and_next_run_converges(tmp_path: Path) -> None:
    fake = make_fake()
    pending = tmp_path / "pending.json"
    patches = 0

    def fail_second_patch(method, path, data=None):
        nonlocal patches
        if method == "PATCH" and path.startswith("/manual-nodes/"):
            patches += 1
            assert pending.exists(), "marker must precede the external mutation"
            if patches == 2:
                return None
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError):
        run_push(fake, pending, request=fail_second_patch)
    assert pending.exists()
    assert fake.subs["node-0"]["url"] == DESIRED[NAMES[0]]
    assert fake.subs["node-1"]["url"] != DESIRED[NAMES[1]]
    assert "vless://" not in pending.read_text()
    run_push(fake, pending)
    assert not pending.exists()
    assert_converged(fake)
    assert not any(method in {"POST", "DELETE"} for method, _ in fake.calls)


def test_invalid_pending_is_rejected_before_preparation(tmp_path: Path) -> None:
    fake = make_fake()
    pending = tmp_path / "pending.json"
    pending.write_text("invalid")
    prepared = []

    def prepare(managed):
        prepared.append(True)
        return dict(DESIRED)

    with pytest.raises(RuntimeError, match="pending reconcile marker"):
        run_push(fake, pending, prepare=prepare)
    assert not prepared
    assert not fake.calls


@pytest.mark.parametrize("invalid_path", [None, "pending.json"])
def test_explicit_pending_path_cannot_fall_back_to_global(invalid_path) -> None:
    fake = make_fake()

    def prepare(managed):
        raise AssertionError("invalid dependency must be rejected before preparation")

    with pytest.raises(TypeError, match="pending reconcile path is invalid"):
        run_push(fake, invalid_path, prepare=prepare)
    assert not fake.calls


def test_preflight_failure_precedes_all_remote_writes(tmp_path: Path) -> None:
    """preflight 失败必须发生在任何写入之前。

    读取是允许的：目标状态要从节点现有凭据推导（HT 与 HK/SG 的 uuid 不同），
    所以先读后验，但绝不能先写。
    """
    fake = make_fake()

    def rejected(managed):
        raise RuntimeError("preflight refused")

    with pytest.raises(RuntimeError, match="preflight refused"):
        run_push(fake, tmp_path / "pending.json", prepare=rejected)
    assert [call[0] for call in fake.calls] == ["GET"] * len(fake.calls)
    assert not (tmp_path / "pending.json").exists()


def test_foreign_refs_protect_only_the_referenced_duplicate(tmp_path: Path) -> None:
    fake = make_fake()
    for node_id in ["shared-dupe", "unused-dupe"]:
        fake.subs[node_id] = dict(fake.subs["node-0"], id=node_id)
    fake.profiles["other"] = {"id": "other", "name": "Other", "manualNodes": []}
    fake.prime_profiles_cache("iso-0")
    fake.profiles["other"]["manualNodes"] = ["node-0", "shared-dupe"]
    run_push(fake, tmp_path / "pending.json")
    assert "shared-dupe" in fake.subs
    assert "unused-dupe" not in fake.subs
    assert fake.profile_refs("other") == ["node-0", "shared-dupe"]
    assert fake.subs["node-0"]["url"] == DESIRED[NAMES[0]]
    assert_converged(fake)


def test_deletes_precede_binding_and_unreferenced_nodes_are_reused(tmp_path: Path) -> None:
    fake = make_fake()
    fake.subs["duplicate"] = dict(fake.subs["node-0"], id="duplicate")
    fake.profiles[PROFILE]["manualNodes"] = ["personal"]
    run_push(fake, tmp_path / "pending.json")
    assert_converged(fake)
    assert "duplicate" not in fake.subs
    assert not any(method == "POST" for method, _ in fake.calls)
    deletion = fake.calls.index(("DELETE", "/manual-nodes/duplicate"))
    bindings = [i for i, (method, path) in enumerate(fake.calls) if method == "PATCH" and path.startswith("/profiles/")]
    assert bindings and all(deletion < i for i in bindings)


@pytest.mark.parametrize("failure", [None, {"success": False, "error": {"status": 503}}, {"success": True, "data": {"id": "personal"}}])
def test_unknown_read_never_authorizes_writes(tmp_path: Path, failure) -> None:
    fake = make_fake()
    before = fake.profile_refs(PROFILE)

    def request(method, path, data=None):
        if path == "/manual-nodes/personal":
            return failure
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError, match="UNKNOWN"):
        run_push(fake, tmp_path / "pending.json", request=request)
    assert fake.profile_refs(PROFILE) == before
    assert not writes(fake)


def test_unknown_foreign_read_blocks_all_writes(tmp_path: Path) -> None:
    fake = make_fake()
    fake.profiles["other"] = {"id": "other", "name": "Other", "manualNodes": ["node-0"]}

    def request(method, path, data=None):
        if path == "/profiles/other":
            return None
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError, match="fresh-read other profile"):
        run_push(fake, tmp_path / "pending.json", request=request)
    assert not writes(fake)


def test_cached_ghost_is_not_deleted_and_stale_ref_is_dropped(tmp_path: Path) -> None:
    fake = make_fake()
    fake.subs["ghost"] = dict(fake.subs["node-0"], id="ghost")
    fake.profiles[PROFILE]["manualNodes"].append("ghost")
    fake.prime_subscriptions_cache("iso-0")
    del fake.subs["ghost"]
    run_push(fake, tmp_path / "pending.json")
    assert ("DELETE", "/manual-nodes/ghost") not in fake.calls
    assert_converged(fake)


def test_managed_ref_missing_from_collection_is_reused(tmp_path: Path) -> None:
    fake = make_fake()
    missing = fake.subs.pop("node-0")
    fake.prime_subscriptions_cache("iso-0")
    fake.subs["node-0"] = missing
    run_push(fake, tmp_path / "pending.json")
    assert_converged(fake)
    assert not any(method in {"POST", "DELETE"} for method, _ in fake.calls)


def test_final_fresh_read_failure_keeps_pending(tmp_path: Path) -> None:
    fake = make_fake()
    pending = tmp_path / "pending.json"
    profile_reads = 0

    def request(method, path, data=None):
        nonlocal profile_reads
        if method == "GET" and path == f"/profiles/{PROFILE}":
            profile_reads += 1
            if profile_reads == 3:
                return {"success": True, "data": {"manualNodeIds": []}}
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError, match="profile references do not match"):
        run_push(fake, pending, request=request)
    assert pending.exists()
    run_push(fake, pending)
    assert not pending.exists()
    assert_converged(fake)


def test_pending_write_failure_prevents_mutation(tmp_path: Path) -> None:
    fake = make_fake()
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("occupied")
    with pytest.raises(OSError):
        run_push(fake, blocked / "pending.json")
    assert not writes(fake)


def test_pending_clear_failure_remains_visible(tmp_path: Path) -> None:
    fake = make_fake()
    pending = tmp_path / "pending.json"

    def request(method, path, data=None):
        response = fake.request(method, path, data)
        if method == "PATCH" and path.endswith("node-5"):
            pending.unlink()
            pending.mkdir()
        return response

    with pytest.raises(RuntimeError, match="could not clear pending"):
        run_push(fake, pending, request=request)
    assert pending.is_dir()
    assert_converged(fake)


def test_ambiguous_create_is_not_repeated_on_cached_retry(tmp_path: Path) -> None:
    fake = make_fake()
    fake.profiles[PROFILE]["manualNodes"].remove("node-0")
    del fake.subs["node-0"]
    fake.prime_subscriptions_cache("iso-0")
    pending = tmp_path / "pending.json"

    def lost_response(method, path, data=None):
        if method == "POST":
            fake._router = lambda method, path: "writer"  # cached reader remains stale
            fake.request(method, path, data)
            fake._router = lambda method, path: "iso-0"
            return None
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError):
        run_push(fake, pending, request=lost_response)
    assert pending.exists()
    post_count = sum(method == "POST" for method, _ in fake.calls)
    with pytest.raises(RuntimeError, match="refusing duplicate POST"):
        run_push(fake, pending)
    assert sum(method == "POST" for method, _ in fake.calls) == post_count == 1
    fake._router = lambda method, path: "fresh-reader"
    run_push(fake, pending)
    assert_converged(fake)
    assert not pending.exists()


@pytest.mark.parametrize("recovers", [False, True])
def test_visibility_retries_are_bounded_and_never_bind_missing_nodes(tmp_path: Path, recovers: bool) -> None:
    fake = make_fake()
    fake.profiles[PROFILE]["manualNodes"].remove("node-0")
    del fake.subs["node-0"]
    created_id = None
    reads = 0
    waits = []

    def request(method, path, data=None):
        nonlocal created_id, reads
        if method == "POST":
            response = fake.request(method, path, data)
            created_id = response["data"]["id"]
            return response
        if created_id is not None and method == "GET" and path == f"/manual-nodes/{created_id}":
            reads += 1
            if not recovers or reads == 1:
                return {"success": False, "error": {"status": 404}}
        return fake.request(method, path, data)

    pending = tmp_path / "pending.json"
    if recovers:
        run_push(fake, pending, request=request, sleep=waits.append)
        assert_converged(fake)
        assert waits == [push.NODE_VISIBILITY_DELAY_SECONDS]
        assert not pending.exists()
    else:
        with pytest.raises(RuntimeError, match="not visible"):
            run_push(fake, pending, request=request, sleep=waits.append)
        assert reads == push.NODE_VISIBILITY_ATTEMPTS
        assert waits == [push.NODE_VISIBILITY_DELAY_SECONDS] * (push.NODE_VISIBILITY_ATTEMPTS - 1)
        assert pending.exists()
        assert not any(method == "PATCH" for method, _ in fake.calls)


@pytest.mark.parametrize("recovers", [False, True])
def test_bind_retries_require_fresh_convergence(tmp_path: Path, recovers: bool) -> None:
    fake = make_fake()
    fake.profiles[PROFILE]["manualNodes"] = ["personal"]
    attempts = 0
    waits = []

    def request(method, path, data=None):
        nonlocal attempts
        if method == "PATCH" and path == f"/profiles/{PROFILE}":
            attempts += 1
            if recovers and attempts == 1:
                return None
            if not recovers:
                return {"success": True, "data": data}  # echoed write is not proof
        return fake.request(method, path, data)

    pending = tmp_path / "pending.json"
    if recovers:
        run_push(fake, pending, request=request, sleep=waits.append)
        assert_converged(fake)
        assert attempts == 2
        assert waits == [push.BIND_RETRY_DELAY_SECONDS]
    else:
        with pytest.raises(RuntimeError, match="could not bind"):
            run_push(fake, pending, request=request, sleep=waits.append)
        assert attempts == push.BIND_ATTEMPTS
        assert waits == [push.BIND_RETRY_DELAY_SECONDS] * (push.BIND_ATTEMPTS - 1)
        assert pending.exists()


def test_node_disappearing_before_bind_is_not_referenced(tmp_path: Path) -> None:
    fake = make_fake()
    fake.profiles[PROFILE]["manualNodes"] = ["personal"]
    seen = 0

    def request(method, path, data=None):
        nonlocal seen
        if method == "GET" and path == "/manual-nodes/node-0":
            seen += 1
            if seen == 2:
                return {"success": False, "error": {"status": 404}}
        return fake.request(method, path, data)

    with pytest.raises(RuntimeError, match="refusing to bind"):
        run_push(fake, tmp_path / "pending.json", request=request)
    assert not any(method == "PATCH" and path.startswith("/profiles/") for method, path in fake.calls)


def test_main_assembles_the_real_execution_dependencies(monkeypatch) -> None:
    observed = []
    monkeypatch.setattr(push, "execute_push", lambda **kwargs: observed.append(kwargs))
    push.main()
    assert observed == [{"prepare": push._prepare_desired_urls, "request": push.api_request,
                         "pending_path": push.PENDING_RECONCILE_FILE, "sleep": push.time.sleep}]
