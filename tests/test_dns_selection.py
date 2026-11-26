from datetime import datetime

from dns_selection import Choice, choose, current_batch


A, B, C = "192.0.2.1", "192.0.2.2", "192.0.2.3"


def test_repeat_batch_cannot_confirm_a_new_dns_preference():
    first = choose(Choice(A), [A, B], {A, B}, set(), [B, A], "batch-1")
    assert first.active == A
    assert choose(first, [A, B], {A, B}, set(), [B, A], "batch-1") == first
    assert choose(first, [A, B], {A, B}, set(), [B, A], "batch-0") == first
    assert choose(first, [A, B], {A, B}, set(), [B, A], "batch-2").active == B


def test_receipt_must_be_from_current_audit():
    now = datetime.fromtimestamp(1_800_000_010)
    started_at = 1_800_000_000_000_000_000
    run = f"{started_at + 1}-123"
    assert current_batch(run, started_at, now) == run
    assert not current_batch(f"{started_at - 1}-123", started_at, now)
    assert not current_batch(f"{started_at + 20_000_000_000}-123", started_at, now)


def test_missing_evidence_retains_current_and_nonmembers_never_win():
    assert choose(Choice(A), [A, B], {C}, set(), [C], "batch-1").active == A
    assert choose(Choice(A), [A, B], set(), {A}, [B], "batch-2").active == A


def test_established_failure_allows_safe_replacement_without_waiting():
    assert choose(Choice(A), [A, B], {B}, {A}, [B], "batch-1").active == B


def test_fresh_competitive_loss_breaks_the_streak():
    next_choice = choose(Choice(A), [A, B], {A, B}, set(), [B, A], "batch-1")
    stable = choose(next_choice, [A, B], {A, B}, set(), [A, B], "batch-2")
    assert choose(stable, [A, B], {A, B}, set(), [B, A], "batch-3").active == A
