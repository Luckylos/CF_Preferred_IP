from datetime import datetime, timedelta

from quality_evidence import Batch, Request, assess, load_batches, parse_transfers, reference_key, store_batches


NOW = datetime(2026, 11, 27, 23, 30)
IP = "192.0.2.1"


def batch(when, warm=55, *, first=900, path="ref", peer=IP):
    return Batch(when, when.isoformat(), path, peer, (
        Request("ok", first), *(Request("ok", warm) for _ in range(3)),
    ))


def clean():
    hours = (8, 10, 12, 14, 16, 17, 18, 19, 20, 22, 23)
    return [batch(NOW.replace(hour=h, minute=0)) for h in hours]


def with_references(evidence):
    return evidence + [batch(b.ts, peer="192.0.2.9") for b in evidence]


def test_curl_results_preserve_first_timeout_and_missing_slots():
    assert parse_transfers("0\t200\t0.725\t0\n1\t000\t0.000\t28\n"
                           "3\t503\t0.052\t0", 3) == (
        Request("ok", 725), Request("timeout", None),
        Request("not_started", None), Request("http_503", 52),
    )


def test_first_latency_not_used_and_both_halves_required():
    assert assess(clean(), IP, "ref", NOW).state == "eligible"
    assert assess(clean()[:-2], IP, "ref", NOW).state == "pending"
    assert assess(clean(), IP, "changed", NOW).state == "pending"


def test_first_timeout_does_not_qualify_on_warm_success_alone():
    from dataclasses import replace

    evidence = [replace(b, requests=(Request("timeout", None), *b.requests[1:])) for b in clean()]
    assert assess(evidence, IP, "ref", NOW).state == "pending"
    assert assess(with_references(evidence), IP, "ref", NOW).state == "ineligible"


def test_batch_ids_do_not_multiply_evidence():
    assert assess([clean()[0]] * 50, IP, "ref", NOW).state == "pending"


def test_peak_tail_is_not_diluted_and_second_block_confirms():
    evidence = clean()
    evidence[-1] = batch(evidence[-1].ts, 140)
    assert assess(evidence, IP, "ref", NOW).state == "pending"
    evidence[-2] = batch(evidence[-2].ts, 140)
    assert assess(with_references(evidence), IP, "ref", NOW).state == "ineligible"


def test_same_latency_can_pass_peak_and_fail_off_peak():
    evidence = clean()
    evidence[-2:] = [batch(b.ts, 100) for b in evidence[-2:]]
    assert assess(evidence, IP, "ref", NOW).state == "eligible"
    evidence[:2] = [batch(b.ts, 100) for b in evidence[:2]]
    assert assess(with_references(evidence), IP, "ref", NOW).state == "ineligible"


def test_later_clean_round_does_not_attribute_shared_failures_to_a_candidate():
    evidence = clean()
    down = (Request("timeout", None),) * 4
    up = (Request("ok", 55),) * 4
    for idx in (len(evidence) - 3, len(evidence) - 2):
        b = evidence[idx]
        evidence[idx] = Batch(b.ts, b.run, "ref", IP, down)
        evidence.extend(Batch(b.ts, b.run, "ref", f"192.0.2.{n}", down if n <= 3 else up)
                        for n in range(2, 6))
    quality = assess(evidence, IP, "ref", NOW)
    assert quality.state != "ineligible"
    assert quality.last_attempt == max(b.ts for b in evidence if b.ip == IP)


def test_simultaneous_unreachable_is_not_proof_against_candidate():
    evidence = clean()
    for idx in (len(evidence) - 1, len(evidence) - 2):
        b = evidence[idx]
        down = (Request("timeout", None),) * 4
        evidence[idx] = Batch(b.ts, b.run, "ref", IP, down)
        evidence.append(Batch(b.ts, b.run, "ref", "192.0.2.2", down))
    result = assess(evidence, IP, "ref", NOW)
    assert result.state == "pending"
    assert result.unresolved == 2


def test_old_high_peak_evidence_cannot_supply_freshness():
    evidence = clean()[:-3] + [batch(b.ts - timedelta(days=1)) for b in clean()[-3:]]
    assert assess(evidence, IP, "ref", NOW).state == "pending"


def test_private_store_retains_only_compatible_nonexpired_records(tmp_path):
    path = tmp_path / "observations.jsonl"
    ref = reference_key(["reference"])
    current = batch(NOW, path=ref)
    old = batch(NOW - timedelta(days=8), path=ref)
    store_batches(path, [old, current], NOW)
    store_batches(path, [current], NOW)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_batches(path, NOW, ref) == [current]
    assert load_batches(path, NOW, reference_key(["changed"])) == []


def test_rank_uses_current_reference_and_preserves_existing_publication():
    from rank import Config, Sample, run_rank

    incumbents = ["192.0.2.2", "192.0.2.3", "192.0.2.4"]
    pool = [IP, *incumbents]
    legacy = [Sample(b.ts, ip, "PASS", 49) for ip in pool for b in clean()]
    result = run_rank(legacy, pool, incumbents, NOW, Config(),
                      evidence=clean(), reference="ref")

    assert result.published is None
    assert result.ranked[0].ip == IP
    assert result.ranked[0].stats.quality.state == "eligible"
    assert {r.stats.quality.state for r in result.ranked[1:]} == {"pending"}
    assert result.evicted == []


def test_shared_slowdown_needs_recovery_not_candidate_eviction():
    evidence = clean()
    suspect = evidence[-2:]
    evidence[-2:] = [batch(b.ts, 250) for b in suspect]
    evidence.extend(batch(b.ts, 250, peer="192.0.2.9") for b in suspect)
    assert assess(evidence, IP, "ref", NOW).state == "pending"
    assert assess(evidence, IP, "ref", NOW).unresolved == 2


def test_fast_opportunities_rotate_even_when_candidates_have_no_valid_evidence():
    from rank import Config, run_rank

    peers = [f"192.0.2.{i}" for i in range(2, 24)]
    evidence = [batch(NOW - timedelta(minutes=1), None, peer=ip) for ip in peers[:10]]
    out = run_rank([], peers, [], NOW, Config(), evidence=evidence, reference="ref")
    assert len(out.challengers) == 10
    assert not set(out.challengers) & set(peers[:10])


def test_quality_unknown_does_not_let_legacy_markers_grant_eligibility():
    from rank import Config, Contender, run_rank

    row = Contender(IP, "2026-11-01 00:00:00", "-", "screen", "2026-11-02 00:00:00")
    out = run_rank([], [IP], [], NOW, Config(), contenders=[row], evidence=[], reference="ref")
    assert out.ranked[0].stats.quality.state == "pending"
    assert not out.evaluations


def test_capacity_reentry_keeps_lifecycle_only_for_same_reference(tmp_path):
    from rank import Contender, read_lifecycle, write_lifecycle

    path = tmp_path / "lifecycle.json"
    first = (NOW - timedelta(days=3)).strftime("%F %T")
    completed = (NOW - timedelta(days=2)).strftime("%F %T")
    row = Contender(IP, first, "-", "screen", completed)
    write_lifecycle(path, "ref", {}, [], [row], NOW)
    assert read_lifecycle(path, "ref", NOW) == {IP: (first, completed)}
    assert read_lifecycle(path, "changed", NOW) == {}


def test_rank_cli_does_not_publish_from_stale_or_unrecorded_receipt(tmp_path):
    from dataclasses import replace
    from publication_snapshot import migrate, read
    from rank import Contender, main, write_contenders

    candidates = (IP, "192.0.2.2", "198.51.100.3")
    old_members = ("203.0.113.5", "203.0.113.6", "203.0.113.7")
    old = "# --- BEST_IPS (machine-readable, one IP per line) ---\n" + "\n".join(old_members) + "\n"
    best = tmp_path / "best.txt"
    best.write_text(old)
    migrate(best, 3)
    snapshot = best.with_name(".publish_desired.json")
    original = snapshot.read_bytes()
    contenders = tmp_path / "contenders.tsv"
    write_contenders(contenders, [Contender(ip, "2026-11-24 01:00:00", "-", "screen") for ip in candidates])
    obs = tmp_path / "observations.jsonl"
    receipt = tmp_path / "receipt"
    from audit_evidence import digest
    import json

    planned = tmp_path / "targets"
    planned.write_text("\n".join(candidates) + "\n")
    start = int(NOW.timestamp()) * 10**9 - 60 * 10**9
    run = f"{start:020d}-fast-1-2"
    ref = reference_key(["isolated-test"])
    evidence = [replace(b, ip=ip, path=ref) for b in clean() for ip in candidates]
    options = ["--contenders", str(contenders), "--best", str(best), "--blacklist", str(tmp_path / "blacklist"),
               "--observations", str(obs), "--reference-file", str(receipt), "--audit-targets", str(planned),
               "--audit-run", run, "--audit-start-ns", str(start), "--now", NOW.strftime("%F %T")]
    batch_rows = [replace(batch(NOW - timedelta(seconds=1), peer=ip, path=ref), run=run) for ip in candidates]
    plan = {"run": run, "reference": ref, "targets": sorted(candidates), "observations": digest(batch_rows)}
    store_batches(obs, evidence, NOW)
    receipt.write_text(json.dumps({**plan, "run": "stale"}))
    assert main(options) == 0
    assert best.read_text() == old
    receipt.write_text(json.dumps(plan))
    assert main(options) == 0
    assert best.read_text() == old
    store_batches(obs, batch_rows, NOW)
    assert main(options + ["--audit-ok", "0"]) == 0
    assert best.read_text() == old
    assert snapshot.read_bytes() == original
    assert main(options) == 0
    assert all(ip in best.read_text().splitlines() for ip in candidates)
    assert "203.0.113.5" not in best.read_text().splitlines()
    assert set(read(snapshot).members) == set(candidates)


def test_misub_replacement_keeps_surviving_member_slots():
    from rank import Config, Ranked, Stats, sticky_publish

    incumbents = ["192.0.2.2", "198.51.100.3", "203.0.113.4"]
    winner = Ranked(IP, Stats(10, 0, 50, 60, True, NOW, 0,
                              quality=assess(clean(), IP, "ref", NOW)), 1, .9, 1)
    ranked = [winner] + [Ranked(ip, winner.stats, .8, score, .9)
                         for ip, score in zip(incumbents, [.8, .7, .6])]
    result = sticky_publish(ranked, incumbents, Config(), set())
    assert result[:3] == [incumbents[0], incumbents[1], IP]
