"""The ordered publication members and DNS decision committed by ranking."""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from atomic_io import atomic_write
from dns_selection import Choice, read as read_legacy_dns, write as write_legacy_dns
from ip_validation import is_valid_ipv4

FILENAME = ".publish_desired.json"
MARKER = "# --- BEST_IPS (machine-readable, one IP per line) ---"


@dataclass(frozen=True)
class Publication:
    members: tuple[str, ...]
    choice: Choice

    def __post_init__(self) -> None:
        if (not self.members or not all(is_valid_ipv4(ip) for ip in self.members)
                or len(set(self.members)) != len(self.members)):
            raise ValueError("publication snapshot requires distinct IPv4 members")
        choice = self.choice
        if (choice.active not in ("", *self.members)
                or (choice.challenger != "" and not is_valid_ipv4(choice.challenger))
                or not isinstance(choice.last_batch, str) or not isinstance(choice.reference, str)):
            raise ValueError("publication snapshot has invalid DNS selection")


def read(path: Path, *, expected_count: int | None = None) -> Publication:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or data.keys() != {"version", "members", "dns"}
            or type(data["version"]) is not int or data["version"] != 1
            or not isinstance(data["members"], list) or not isinstance(data["dns"], dict)):
        raise ValueError("unrecognized publication snapshot format")
    publication = Publication(tuple(data["members"]), Choice(**data["dns"]))
    if expected_count is not None and len(publication.members) != expected_count:
        raise ValueError("publication snapshot does not contain the configured member count")
    return publication


def write(path: Path, publication: Publication) -> None:
    data = {"version": 1, "members": publication.members, "dns": asdict(publication.choice)}
    atomic_write(path, json.dumps(data) + "\n")


def migrate(best: Path, count: int) -> Publication:
    """Initialize under the production cycle and application locks."""
    path = best.with_name(FILENAME)
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    _, lines = legacy_best(best)
    members = tuple(line for line in lines if line and line[0] in "0123456789")[:count]
    if len(members) != count:
        raise ValueError("legacy publication does not contain the configured member count")
    choice = read_legacy_dns(best.with_name(".dns_preference.json"), "")
    publication = Publication(members, choice)
    write(path, publication)
    return publication


def legacy_best(best: Path) -> tuple[list[str], list[str]]:
    lines = best.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# --- BEST_IPS"):
            return lines[:i], lines[i + 1:]
    raise ValueError("legacy publication marker is missing")


def project_legacy(best: Path, count: int) -> None:
    """Project the current publication into the old reader files under both locks."""
    if type(count) is not int:
        raise TypeError("configured publication member count must be an integer")
    publication = read(best.with_name(FILENAME), expected_count=count)
    header, old_members = legacy_best(best)
    members = list(publication.members)
    for ip in old_members[count:]:
        if is_valid_ipv4(ip) and ip not in members:
            members.append(ip)
    atomic_write(best, "\n".join([*header, MARKER, *members, ""]))
    # The legacy reader drops hysteresis when active is empty.
    choice = publication.choice
    write_legacy_dns(best.with_name(".dns_preference.json"),
                     replace(choice, active=choice.active or publication.members[0]))


def publish_misub(members: list[str]) -> None:
    """Supply the captured members through the existing MiSub parser."""
    import push_to_misub

    with os.fdopen(os.memfd_create("cfst-misub-publication"), "w") as snapshot:
        snapshot.write("\n".join([MARKER, *members, ""]))
        snapshot.flush()
        push_to_misub.BEST_IPS_FILE = f"/proc/self/fd/{snapshot.fileno()}"
        push_to_misub.main()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    targets = commands.add_parser("targets")
    targets.add_argument("path", type=Path)
    targets.add_argument("--ignore-preference", action="store_true")
    targets.add_argument("--count", type=int)
    seed = commands.add_parser("migrate")
    seed.add_argument("best", type=Path)
    seed.add_argument("count", type=int)
    legacy = commands.add_parser("project-legacy")
    legacy.add_argument("best", type=Path)
    legacy.add_argument("count", type=int)
    misub = commands.add_parser("misub")
    misub.add_argument("members", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "targets":
            publication = read(args.path, expected_count=args.count)
            preferred = "" if args.ignore_preference else publication.choice.active
            print(preferred, *publication.members, sep="\n")
        elif args.command == "migrate":
            migrate(args.best, args.count)
        elif args.command == "project-legacy":
            project_legacy(args.best, args.count)
        else:
            # Only direct pushes may override the addresses captured for automatic publication.
            os.environ.pop("CFST_NODE_HOST", None)
            publish_misub(args.members)
    except Exception as exc:
        parser.exit(1, f"publication snapshot: {exc}\n")


if __name__ == "__main__":
    main()
