"""Strict IPv4 validation shared by CFST input boundaries."""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Iterable


def is_valid_ipv4(value: str) -> bool:
    """Return True only for a canonical, whitespace-free IPv4 literal."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address)


def is_valid_ipv4_network(value: str) -> bool:
    """Return True for an IPv4 literal or IPv4 network in CIDR notation."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return isinstance(network, ipaddress.IPv4Network)


def _validate_lines(
    lines: Iterable[str],
    field: int | None = None,
    strict: bool = True,
    network: bool = False,
) -> int:
    invalid = False
    validator = is_valid_ipv4_network if network else is_valid_ipv4
    for raw_line in lines:
        value = raw_line.rstrip("\r\n")
        if not value:
            continue
        candidate = value
        if field is not None:
            columns = value.split("\t")
            if field < 1 or field > len(columns):
                candidate = ""
            else:
                candidate = columns[field - 1]
        if validator(candidate):
            print(value)
        else:
            print(f"invalid IPv4: {candidate!r}", file=sys.stderr)
            invalid = True
    return 1 if invalid and strict else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="validate IPv4 addresses from stdin")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--strict",
        action="store_true",
        help="emit valid lines and return nonzero if any non-empty line is invalid",
    )
    mode.add_argument(
        "--filter",
        action="store_true",
        help="emit only valid lines and return zero for invalid records",
    )
    mode.add_argument(
        "--filter-network",
        action="store_true",
        help="emit only valid IPv4 literals or CIDR networks",
    )
    parser.add_argument(
        "--field",
        type=int,
        help="validate this 1-based tab-separated field instead of the whole line",
    )
    args = parser.parse_args()
    return _validate_lines(
        sys.stdin,
        field=args.field,
        strict=args.strict,
        network=args.filter_network,
    )


if __name__ == "__main__":
    raise SystemExit(main())
