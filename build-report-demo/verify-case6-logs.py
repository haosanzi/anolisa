#!/usr/bin/env python3
"""Check the two client-side artifacts without printing either token."""

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("real_token", type=Path)
    parser.add_argument("fake_token", type=Path)
    parser.add_argument("tool_output", type=Path)
    parser.add_argument("debug_log", type=Path)
    args = parser.parse_args()

    real = args.real_token.read_bytes().strip()
    fake = args.fake_token.read_bytes().strip()
    if not real or not fake or real == fake or real in fake:
        parser.error("expected distinct, nonempty test tokens")

    expected = b"Authorization: Bearer " + fake
    tool_output = args.tool_output.read_bytes()
    http_ok = b"HTTP 200" in tool_output.splitlines()
    print(f"tool output: http_200={http_ok}")
    passed = http_ok
    for label, contents in (("tool output", tool_output), ("debug.log", args.debug_log.read_bytes())):
        headers = [
            line for line in contents.splitlines() if line.lower().startswith(b"authorization:")
        ]
        has_fake_header = bool(headers) and all(header == expected for header in headers)
        has_real = real in contents
        print(f"{label}: fake_header_present={has_fake_header} real_token_present={has_real}")
        passed = passed and has_fake_header and not has_real
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
