from __future__ import annotations

import sys
import unittest

from rgkd.sizes import draft_claims, keydist_size, state_object_size


def main() -> int:
    claims = draft_claims()
    print("R-GKD draft size claims", file=sys.stderr)
    for name, value in claims.items():
        print(f"  {name}: {value}", file=sys.stderr)
    print(f"  state N=16 bytes: {state_object_size(16)}", file=sys.stderr)
    print(f"  keydist N=15 bytes: {keydist_size(15)}", file=sys.stderr)
    print(file=sys.stderr)
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
