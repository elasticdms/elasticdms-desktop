#!/usr/bin/env python3
"""Check the text catalogues with a second, foreign TOML implementation.

`crates/i18n/src/reader.rs` reads a strict subset of TOML with a reader of our own (the crate
header says why). A reader of our own can be wrong in a way its own tests do not see — so this
script parses the same files with Python's `tomllib`, which is not ours, and compares:

* both files are valid TOML for a parser that knows the whole language, and
* both have exactly the same set of dotted keys.

Exit code 0 when everything holds, 1 with a report otherwise. Run by `make check` next to the Rust
tests; the tests themselves compare the catalogues against `edms_i18n::KEYS`, which this script
cannot see.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "crates" / "i18n" / "catalog"


def flatten(table: dict, prefix: str = "") -> dict[str, object]:
    """Dotted keys, the way the Rust reader produces them."""
    out: dict[str, object] = {}
    for key, value in table.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, path + "."))
        else:
            out[path] = value
    return out


def main() -> int:
    files = sorted(CATALOG.glob("*.toml"))
    if not files:
        print(f"no catalogue found under {CATALOG}", file=sys.stderr)
        return 1

    problems: list[str] = []
    read: dict[str, dict[str, object]] = {}
    for path in files:
        try:
            with path.open("rb") as handle:
                read[path.stem] = flatten(tomllib.load(handle))
        except tomllib.TOMLDecodeError as error:
            problems.append(f"{path.name}: not valid TOML: {error}")

    if len(read) > 1:
        first, *rest = sorted(read)
        for other in rest:
            missing = sorted(set(read[first]) - set(read[other]))
            surplus = sorted(set(read[other]) - set(read[first]))
            for key in missing:
                problems.append(f"{other}.toml: `{key}` is missing (it stands in {first}.toml)")
            for key in surplus:
                problems.append(f"{other}.toml: `{key}` stands in no other catalogue")

    for name, entries in sorted(read.items()):
        for key, value in entries.items():
            if not isinstance(value, str):
                problems.append(f"{name}.toml: `{key}` is {type(value).__name__}, not a string")

    if problems:
        print("the text catalogues do not hold:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    for name, entries in sorted(read.items()):
        print(f"catalog/{name}.toml: valid TOML, {len(entries)} keys")
    return 0


if __name__ == "__main__":
    sys.exit(main())
