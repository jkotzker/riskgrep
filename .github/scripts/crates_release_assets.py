#!/usr/bin/env python3
"""Prepare the crates.io section and assets of a GitHub release.

For every publishable workspace package, finds `<name>-<version>.crate` in
--package-dir, checks that its SHA-256 equals the checksum the crates.io index
records for that version (waiting for the index to catch up after a publish),
and writes to --out-dir:

- assets/: the verified .crate files and SHA256SUMS, one `<sha256>  <file>`
  line per .crate file. These are the files to attach to the release;
- release-body.md: --body-in with the crates.io section added, or replaced if
  an earlier run already added one.

Uses only the standard library and `cargo metadata`.
"""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

INDEX = "https://index.crates.io"
USER_AGENT = "riskgrep-release (https://github.com/jkotzker/riskgrep)"
START = "<!-- crates.io: start -->"
END = "<!-- crates.io: end -->"


def packages():
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    # `publish = false` shows up as an empty list of allowed registries.
    return [(p["name"], p["version"]) for p in meta["packages"] if p["publish"] != []]


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def index_checksum(name, version, wait):
    url = f"{INDEX}/{index_path(name)}"
    deadline = time.monotonic() + wait
    while True:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                for line in response.read().decode().splitlines():
                    entry = json.loads(line)
                    if entry["vers"] == version:
                        return entry["cksum"]
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        if time.monotonic() >= deadline:
            sys.exit(f"{name} {version} is not in the crates.io index after {wait} s")
        time.sleep(15)


def section(rows, run_url):
    lines = [
        START,
        "### Published to crates.io",
        "",
        "| Crate | SHA-256 of the `.crate` file |",
        "|---|---|",
    ]
    for name, version, digest in rows:
        lines.append(f"| [`{name}` {version}](https://crates.io/crates/{name}/{version}) | `{digest}` |")
    lines += [
        "",
        f"Published by the [Release workflow]({run_url}) through crates.io Trusted Publishing. "
        "The attached `.crate` files are the packages it uploaded; each checksum matches the one in the crates.io index. "
        "Install with `cargo install --locked riskgrep riskgrep-claude`.",
        END,
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--package-dir", required=True, type=pathlib.Path)
    parser.add_argument("--out-dir", required=True, type=pathlib.Path)
    parser.add_argument("--body-in", required=True, type=pathlib.Path)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--wait", type=int, default=600, help="seconds to wait for the index")
    args = parser.parse_args()

    assets = args.out_dir / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    rows = []
    sums = []
    for name, version in packages():
        crate = args.package_dir / f"{name}-{version}.crate"
        digest = hashlib.sha256(crate.read_bytes()).hexdigest()
        expected = index_checksum(name, version, args.wait)
        if digest != expected:
            sys.exit(f"{crate.name}: SHA-256 {digest} differs from the crates.io index ({expected})")
        print(f"{crate.name}: {digest} matches the crates.io index")
        shutil.copyfile(crate, assets / crate.name)
        rows.append((name, version, digest))
        sums.append(f"{digest}  {crate.name}\n")

    body = args.body_in.read_text().rstrip()
    if START in body and END in body:
        before, rest = body.split(START, 1)
        body = (before.rstrip() + "\n\n" + rest.split(END, 1)[1].lstrip()).rstrip()
    body = f"{body}\n\n{section(rows, args.run_url)}\n" if body else f"{section(rows, args.run_url)}\n"

    (assets / "SHA256SUMS").write_text("".join(sums))
    (args.out_dir / "release-body.md").write_text(body)


if __name__ == "__main__":
    main()
