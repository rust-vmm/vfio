#!/usr/bin/env python3
#
# Copyright © 2026, Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#

import argparse
import re
import sys
from pathlib import Path
import subprocess

'''
tag_release.py — create annotated git tags for workspace crates from CHANGELOG.md.

Overview
--------
For each workspace member (vfio-bindings, vfio-ioctls, vfio-user):
  * reads the current version from the crate's Cargo.toml
  * extracts the matching section from the crate's CHANGELOG.md
  * creates an annotated git tag "<crate>-v<version>" using that section
    as the tag message
Tags that already exist in the local repo are skipped.

Assumptions
-----------
* Workspace layout: <repo-root>/<crate>/{Cargo.toml,CHANGELOG.md}
* CHANGELOG version headers use H1 form, e.g. "# [v0.6.2]"
* Cargo.toml has a top-level `version = "X.Y.Z"` line

Usage
-----
List probable tags for all crates (no changes to the repo):
    $ ./scripts/tag_release.py --list

List for a single crate / explicit version:
    $ ./scripts/tag_release.py -l --crate vfio-ioctls
    $ ./scripts/tag_release.py -l --version v0.5.0 --crate vfio-bindings

Create tags for all crates (skips any tag that already exists):
    $ ./scripts/tag_release.py

Create tag for a single crate:
    $ ./scripts/tag_release.py --crate vfio-ioctls

Override the version (must exist as a section in the crate's CHANGELOG.md):
    $ ./scripts/tag_release.py --version v0.6.0 --crate vfio-bindings

Push the created tags upstream (done manually, not by this script):
    $ git push origin <tag-name>
    $ git push origin --tags        # push all local tags

Remove a local tag if created by mistake:
    $ git tag -d <tag-name>

Example output
--------------
$ ./scripts/tag_release.py --crate vfio-bindings
vfio-bindings-v0.5.0

Fixed
* https://github.com/rust-vmm/vfio/pull/85 Fix file permissions

Changed
* https://github.com/rust-vmm/vfio/pull/86 Upgrade vmm sys utils to v0.14.0
* https://github.com/rust-vmm/vfio/pull/91 vfio-bindings: Regenerate bindings using new bindgen-cli
'''


def get_crate_path(crate, file):
    return Path(__file__).parent.parent / crate / file


def extract_changelog(crate, version):
    # Get the changelog file for the crate
    changelog_path = get_crate_path(crate, "CHANGELOG.md")
    with open(changelog_path, "r") as f:
        lines = f.readlines()

    # Find the changelog section for the specified version
    section_start = None
    section_end = None
    for i, line in enumerate(lines):
        if re.match(r"^# \[" + re.escape(version) + r"\]", line):
            section_start = i+1
        elif section_start is not None and re.match(r"^# \[", line):
            section_end = i
            break
    if section_start is None:
        raise RuntimeError("No changelog section found for version " + version)
    if section_end is None:
        section_end = len(lines)

    # Remove leading '#' from lines and strip whitespace
    section = [x.lstrip("#").rstrip().lstrip() for x in lines[section_start:section_end]]
    # Replace markdown links with just the url
    section = [re.sub(r"\[.*?\]\((.*?)\)", r"\1", x) for x in section]
    # Remove empty lines at start/end
    while section and not section[0].strip():
        section.pop(0)
    while section and not section[-1].strip():
        section.pop()
    return "\n".join(section)


def get_latest_version(crate):
    cargo_toml_path = get_crate_path(crate, "Cargo.toml")
    with open(cargo_toml_path, "r") as f:
        for line in f:
            m = re.match(r"^version = \"([^\"]+)\"", line)
            if m:
                return "v" + m.group(1)
    raise RuntimeError("No released version found in changelog")


def get_crates():
    root_cargo_toml = Path(__file__).parent.parent / "Cargo.toml"
    with open(root_cargo_toml, "r") as f:
        content = f.read()
    members_match = re.search(r'members\s*=\s*\[([^\]]+)\]', content)
    if not members_match:
        raise RuntimeError("No members found in root Cargo.toml")

    members_str = members_match.group(1)
    members = [m.strip().strip('"').strip("'") for m in members_str.split(",") if m.strip()]
    return members


def tag_exists(tag_name):
    ret = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag_name}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return ret.returncode == 0


def list_tags(crates, version_arg):
    for crate in crates:
        version = version_arg if version_arg else get_latest_version(crate)
        tag_name = f"{crate}-{version}"
        status = "exists" if tag_exists(tag_name) else "new"
        print(f"{tag_name}\t[{status}]")
    return 0


def main(args):
    crates = []
    if not args.crate:
        crates = get_crates()
    else:
        crates = [args.crate]

    if args.list:
        return list_tags(crates, args.version)

    for crate in crates:
        print(f"Processing crate: {crate}")
        version = args.version if args.version else get_latest_version(crate)
        tag_name = f"{crate}-{version}"
        # skip if the tag already exists in the current repo
        if tag_exists(tag_name):
            print(f"Skipping {tag_name}: tag already exists")
            continue
        changelog = extract_changelog(crate, version)
        # create the tag with changelog as the message
        ret = subprocess.run(["git", "tag", "-a", tag_name, "-m", changelog])
        if ret.returncode != 0:
            raise RuntimeError(f"Error creating tag: {tag_name}")

        print(f"Created tag: {tag_name}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create annotated git tags for workspace crates from CHANGELOG.md.\n"
                    "Reads each crate's version from Cargo.toml, extracts the matching\n"
                    "CHANGELOG.md section, and creates a tag \"<crate>-v<version>\".\n"
                    "Existing tags are skipped. See file docstring for full usage.",
        epilog="examples:\n"
        "  ./tag_release.py --list                                # preview tags for all crates\n"
        "  ./tag_release.py -l --crate vfio-ioctls                # preview one crate\n"
        "  ./tag_release.py                                       # create tags for all crates\n"
        "  ./tag_release.py --crate vfio-ioctls                   # create tag for one crate\n"
        "  ./tag_release.py --version v0.6.0 --crate vfio-bindings\n"
        "\n"
        "After creating tags, push them manually:\n"
        "  git push origin <tag-name>       # push a single tag\n"
        "  git push origin --tags           # push all local tags\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        dest="list",
        help="List probable tags (from Cargo.toml/CHANGELOG.md) without creating them",
    )
    parser.add_argument(
        "--version",
        "-v",
        type=str,
        dest="version",
        required=False,
        help="The version string, e.g. \"v0.6.0\", otherwise the current version in CARGO.toml",
    )
    parser.add_argument(
        "--crate",
        "-c",
        type=str,
        required=False,
        default=None,
        dest="crate",
        help="Generate tag for a crate (vfio-bindings, vfio-ioctls, or vfio-user)",
    )
    res = main(parser.parse_args())
    sys.exit(res)
