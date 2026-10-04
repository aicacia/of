#!/usr/bin/env python3
import json
import subprocess
import sys

COMPOSITION_HOSTS = {"idp-unified", "unified-server", "lidp"}


def main() -> int:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            text=True,
        )
    )
    packages = {package["name"]: package for package in metadata["packages"]}
    server_names = {name for name in packages if name.endswith("-server")}
    checked_sources = server_names | (COMPOSITION_HOSTS & packages.keys())
    violations = []

    for source in sorted(checked_sources - COMPOSITION_HOSTS):
        package = packages[source]
        for dependency in package["dependencies"]:
            target = dependency["name"]
            if target in server_names:
                violations.append(f"{source} -> {target}")

    if violations:
        print("Server crates must not depend on other server crates:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print("No direct server-to-server dependency edges found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
