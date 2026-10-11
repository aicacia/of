#!/usr/bin/env python3
"""Static deployment contract checks; never invokes Docker or Cargo."""
import json
import os
import posixpath
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ContainerContract(unittest.TestCase):
    def test_image_launches_full_node_cli_with_overridable_commands(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("unified_server::run().await", (ROOT / "src/main.rs").read_text())
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(manifest["features"]["cli"], ["unified-server/cli"])
        self.assertRegex(dockerfile, r"cargo build --locked --release -p unified-server --features cli --bin unified-server")
        entrypoint = re.search(r"^ENTRYPOINT (.+)$", dockerfile, re.M)
        self.assertIsNotNone(entrypoint, "operators must be able to replace serve with provision")
        self.assertEqual(json.loads(entrypoint[1]), ["/app/run"])
        command = re.search(r"^CMD (.+)$", dockerfile, re.M)
        self.assertEqual(json.loads(command[1]), ["-c", "/app/config.yaml", "serve"])
        self.assertNotIn("FROM scratch", dockerfile)
        self.assertIn("libdbus-1-3", dockerfile)
        self.assertIn("ca-certificates", dockerfile)
        self.assertRegex(dockerfile, r"(?m)^USER 65532:65532$")
        self.assertNotRegex(dockerfile, r"(?m)^EXPOSE ")
        self.assertNotIn("musl", dockerfile)
        for name in ("of", "ofdb", "offs", "ofnet"):
            self.assertIn(f"COPY {name}/ /workspace/{name}/", dockerfile)
        self.assertIn("WORKDIR /workspace/of", dockerfile)
        self.assertIn("/workspace/of/target/release/unified-server /app/run", dockerfile)

    def test_parent_context_is_allowlisted_and_prunes_nested_private_state(self):
        rules = (ROOT / "Dockerfile.dockerignore").read_text().splitlines()
        rules = [rule for rule in rules if rule and not rule.startswith("#")]
        self.assertEqual(rules[:9], [
            "**", "!of/", "!of/**", "!ofdb/", "!ofdb/**",
            "!offs/", "!offs/**", "!ofnet/", "!ofnet/**",
        ])
        for name in (".git", ".worktrees", ".scratch", "target", "node_modules",
                     ".env*", "data", "unified-data", "protected-initial-password",
                     "*.pem", "*.key", "*.p12", "*.pfx", ".cargo/config.toml"):
            self.assertIn(f"**/{name}", rules[9:])
        self.assertFalse(any(rule.startswith("!") for rule in rules[9:]),
                         "later source exceptions must not reinclude private state")

    def test_manifest_path_dependencies_fit_the_four_repository_context(self):
        repositories = {"of", "ofdb", "offs", "ofnet"}
        checked = 0
        manifests = []
        for directory, children, files in os.walk(ROOT):
            children[:] = [name for name in children if not name.startswith(".")
                           and name not in {"target", "node_modules", "data", "unified-data"}]
            if "Cargo.toml" in files:
                manifests.append(Path(directory) / "Cargo.toml")
        for path in manifests:
            relative = path.relative_to(ROOT)
            manifest = tomllib.loads(path.read_text())
            tables = [manifest]
            tables.extend(manifest.get("target", {}).values())
            for table in tables:
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for dependency in table.get(section, {}).values():
                        if isinstance(dependency, dict) and "path" in dependency:
                            resolved = posixpath.normpath(
                                f"of/{relative.parent}/{dependency['path']}")
                            self.assertIn(resolved.split("/")[0], repositories, resolved)
                            checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
