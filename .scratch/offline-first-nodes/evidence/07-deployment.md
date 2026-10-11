# Ticket 07: bounded deployment slice — 2026-10-11

Branch/worktree: `offline-first-node07-deployment`, `of/.worktrees/node07-deployment`.
Base: `fc74d950b4a8f64ebd806c7422982bbc89d3a6d7` (also the local integration tip at implementation time).
Disposition: recipe/static-check/documentation delivery only. **Ticket 07 remains open; no acceptance checkbox or ticket/map was edited.**

## Scope, assessment and diagnosis

Read this worktree's `AGENTS.md`, `.scratch/offline-first-nodes/spec.md`, `issues/07-node-operations-and-runtime-lifecycle.md`, `docs/operations.md` and shared glossary; invoked `tdd` and `ponytail`. The user-specified deployment seams are image build/launch configuration and build-context tests. Complexity: low for a native two-stage recipe/static checks; operational risk: high for secure provider availability, listener/TLS exposure and identity persistence. Priority: remove misleading image assumptions without claiming runtime/deployment acceptance. No new runtime API, dependency, deployment role or provider fallback is justified.

Actual source inspection, not inference from names:

- Root `src/main.rs` invokes `unified_server::run().await`; root `cli` forwards `unified-server/cli`. The old root binary already composes a full Node. Selecting explicit `unified-server` is clarity, **not** a fix for alleged IdP-only forwarding.
- `crates/unified-server/src/cli.rs` exposes `provision` and existing-only `serve`; config loads four documented secret environment variables, not generic Docker-secret file references.
- `runtime.rs::build_on_listener` and `local_provisioning.rs` reject non-loopback addresses. Bridge port publication and `EXPOSE` cannot expose container loopback; changing `--host` to `0.0.0.0` is not a supported solution. External access requires a TLS proxy sharing reachability to the loopback listener.
- `crates/idp-service/src/repo/private_key_keyring_repo.rs::set_credential_store` selects D-Bus Secret Service on Linux without `headless`; the default build requires D-Bus libraries and an accessible authenticated provider, not merely a mounted data directory. The kernel-keyutils alternative was not enabled or assumed persistent. No provider was queried, unlocked, reset or modified.
- Manifests refer to sibling `ofdb`, `offs`, `ofnet` paths. A workspace-parent build context is required. An `of/.dockerignore` scoped as though `of/` were the context root does not protect that parent context.
- The former scratch/musl recipe and Cargo-chef default-feature cook do not supply or qualify this provider/deployment boundary. No actual image/linker failure was reproduced: these are source/recipe blockers, not observed build failures.

## Changes

- `Dockerfile`: replace chef/musl/scratch/cross-target fallback with native GNU/Linux Rust/Debian stages, locked explicit `unified-server` CLI build, sibling source layout, build-time D-Bus headers/pkg-config, runtime D-Bus/CA certificates, non-root numeric user, overridable entrypoint, existing-only default serve. No embedded config/credentials or advertised plaintext port.
- `Dockerfile.dockerignore`: Dockerfile-specific workspace-parent allowlist for four repositories; subsequently exclude nested worktrees/Git/tracker/build output, node modules, dotenv, conventional data/password/key paths and host Cargo config. This is not a secret scanner; operator state belongs outside source trees.
- `scripts/test_container.py`: three Python stdlib static contract checks, with directory pruning and no Cargo/Docker subprocess. Check full-Node CLI selection/entrypoint/runtime prerequisites, ordered context exclusions, and declared local manifest dependency paths fitting the four-repository layout. Does not read/validate sibling source contents or implement Docker's pattern engine.
- `docs/operations.md`: correct the old image audit warning; describe prospective staged-context build and Linux host/shared-network TLS-proxy deployment, protected config/input, persistent parent/journal/owner roots, same-identity Secret Service requirements/security exposure, four service secrets, explicit fresh/exact continuation/default serve and unqualified acceptance gaps.

## Exact checks and results

All commands ran in this worktree unless noted. Python is the host stdlib Python 3.12 (traceback path); `-B` prevents bytecode artifacts. Checks were bounded to 2–30 seconds per invocation; no timed-out command is counted as passing.

1. `python3 -B scripts/test_container.py` after writing the first tracer check against the original Dockerfile: **exit 1**, one failure (missing explicit locked `unified-server` build). After replacing the recipe: **exit 0**, one test passed, 0.001s.
2. Same command after adding the context/dependency checks, before creating the Dockerfile-specific ignore file: **exit 1**, two checks passed and one `FileNotFoundError` for `Dockerfile.dockerignore`. After adding the ignore file: **exit 0**, three tests passed, 0.017s.
3. Same command after pruning the manifest traversal and final documentation clarification: **exit 0**, three tests passed, 0.013s.
4. `git --no-pager diff --check`: **exit 0**, no whitespace errors.
5. `git check-ignore -v .scratch/offline-first-nodes/evidence/07-deployment.md`: `.gitignore:2:/.scratch` matches; force-add is required **only for this evidence file**, not its siblings or tracker.
6. `git --no-pager log -1 --format='%H %s' offline-first-nodes-integration`: local tip `fc74d950b4a8f64ebd806c7422982bbc89d3a6d7`, `Record final cleanup and ignore auxiliary worktrees`.
7. Bounded `shutil.disk_usage('.')` static capacity check: total 936.73 GiB, used 488.54 GiB, free 400.54 GiB. Free disk is not permission to build: user reports 23/30 GiB RAM used and full swap. No cleanup/prune/cache deletion was performed.

No Docker build/pull/run, Cargo build/test/metadata, full hack/CRAP, GUI, live proxy, provider reset, cross-repository write or root worktree change was performed. Commit/merge hooks are disabled for these operations to prevent implicit forbidden build/test/provider commands; static checks are run explicitly. Existing worktrees and root user dirt remain outside this slice.

## Remaining acceptance gaps

Not qualified: Rust 1.99 image tag/toolchain availability; locked dependency resolution/actual native linkage; Docker engine context filtering; real built image/non-root permissions; authenticated unattended D-Bus provider persistence across process/container/logout/host restart; TLS/proxy routing and certificate validation; Iroh/firewall connectivity; offline completed-Node restart; same-Node protected backup/recovery and no signer cloning. Host networking is a Linux deployment option, not a Docker Desktop or Windows guarantee. No generic secret-file adapter, ready health probe, peer join/reset/rotation command, transparent multihop sync, role compatibility or fallback is invented.

Other ticket-07 lifecycle/shared-endpoint/admission/allowlist/shutdown, Windows ACL, authorized rotation/revocation rollout, and current-format recovery acceptance remain with their owners. Ticket04 and full07/08 completion are not advanced by these static checks.

## Commit/integration closure

Selected exactly the five files listed above, with `git add -f` applied only to this ignored evidence path; the ticket, spec, map, runtime, config and Cargo manifests/lockfile are unchanged. Committed with message `Document and constrain full-Node container deployment recipe` (initial commit `59b30f1`, subsequently amended only to record closure). `GIT_EDITOR=true git -c core.hooksPath=/dev/null merge offline-first-nodes-integration` returned **Already up to date**: the local integration tip remained `fc74d950b4a8f64ebd806c7422982bbc89d3a6d7`. No remote fetch/pull or integration-branch write was performed. Git reported automatic background packing on commit; no explicit prune/GC/cache cleanup was requested or run.

Post-commit `python3 -B scripts/test_container.py`: **exit 0**, three tests passed, 0.014s. `git --no-pager diff HEAD --check`: **exit 0**. `git --no-optional-locks status --short --branch`: clean `offline-first-node07-deployment`. `git --no-pager show --format= --name-only HEAD` listed exactly the five slice files. `git --no-pager diff fc74d95 HEAD -- .scratch/offline-first-nodes/spec.md .scratch/offline-first-nodes/map.md .scratch/offline-first-nodes/issues/07-node-operations-and-runtime-lifecycle.md crates src config Cargo.toml Cargo.lock`: empty. Final evidence-only amend and integration-tip recheck do not change the tested recipe or source scope.
