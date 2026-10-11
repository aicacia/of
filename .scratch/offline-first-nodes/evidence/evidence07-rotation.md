# Ticket 07 bounded local credential rotation/restart

Date: 2026-10-11. Branch: `offline-first-node07-rotation`.
Base: integration `a3edacd`.
Disposition: bounded rotation/restart acceptance passed; ticket 07 remains open.
This file is the only evidence/documentation change. Prior evidence is preserved.

## Scope and CRP

Invoked `tdd` and `ponytail`; read worktree `AGENTS.md`, shared/context glossaries,
`.scratch/offline-first-nodes/spec.md`, ticket 07, and `docs/operations.md`.
Changes: `crates/unified-server/src/local_provisioning.rs`, its tests, and the
required public read-only verification seam in
`crates/idp-server/src/provisioning.rs`. No new dependency or broad owner rewrite.
No root/map/ticket/stable-doc, GUI, image, keyring implementation, or cross-repo
source changes; no full Cargo hack/CRAP. Existing operations prose describing
completed exact captured relationships is not updated by this bounded slice.

Complexity: moderate, one completed/incomplete branch and owner validation.
Risk: high, startup credential/trust boundary; config is not authorization.
Priority: high, authorized same-ID rotation otherwise makes completed restart
impossible. No numeric CRAP/coverage score is claimed.

## Source trace and fix

- `LocalProvisioner::open_runtime` treats a present journal as authoritative and
  delegates through `open`/`read` to `build_runtime`; the absent-journal existing
  trusted-host path remains unchanged.
- Baseline `read` always verifies configured relationship secrets against the
  journal's original Argon2 verifiers. After public same-ID rotation, the new
  secret fails this historical comparison.
- The old secret passes historical comparison but completed `build_runtime`
  replays `prepare_setup_client_slots` and
  `ensure_setup_infrastructure_client`. The latter follows captured key/setup
  producers and `OAuth2Service::ensure_infrastructure_client`, which compares
  the secret against the current local Client hash, rejecting the old secret.
- Baseline completed startup also calls `verify_prepared_node_signer`, whose
  implementation writes preparation inventory. It is not a read-only current
  trust check.
- Incomplete continuation still verifies original secrets, exact intent,
  protected password and captured owner operations. No verifier migration,
  journal deletion/rewrite, new provisioning attempt or changed identity is
  introduced. Explicit provision against a completed journal performs current
  existing-only runtime validation/shutdown, not incomplete producers.
- Completed startup retains exact issuer/key namespace/password policy, Client
  IDs/relationship metadata, context roots and configured signer binding.
  Retained endpoint identity is checked before constructing owners/runtime.
  Current trusted `verify_node_signer` must match the captured public signer;
  preparation verification/slot preparation/Client ensure are removed here.
- `OwnerProvisioner::verify_infrastructure_client` reads the active local Client
  and its actual Application, compares full normalized registration metadata,
  then uses the existing OAuth Client-credentials issuance path with the
  configured local trusted signer. This checks current secret hash, Client
  activity/expiry, grant/auth method, requested audience/scopes, active Client
  principal key and local Node signing capability. The generated token is
  discarded, not persisted/logged/returned. The source path creates no Client,
  signing key or captured inventory and supplies no repair fallback.
- Completed startup verifies all four configured relationships, retained
  context databases/Storage directories, and current public readiness. Missing
  or changed evidence refuses; no privileges are widened to accommodate rollout.
  Existing endpoint comparison after runtime construction also remains.

The agreed test seams are authorized IdP registration HTTP operations,
`LocalProvisioner::open_runtime` (the CLI startup decision), and the real public
Storage `IdpClient` HTTP boundary. The fixture registers its login Client through
public `OAuth2Service::register_client` using normal owner service construction;
no direct repository mutation or SQL seeding is used for that registration.

## Executed HTTP acceptance

`local_provisioning_authorized_rotation_reopens_completed_host`:

1. Explicitly provision a real isolated host with IdP/Management/Storage stores,
   captured Node signer and endpoint. Use the existing narrow mock secure
   provider; deliver/read the replacement test secret through that provider.
2. Authenticate the actual initial administrator User via password login and
   token exchange for the IdP service audience. Retain the provisioned explicit
   installation infrastructure Client read/update/delete permissions; do not
   add roles, evaluator privilege, or permission bypasses.
3. GET the existing Storage-to-IdP registration using that User bearer. PUT the
   full registration with the same Client ID and only its supplied secret
   changed. Verify scopes/audiences preserved, old secret rejected and new
   secret issuance successful through the actual listener.
4. Show an unregistered config-only new secret is insufficient. An authorized
   audience-widening control causes completed startup denial; restore exact
   metadata through the authorized API, not through setup replay.
5. Shutdown the host. Old config fails restart. Changed issuer, signer binding,
   retained endpoint key, and each context/endpoint root fail without creating
   replacement directories. Restore only the isolated test endpoint bytes.
6. Reopen twice through `LocalProvisioner::open_runtime` with the current secret,
   retaining endpoint identity. Serve each runtime and make an actual public
   Storage `IdpClient::approved_storage_endpoints` call to IdP; the local endpoint
   is returned. Shutdown each runtime and drop its provisioning lock guard.
7. Check journal bytes and modification time, owner setup inventory bytes and
   secure-provider contents unchanged by restart. No private material is
   reproduced and no historical secret/verifier is rewritten.
8. Independently DELETE the relationship using the authorized User bearer on
   the second reopened listener. Its previously issued original bearer now
   receives HTTP 401 from the device-endpoint API; current-secret token issuance
   fails. Subsequent completed reopen refuses instead of recreating registration.

The separate new incomplete-intent control rejects a changed relationship
secret, accepts the original exact secret and leaves journal/private-production
state unchanged. Existing continuation/missing-state controls remain intact.

## Commands and red/green chronology

All Cargo attempts used this literal common prefix and suffix:

```sh
systemd-run --user --wait --pipe --unit=UNIT --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-rotation -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::local_provisioning_authorized_rotation_reopens_completed_host -- --exact --test-threads=1
```

`UNIT` denotes the exact literal unit name in the table, not an executed shell
variable. Tool bounds were 910000 ms. No profile/rustflags change, network fetch,
cache deletion, or authorization/test HTTP timeout increase was made. The HTTP
client and host shutdown bounds remain 10 seconds. Disk check before compilation
reported 397 GiB available on the target filesystem.

| Unit | Invocation ID | Result |
| --- | --- | --- |
| `of-node07-rotation-red` | `9902fe8821544deca498e2bb2c3065a6` | Executed behavioral **red**, exit 101: compiled in 8m36s; test reached completed new-secret reopen and failed with `input credential differs from retained local intent`, 52.45s. Authorized rotation and old/new token checks had succeeded. |
| `of-node07-rotation-green` | `54946ef08f294d22ad044b628e764192` | Compile-only failure, exit 101, 4.017s: attempted import of non-exported `idp_service::verify_password`. Not a behavioral red. Corrected by using existing public OAuth credential validation, without adding an export/dependency. |
| `of-node07-rotation-green-public-auth` | `210776511b15414e9407babaefaec182` | Exit 0, regression passed, test 98.38s; compile 2m50s. |
| `of-node07-rotation-controls-build` | `b3bf8c20865f44a5aa90bed5ab0cdd42` | Exit 0, expanded controls passed, test 125.44s; compile 22.12s. |
| `of-node07-rotation-final-build` | `c8c73b0b02514f62a478389e1ceabb3b` | Exit 0, final source passed, test 145.60s; compile 1m50s. |

Earlier current-artifact control runs also passed (not substituted for final
source): incomplete 0.02s, continuation 30.50s, absent journal 173.40s, lost
Management 22.81s, lost Storage 37.51s, exact host 194.77s. Units respectively
`of-node07-rotation-incomplete-current`, `-continuation-current`,
`-existing-current`, `-lost-management-current`, `-lost-storage-current`,
`-exact-host-current`.

## Final artifact controls: seven passed, zero failed

Artifact: `/home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3`.
SHA-256: `0c3d654fdfbcb70beb589117a4d4562e792f8dd81d605d600ac8a98828f706e5`.

Each final control used this exact command shape with literal table substitutions:

```sh
systemd-run --user --wait --pipe --unit=UNIT --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-rotation -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=CAP env RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3 local_provisioning_tests::TEST --exact --test-threads=1
```

| Unit | CAP seconds | TEST | Test seconds / exit |
| --- | ---: | --- | --- |
| `of-node07-rotation-final-http-artifact` | 300 | `local_provisioning_authorized_rotation_reopens_completed_host` | 121.79 / 0 |
| `of-node07-rotation-final-incomplete` | 300 | `local_provisioning_incomplete_rotation_requires_original_exact_secret` | 0.02 / 0 |
| `of-node07-rotation-final-continuation` | 450 | `local_provisioning_continues_retained_attempt_and_refuses_changed_credentials` | 31.66 / 0 |
| `of-node07-rotation-final-existing` | 450 | `local_provisioning_existing_cli_host_without_journal_starts_and_reopens` | 194.89 / 0 |
| `of-node07-rotation-final-lost-management` | 300 | `local_provisioning_lost_management_after_late_failure_denies_without_recreation` | 20.25 / 0 |
| `of-node07-rotation-final-lost-storage` | 300 | `local_provisioning_lost_storage_after_runtime_initialization_denies_without_recreation` | 31.89 / 0 |
| `of-node07-rotation-final-exact-host` | 300 | `local_provisioning_creates_exact_host_and_reopens_offline` | 171.06 / 0 |

Controls were single-threaded, serial and bounded; grouped tool invocations used
910000 ms, standalone final HTTP artifact used 310000 ms. No timeout/OOM was
reported. Systemd printed very small memory peaks; these are not presented as
credible compiler/process peak-memory measurements or platform qualification.

Focused Clippy passed, exit 0, 1m46.219s under the same 4G/zero-swap/900s control:

```sh
systemd-run --user --wait --pipe --unit=of-node07-rotation-clippy --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-rotation -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_JOBS=1 cargo clippy --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib --tests --no-deps
rustfmt --edition 2024 --check crates/idp-server/src/provisioning.rs crates/unified-server/src/local_provisioning.rs crates/unified-server/src/local_provisioning_tests.rs
git --no-pager diff --check
```

Clippy is not warning-clean: existing fixture default-field reassignment,
collapsible runtime configuration checks and non-Drop interruption-fixture drops
are reported (unified lib-test nine warnings, lib one duplicate). No unrelated
lint fix is included. Formatting and diff checks pass.

## Delivery boundary and remaining gaps

Commit this finished four-file slice and fast-forward it into
`offline-first-nodes-integration`; final delivery response records confirmed
revisions. Integration started at `a3edacd`; its ten pre-existing Storage build
outputs/shims were fingerprinted before merge and must remain byte-exact.

This proves local same-ID Storage-to-IdP secret rotation, owner-authorized HTTP
mutation, bounded completed CLI-seam restart/retry, real consuming owner calls,
exact incomplete continuation and locally learned deletion denial. It does not
qualify peer propagation, partition timing, interrupted multi-consumer rollout,
actual OS/unattended secure providers, Windows ACLs, CLI OS-process restart,
images/TLS/desktop/GUI, same-Node backup/recovery, or all ticket-07 acceptance.
The fixture provider is a narrow mock, not real OS keyring success. This is not
a full feature-powerset or CRAP run. No reset, migration, central dependency,
privilege widening or automatic missing-state recovery is supplied.

## Independent review follow-up: assertion disclosure and limits

The independent review identified a test-only disclosure in the added provider
snapshot `assert_eq!`: a mismatch would print raw private material and Client
secrets. Replaced only that assertion with boolean equality and a descriptive
non-secret message, matching the baseline pattern. Inspected all assertions
added by `8f50fd3`: the remaining operand-dumping comparisons contain HTTP
statuses, scope/audience metadata, public endpoint identity, journal public
intent/one-way verifiers, owner preparation inventory, or timestamps, not raw
secrets/private keys/tokens. No other added raw-secret/token operand dump was
found. Production code, permissions and relationship scopes remain unchanged.

Acceptance is **serial Storage-to-IdP rotation/restart only**, not a concurrent
rollout or qualification of every relationship. Owner metadata comparison and
OAuth issuance are separate operations, **not an atomic snapshot guarantee**
against concurrent owner changes. The verification seam is read-only in the
sense of **no credential provisioning or repair**, not a guarantee of zero host
DB writes during startup/runtime. Journal/provider/inventory assertions establish
the named retained-state observations, not universal database immutability.

This follow-up stays on `offline-first-node07-rotation` for the merger. Do not
update root integration again; the earlier delivery instructions above describe
the original slice, not authorization to merge this follow-up.

### Follow-up validation

Only the current-source authorized rotation regression was built and executed:

```sh
systemd-run --user --wait --pipe --unit=of-node07-rotation-review-assertion --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-rotation -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::local_provisioning_authorized_rotation_reopens_completed_host -- --exact --test-threads=1
```

Tool timeout: 910000 ms. Invocation:
`e67399a453be44cbbd82f3b1daa0f3f0`. Exit 0; compilation 1m51s;
**1 passed / 0 failed / 70 filtered**, test 128.03s; service runtime 3m59.577s.
No timeout/OOM reported. `rustfmt --edition 2024 --check
crates/unified-server/src/local_provisioning_tests.rs` and
`git --no-pager diff --check` also passed. No all-seven rerun, Clippy, full hack,
CRAP, root integration update or root worktree edit was performed for this
assertion-only follow-up. The original artifact hash/results above describe the
original slice, not this rebuilt assertion-follow-up artifact.
