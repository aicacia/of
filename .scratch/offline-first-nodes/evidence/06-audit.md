# Ticket 06 documentation and artifact audit — 2026-10-11

Worktree: `of/.worktrees/ticket06-docs`; branch: `offline-first-ticket06-docs`; base: `2e67ed5` (`offline-first-nodes-integration` at audit start).

## Scope and disposition

Completed the documentation/static-artifact audit slice, **not all ticket-06 acceptance**. Read original root [spec](../spec.md), [ticket06](../issues/06-api-clients-and-obsolete-artifacts.md), [map/current checkpoint](../map.md), [generator safety](06-generator-safety.md), [obsolete-contract checkpoint](06-obsolete-contracts.md) and [ticket04 native checkpoint](04-native-acceptance/checkpoint.md). Followed `docs/agents/domain.md`; loaded ponytail/domain-modeling; no ADR.

Complexity: bounded source-to-document reconciliation. Risk: deleting valid signer/CRDT/security fixtures or presenting scoped backend evidence as accepted GUI/full-Node behavior. Priority: remove misleading active contracts and record owner handoffs without widening permissions. No new dependencies.

Ownership: only stable system/context docs, glossary/map and this worktree evidence changed. No Rust/source/config/generated/client/frontend/generator/fixture/Docker edits. Active artifact deletion is already supplied by `6ddd54d`/`6c6b70f`; no further owned static artifact was proven obsolete. Generated stale files are reported to their owner, never hand-edited. Historical evidence is retained unchanged.

## Coverage and findings

| Audit category                                | Finding and disposition                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Designated authority/privileged replica roles | Current Node design rejects those roles. OAuth config explicitly rejects retired `role`; test role strings are negative fixtures. RBAC authority, OIDC `authority` URL vocabulary and local one-shot production authority are not a designated writer topology. No active topology config found after prior deletion.                                                                                                                                                                    |
| Storage-only join / password-grant join       | Current `NodeJoinRequest` pins approving endpoint and binds independent public signer/Installation/member; no password/grant role input. `storage-only` occurs in a rejected unknown-field fixture and a service-scope denial message, not a join option. Ordinary OAuth password sign-in remains valid.                                                                                                                                                                                 |
| Freshness30s gates                            | No active trust-freshness lease found in the scoped current sources/config. 30-second matches are test/harness waits, native-fetch request timeout example and OIDC access-token renewal margin. Local signer/token lifetime checks remain required. No timer or denial test blindly removed.                                                                                                                                                                                            |
| Obsolete setup/signing routes                 | `/setup/bootstrap` is absent from source/OpenAPI inventory; the regression asserts absence. Generated IdP still contains `SuperRoutesSetupApi`, `SetupBootstrapRequest` and exports at base: stale generation-owner handoff. Active native `GET /lidp/setup/status`, `SetupStage`/`SetupStatus`, IPC and owner setup remain. No replacement undocumented HTTP join/readiness route invented.                                                                                             |
| Current signer API                            | Keep `/replica-signers` POST and member PUT/DELETE: handlers bind StandardAuthorization to exact Installation `idp.replica_signers.enroll`/`.rotate`/`.revoke`. `DbReplicaSignerRepo`, schema names and permission spelling are legitimate current API/persistence vocabulary, not privileged replicas.                                                                                                                                                                                  |
| CRDT/source/replica flows                     | Keep `replica` persistence feature/schema, public SQL/KV `SyncRole::Initiator`/`Responder`, directional source SendOnly/receiver ReceiveOnly, conflict and native-reopen tests. They describe data exchange, not Node privileges.                                                                                                                                                                                                                                                        |
| Remote-only authorization                     | Unified supplies local IdP listener relationship and local Management persistent evaluator/replication authorizer. Management's authenticated local HTTP introspection/Device lookup is not remote-only authorization. Missing local evidence/context denies. Standalone configurable URLs alone do not prove completed equal-Node composition. Corrected Storage API prose that still treated local owner calls as an unresolved remote cutover.                                        |
| Alternate actor headers                       | `x-actor-subject` appears in two real HTTP impersonation-denial fixtures (401/403), not an accepted caller override. Management evaluator binds same User or the separately registered exact-scope evaluator Client. Selection uses typed `storageAccessToken`, not `X-Storage-Authorization`. Preserve negative tests.                                                                                                                                                                  |
| Removed credentials                           | SQL removed secret/enrollment fields from public `clients`/`credentials`/`devices`. Matches remain in active `local_credential_secrets`, `local_client_credentials`, `local_device_enrollments`, schema-rejection checks and historical/negative tests. These are valid local-only persistence, not obsolete shared credential contracts. No raw credentials captured.                                                                                                                   |
| Internal persistence dependencies             | Every direct `ofdb` manifest edge is `ofdb-sql`/`ofdb-kv`, including dev edges. Runtime imports use public facades; backend feature names/transitive owner crates and `.redb` filenames are legitimate. No internal consumer edge found, no Cargo changes.                                                                                                                                                                                                                               |
| Static config/spec/deployment artifacts       | Only active tracked YAML config is `config/unified/example.yaml`, with separate roots, four Client-ID placeholders and exact audiences, no populated secrets or role. No saved OpenAPI/Swagger JSON/YAML snapshot is tracked; source OpenAPI and generated clients are owner workflows. Keep SQL schema, OpenAPI generator version config and CI/instruction files. Docker retained `idp-unified` defaults/`/app/config.yaml` expectation is ticket07 deployment follow-up, not changed. |
| Prefixes and owner identity                   | Unified assigns `/idp`, `/management`, `/storage`; owner routers/clients have their own path normalization. `idp-management` is Management's Application URI/audience, not prefix. Source inspection is not a live complete-spec or double-prefix HTTP test. Owner caller agent owns actual probe/caller qualification.                                                                                                                                                                  |
| Setup/readiness/acceptance                    | Corrected obsolete IdP claim that no production signer preparation exists. Owner local provisioning/join and current public readiness are present; receipt/status/listener/completion marker alone is insufficient. **04 GUI authorized approval, joining-Node completion and two-profile offline restart remain unverified**. No full-spec/ticket acceptance promoted.                                                                                                                  |

## Documentation changes

- [System API](../../../docs/api.md): owner route/permission boundaries, exact prefix distinction, active setup probe vs persistent readiness, trusted-peer join and generator-source preservation.
- [System security](../../../docs/security.md): subject/signer/endpoint/actor separation, legitimate historical API names, local trust, learned denial, credential separation and facade ownership.
- [System design](../../../docs/design.md) and [operations](../../../docs/operations.md): link current contracts and explicitly preserve 04/07/08 limits, including unchanged Docker follow-up.
- [IdP local security](../../../crates/idp-service/docs/local-security.md): replace stale no-production-signer blocker with delivered source seams and unverified native acceptance.
- [Storage API](../../../crates/storage-service/docs/api.md): distinguish locally hosted authenticated owner calls from central authorization; preserve restriction/selection/transfer/Residency semantics. [Storage security](../../../crates/storage-service/docs/security.md) now links scoped acceptance and owner contracts rather than asserting all generic owner work remains blocked.
- [Public persistence](../../../docs/public-persistence.md): remove superseded current 02/03/05-pending claims, link scoped Answers/current map and label recorded command sections historical. No historical evidence files or test results rewritten into acceptance.
- [Glossary map](../../../GLOSSARY-MAP.md): stable API/security links; [Storage glossary](../../../crates/storage-service/GLOSSARY.md) Residency definition now includes resource or path, without implementation details. Other context/shared definitions remain valid.

## Reports to other owners (no edits)

- **Client generation owner:** regenerate complete current IdP/Management/Storage contracts through the safe endpoint workflow; base IdP generated bootstrap API/model/exports are stale. This audit does not qualify live generation, source-preservation negative tests, TypeScript, current generated model completeness or application imports. Prior evidence is linked above; current generation results must come from that owner.
- **Caller/frontend owner:** verify once-only service base/prefix joins, direct IdP administration, and setup-stage probes vs current persistent readiness. No source/UI changes or Svelte analysis in this audit. Full 04 approval/completion/restart remains explicitly unverified.
- **Runtime/deployment owner (07):** Docker defaults still name `idp-unified` and launch `/app/config.yaml`; prior topology YAML removal does not qualify image/runtime configuration. No Docker/build/run changes here.
- **ofdb:** read-only scoped docs/manifest search found no obsolete `of` topology artifacts. `docs/storage-sync-directional-sessions.md`, `docs/storage-sync-table-scope.md`, `docs/storage-sync-candidate-validation.md`, `docs/design.md`, `docs/goal.md` explicitly separate generic execution/direction from freshness/domain authorization. Internal owner manifests are legitimate, not forbidden `of` consumer edges. No owner validation rerun or edits.
- **offs:** read-only `docs/metadata.md`/`docs/execution.md` reject freshness leases and leave domain composition in `of`; per-path Residency and revision checks are legitimate. No obsolete join/auth artifact found in scoped docs/manifests. No owner validation rerun or edits.
- **ofnet:** scoped docs/manifests have no matching obsolete domain topology contracts; Endpoint/Peer/Mesh/Broadcast/Direct Message/Byte Stream glossary remains distinct from Installation/Device authority. No owner validation rerun or edits.

## Exact audit commands

Unless specified, working directory is `of/.worktrees/ticket06-docs`. Discovery/read commands were bounded to current `docs`, context docs/glossaries, `config`, source `crates`/`src`/`apps`, `packages`, `scripts`, root manifests and explicit deployment files. Searches do not traverse `.worktrees`, `target`, historical `.scratch`, or dependency installs. Original `.scratch` requirements/evidence were read explicitly, not treated as active source hits.

```sh
git --no-optional-locks status --short
git --no-pager log -5 --oneline
git --no-pager branch --show-current
rg -n -i 'authority|replica|freshness|storage.only|password.grant|setup/bootstrap|setup/join|x-.*(actor|subject|storage|user)|remote.*(authoriz|introspect)|primary|secondary' docs crates/*/docs crates/*/GLOSSARY.md config README.md GLOSSARY*.md
rg -n -i 'freshness|fresh_until|last_sync|30_000|from_secs\(30\)|authority_url|authorityUrl|storage.only|privileged.replica|x-actor|x-user|x-subject|x-storage-authorization|setup/bootstrap|setup/join' crates src apps packages scripts config --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/*.map'
rg -n 'ofdb' Cargo.toml crates/*/Cargo.toml
rg -n 'secret_hash|client_secret_hash|enrollment_code_hash|enrollment_expires_at|pairing_accepting_public_key' crates/idp-model/replica_migrations packages/idp-client/src/models --glob '*.sql' --glob '*.ts'
git --no-pager ls-files config .github '*openapi*' '*swagger*' '*spec.json' '*spec.yaml' '*.sql' Dockerfile .dockerignore
rg -n 'role|password|grant|peer|signer' crates/idp-server/src/node_join.rs
rg -n 'SyncRole::|SyncRole|source|replica' crates/storage-server/src/database_protocol.rs crates/storage-server/src/database_transport.rs
rg -n 'prepare_node_signer|prepare_local_node|node_public_ready|node_join_public_ready' apps/app/src-tauri/src crates/unified-server/src/local_provisioning.rs --glob '*.rs'
rg -n 'local_credential_secrets|local_client_credentials|local_device_enrollments' crates/idp-service/src --glob '*.rs'
```

Matched categories were classified in the table, not interpreted as failures by substring. Read actual signer handlers, actor binding, header-denial assertions, local introspection, host prefix/readiness and native probe/setup implementations. Initial exploratory commands included nonexistent guessed subpaths and a mistaken worktree-relative sibling path; those emitted file-not-found errors and establish nothing. Corrected source paths and independent owner-root commands above/below supplied the audit evidence. No failures hidden as successful scans.

In each of `ofdb`, `offs`, `ofnet` independently:

```sh
rg -n -i 'freshness|authority_url|replica_role|storage.only|password.grant|setup/bootstrap|x-actor-subject' docs crates --glob '*.md' --glob 'Cargo.toml' --glob '!**/target/**'
cat GLOSSARY.md
```

Results: ofdb/offs matches only the legitimate policy disclaimers described above; ofnet no matching docs/manifests. Owner glossary reads were terminology checks, not whole-owner source audits.

## Targeted validation and limits

No Cargo, GUI, install, endpoint fetch/generation, full powerset/CRAP, broad workspace test or Docker invocation. Whitespace: `git --no-pager diff --check` passed. The exact targeted standard-library link check below checks local paths and Markdown headings, resolving absent historical tracker/external links in the original workspace without rewriting them. It does not validate remote URLs, arbitrary Markdown syntax or every historical evidence link. First pre-evidence run found only four links to this not-yet-written evidence file; final rerun passed: **15 targeted documents, 107 links, zero failures, 15 original-workspace/external resolutions**. Separate audit-evidence path check passed **16 local links, zero failures**. The suspected context-link depth issue was not confirmed: existing context links are correct, so none were changed merely on that inference.

```sh
python3 - <<'PY'
from pathlib import Path
import re
root=Path.cwd()
original=Path('/home/nathan/code/rust/aicacia/of')
files=[root/'GLOSSARY-MAP.md',root/'GLOSSARY.md',*sorted((root/'docs').glob('*.md')),*sorted((root/'crates').glob('*-service/GLOSSARY.md')),*sorted((root/'crates').glob('*-service/docs/*.md'))]
checked=0
missing=[]
fallback=[]
for file in files:
    for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',file.read_text()):
        if re.match(r'[a-z]+:',link): continue
        path,_,anchor=link.partition('#')
        dest=(file.parent/path).resolve() if path else file
        if not dest.exists():
            logical=(original/file.relative_to(root).parent/path).resolve() if path else original/file.relative_to(root)
            if logical.exists():
                dest=logical
                fallback.append((str(file.relative_to(root)),link))
            else:
                missing.append((str(file.relative_to(root)),link,'missing path'))
                continue
        if anchor and dest.suffix=='.md':
            headings=[]
            for heading in re.findall(r'^#{1,6}\s+(.+)$',dest.read_text(),re.M):
                slug=re.sub(r'[^\w\- ]','',heading.lower()).replace(' ','-')
                headings.append(slug)
            if anchor not in headings: missing.append((str(file.relative_to(root)),link,'missing heading'))
        checked+=1
print(f'{len(files)} targeted documents; {checked} links checked; {len(missing)} failures; {len(fallback)} original-workspace/external resolutions')
for item in missing: print(item)
raise SystemExit(bool(missing))
PY
git --no-pager diff --check
```

Additional exact evidence-link check (working directory unchanged):

````sh
python3 - <<'PY'
from pathlib import Path
import re
text=Path('.scratch/offline-first-nodes/evidence/06-audit.md').read_text()
code=text.split("python3 - <<'PY'\n",1)[1].split('\nPY\n',1)[0]
try: exec(compile(code,'06-audit-link-check','exec'))
except SystemExit as result:
    if result.code: raise
file=Path('.scratch/offline-first-nodes/evidence/06-audit.md').resolve()
checked=0
missing=[]
for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',re.sub(r'```.*?```','',text,flags=re.S)):
    path,_,anchor=link.partition('#')
    dest=(file.parent/path).resolve()
    if not dest.exists(): dest=(original/file.relative_to(root).parent/path).resolve()
    if not dest.exists(): missing.append(link)
    checked+=1
print(f'Audit evidence: {checked} local paths checked; {len(missing)} failures')
for link in missing: print(link)
raise SystemExit(bool(missing))
PY
````

Integration-tip consumption completed before commit:

```sh
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --ff-only offline-first-nodes-integration
# Already up to date at 2e67ed5.
```

Original root had only pre-existing storage-client generated output/shim changes and retained worktrees/native target; no owned-document dirt. No reset/stash/clean, source override, profile/keyring or shared-target cleanup. Evidence is force-added from this worktree, not an edit of historical root evidence.

Ticket06 stays claimed until generation/caller owners provide remaining evidence; ticket04 dependency/qualification is not waived by completion of this audit slice.
