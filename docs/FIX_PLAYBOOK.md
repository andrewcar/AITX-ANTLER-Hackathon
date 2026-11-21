# Fix playbook

One entry per check the swarm can confirm. Each entry says what the finding means,
how the swarm confirmed it (always non-destructive), and how to fix it.

## MONAI Label: datastore path traversal / arbitrary file write (CVE-2026-133968)

**Finding title:** `version appears vulnerable (unconfirmed): MONAI Label (<version | version hidden>) with auth disabled, datastore arbitrary file write (CVE-2026-133968)` (critical),
`version appears vulnerable (unconfirmed): MONAI Label with auth enabled, datastore arbitrary file write for any ANNOTATOR (CVE-2026-133968)` (high), or
`MONAI Label <version> exposed without auth; confirm the build includes PR #1915 (CVE-2026-133968)` (info).
**Check id:** `monai-label` (agent: `misconfig`).

**What it is.** MONAI Label's `PUT /datastore/image` takes a caller-controlled `image` query
parameter and uses it as the image id without validation. `LocalDatastore.add_image()` joins
that id onto the datastore directory and `shutil.copy()`s the upload there, so an id such as
`../../../tmp/x` writes the upload anywhere the server user can write. `PUT /datastore/label`
(`save_label`) has the same flaw. That is arbitrary file write, and in practice remote code
execution. GHSA-qc22-rmgc-vg94 (published 2026-11-18) rates it CVSS 9.8, CWE-22. Auth is off by
default (`MONAI_LABEL_AUTH_ENABLE=False`), so any network client can exploit it; with auth on,
the ANNOTATOR role is enough. Every released version is affected, through 0.8.5 (the newest
release, October 2023). **No fixed release exists yet.** The fix is merged in source as PR #1915
("fix: confine datastore write paths", 2026-10-19) and ships in the next release.

It is exploited in the wild. Amazon Threat Intelligence reports that a China-nexus actor's
Cairn autonomous AI pen-test agents found the bug on their own and got root on a university
server: they planted a Python startup file, then triggered a training job so the server
loaded it.

**How the swarm confirms it (non-destructive).** Read-only GETs only, at most three, using
endpoints verified in the `Project-MONAI/MONAILabel` source (`main` and tag `0.8.5`):

1. `GET /info/` (`monailabel/endpoints/info.py`). It returns `MONAILabelApp.info()`
   (`monailabel/interfaces/app.py`): `name`, `description`, `version`, `labels`, `models`,
   `trainers`, `strategies`, `scoring`, `train_stats`, and `datastore` (`total`, `completed`,
   `label_tags`). A 200 with that shape and no token means auth is off. The MONAI Label version
   comes from `name` (`"MONAILabel - Radiology (0.8.5)"` in the sample apps) or from `version`
   when `name` names MONAILabel. A custom app's `version` is its own, so it is not trusted.
2. Only if `/info/` answers 401/403: `GET /auth/` (`monailabel/endpoints/login.py`), which
   returns `{"enabled": true, "client_id": ..., "realm": ...}`. `monailabel/app.py` only mounts
   it when auth is on.
3. Only if that did not identify MONAI Label: `GET /openapi.json` (FastAPI title `MONAILabel`
   by default, or the `/datastore/image` + `/info/` routes).

Severity: critical when `/info/` answers without auth at version `<= 0.8.5` or with the version
hidden; high when auth is on (version hidden, ANNOTATOR still suffices); info when the version
is above 0.8.5 (likely a source or pre-release build; confirm it includes PR #1915). The swarm
never requests anything under `/datastore`, never sends PUT/POST/DELETE, an upload, a `../`
payload, a token, or a training, inference, or reload trigger. The verifier re-runs the same
GETs on a fresh fetch. Treat the finding as a lead and confirm by hand on a system you own.

**Fix.**
1. Turn auth on: `MONAI_LABEL_AUTH_ENABLE=true` with your OIDC / Keycloak realm.
2. Grant the ANNOTATOR role only to trusted users; review who already has it.
3. Keep MONAI Label off untrusted networks: VPN or IP allowlist, and block `PUT /datastore/*`
   from outside at the reverse proxy.
4. Run the server as an unprivileged user that can write only to the datastore directory (not
   root, read-only code and site-packages, container with a read-only root filesystem).
5. If you run a source build, confirm it includes PR #1915. Upgrade to the first release that
   ships it as soon as one exists.

**Check for compromise.**
- Unexpected Python startup files in every site-packages / venv the server uses: new `*.pth`
  files, `sitecustomize.py`, or `usercustomize.py`.
- Datastore files or labels with `..` or absolute paths in their ids, and files outside the
  datastore with the server user as owner and recent timestamps.
- Training jobs nobody started (`/train` requests, new model checkpoints), and unusual
  outbound connections or child processes from the MONAI Label process.
- Access logs with `PUT /datastore/image` or `PUT /datastore/label` from unknown clients,
  especially with `%2e%2e` / `../` in the `image` or `label` parameter.

**Sources:** [GHSA-qc22-rmgc-vg94](https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94),
[PR #1915](https://github.com/Project-MONAI/MONAILabel/pull/1915),
[OSV CVE-2026-133968](https://osv.dev/vulnerability/CVE-2026-133968),
[Amazon Threat Intelligence](https://aws.amazon.com/blogs/security/chinese-nexus-actors-cairn-ai-agents-found-a-zero-day-on-their-own/),
[The Hacker News](https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html).
