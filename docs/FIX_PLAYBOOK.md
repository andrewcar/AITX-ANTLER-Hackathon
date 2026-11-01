# Fix playbook

One entry per check the swarm can confirm. Each entry says what the finding means,
how the swarm confirmed it (always non-destructive), and how to fix it.

## GitLab CE/EE: CI/CD regex compiler RCE (CVE-2026-97229)

**Finding titles:**
- `GitLab <version> affected by CVE-2026-97229 (CI regex RCE, CISA KEV)`: **critical** when the
  version came from an anonymous `/api/v4/version` answer (high confidence), **high** when it
  came from HTML version strings (medium confidence).
- `Unsupported GitLab <version> (older than the 19.2 line)` (medium).
- `GitLab detected; version not exposed anonymously` (info: exposure unknown, check by hand).

**Agent:** `gitlab_version`. It runs only when the target fingerprints as GitLab
(`_gitlab_session` cookie, `X-Gitlab-*` headers, or a `/users/sign_in` page in the crawl).

**What it is.** It's a CVSS 10.0 remote-code-execution bug in self-managed GitLab CE/EE.
An integer overflow in the Ruby/Onigmo regular-expression compiler is reached through
a crafted regex in a CI/CD configuration. The regex passes GitLab's validation in a
compact ASCII form. It is then recompiled for UTF-8 against a crafted repository path,
the program-size calculation overflows, and the result runs a command as the `git` user.
GitLab rates it unauthenticated. Rapid7 found that the attacker has to plant a
`.gitlab-ci.yml` first, which any account can do where self-sign-up and public project
creation are allowed. GitLab fixed it on 2026-10-12. CISA added it to the **Known
Exploited Vulnerabilities catalog on 2026-10-29** (active exploitation), with a federal
due date of **2026-11-01**. KEV notes that other Ruby/Onigmo-based products may share
the same root cause.

**Affected / fixed (GitLab advisory):**

| Line | Affected | Fixed in |
| --- | --- | --- |
| 19.2 | 19.2.0 – 19.2.7 | **19.2.8** |
| 19.3 | 19.3.0 – 19.3.4 | **19.3.5** |
| 19.4 | 19.4.0 – 19.4.1 | **19.4.2** |

The advisory lists this CVE from 19.2 only. Releases older than 19.2 are reported
separately as *unsupported*, because they also miss the other fixes in the 2026-10-12
security release (several of which reach back to much older versions). GitLab.com and
GitLab Dedicated are already patched.

**How the swarm confirms it (non-destructive).** It sends anonymous `GET`s, at most four:

1. `/users/sign_in`, for GitLab markers and the `gon.version` string.
2. `/-/manifest.json`, for the product name.
3. `/api/v4/version`, which only counts if it answers **without** a token. Most
   instances answer 401, and that's fine.
4. `/help`, for an "Edition x.y.z" string.

If the first two requests show no GitLab markers, it stops there. It never sends a
regex, a CI config or a CI-lint request. It never creates a project, pipeline or
account, never authenticates and never guesses credentials. Every request goes through
the normal request layer, so it gets the allowlist gate, the redirect scope lock, pacing,
the kill switch and the audit log. The agent also re-checks the allowlist itself before
its first request. The verifier re-runs the same fingerprint on a fresh fetch.

A match means "running a release GitLab lists as affected". It can't see hot-patches, or
a patched Ruby on a source install, so confirm on the host
(`sudo gitlab-rake gitlab:env:info`, or Admin > Help).

**Fix.**
1. **Upgrade now, outside the normal patch cycle**, to 19.2.8, 19.3.5 or 19.4.2 (or any
   later release). The patch has database migrations: single-node installs have downtime,
   and multi-node installs can use the zero-downtime procedure. Releases older than 19.2
   should move to a supported line by following the upgrade path.
2. **Source installs:** also run Ruby 3.3.13, 3.4.12 or 4.0.9 or later. Those releases
   carry the regexp fixes for GitLab's CVEs (see the ruby-lang.org notice).
3. **Until you can patch.** These steps only narrow the known delivery path; they don't
   fix the compiler.
   - Disable open sign-up (Admin > Settings > General > Sign-up restrictions).
   - Stop untrusted users creating or writing to public projects.
   - Restrict anonymous access to public projects, or set visibility to internal or private.
   - Keep the instance off the open internet (VPN or IP allowlist).
4. **Assume compromise if it was exposed** (KEV marks forensic triage as required).
   - Look for the GitLab-published detections: Onigmo native worker crashes, hostile
     regexps in GraphQL `ciLint`, CI regexp guard rejections, CI-lint workhorse worker
     crashes and scripted CI-lint error bursts.
   - Look for unexpected processes run by the `git` user.
   - Look for new public projects with odd `.gitlab-ci.yml` files or UTF-8-heavy paths.
   - Rotate runner tokens, deploy keys and CI secrets if anything turns up.
5. Optionally, stop advertising the version to anonymous users.

**References:**
- [GitLab critical patch release 19.4.2 / 19.3.5 / 19.2.8](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/)
- [CISA KEV alert, 2026-10-29](https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [cisagov/kev-data](https://github.com/cisagov/kev-data)
- [NVD CVE-2026-97229](https://nvd.nist.gov/vuln/detail/CVE-2026-97229)
- [Rapid7 analysis](https://www.rapid7.com/blog/post/etr-cve-2026-97229-critical-unauthenticated-remote-code-execution-in-gitlab/)
- [Ruby regexp fixes for GitLab CVEs](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/)
