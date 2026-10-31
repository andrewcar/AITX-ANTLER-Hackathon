# Fix playbook

One entry per check the swarm can confirm. Each entry says what the finding means,
how the swarm confirmed it (always non-destructive), and how to fix it.

## PHP2Shell: affected PHP runtime (CVE-2026-109618 / CVE-2026-109619)

**Finding titles:** `PHP2Shell-affected PHP runtime (<version>)` (high) and
`PHP session.upload_progress enabled (PHP2Shell mitigation not applied)` (medium).
**Agent:** `php_runtime` (runs only when the target fingerprints as PHP).

**What it is.** Two unauthenticated remote-code-execution bugs in the PHP runtime,
disclosed and fixed on 2026-10-21 and added to CISA's Known Exploited Vulnerabilities
catalog on 2026-10-26. They affect every server API that serves web requests
(mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed). One abuses an out-of-memory
corruption path, the other stale request state reached via session upload progress
or fatal-error backtraces.

**How the swarm confirms it (non-destructive).** It reads the version the target already
advertises in `X-Powered-By`, plus at most one `GET /phpinfo.php` if that page is openly
served. It never sends multipart bodies, `PHP_SESSION_UPLOAD_PROGRESS` fields, oversized
requests or anything that pushes PHP toward out-of-memory. The verifier re-reads the
same evidence on a fresh fetch. A match means the target runs a release PHP lists as
affected; distro builds can carry backported fixes, so confirm the package changelog.

**Fixed releases:** PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.1 and earlier get no new
release; the PHP security team published source backports for 7.4, 8.0 and 8.1.

**Fix.**
1. Upgrade to the fixed release for your branch and restart every PHP worker.
2. Until you can: set `memory_limit=-1` administratively (e.g. `php_admin_value` in the FPM
   pool) with a container/cgroup memory cap, set `session.upload_progress.enabled=0`
   (php.ini, FPM pool or server config; not `.user.ini` or `ini_set`), and on PHP 8.5 set
   `fatal_error_backtraces=0`. Keep `post_max_size` low. Restart workers after each change.
3. Keep `session.upload_progress.enabled=0` after patching if you don't use upload progress
   bars; it is also PHP's mitigation for CVE-2026-115560, which the Oct 21 releases don't fix.
4. Stop advertising the version: `expose_php=Off`, and remove `phpinfo.php` from the web root.

**Sources:** [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching),
[PHP news archive (Oct 23 advisory)](https://www.php.net/archive/2026.php),
[AWS mitigation guide](https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/).
