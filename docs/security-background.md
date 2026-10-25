# Security background and evidence

This reference preserves dated source research and its limits. Repository availability and vendor support can change; check current advisories before applying an operator recipe. The implemented recognition rules are in `dephp2shell.sh`; [Sury evidence](sury-backport-evidence.md) records the bounded older-build review.

## What the vulnerabilities do

The [PHP release advisory](https://www.php.net/archive/2026.php) identifies all web-serving PHP installations as potentially exposed, including FPM, mod_php, CGI, FrankenPHP, and LiteSpeed.
Both issues have upstream CVSS v4.0 scores of 9.2.
Fix the PHP runtime; an application or plugin update alone does not replace that fix.

| CVE | Mechanism and operational consequence |
| --- | --- |
| [CVE-2026-109618: upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | An out-of-memory interruption can leave partially initialised request data that cleanup later consumes. Crafted multipart input can exhaust memory despite apparent upload limits. Confirmed mod_php exploitation occurs before application code starts. Upstream identifies FPM as susceptible through later application execution, without a complete demonstrated FPM exploit for this CVE. |
| [CVE-2026-109619: upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Request-owned state can remain after its memory is freed. Another request reaching the same worker can consume that state. Research confirmed RCE against mod_php and FPM. FPM's confirmed session path depends on a suitable application operation. Session upload progress can act before normal initialisation, even without an application call to `session_start()`. |

Operational inference: a PHP login screen or application maintenance plugin is an insufficient boundary. Requests can reach PHP before application authentication.
Do not infer immunity from nginx, a dynamic FPM pool, or a site that has no ordinary file-upload form.

The [Wiz research article](https://www.wiz.io/blog/php2shell-php-rce) reports demonstrations against WordPress, Drupal, and Joomla, and memory disclosure as well as RCE.
Those applications are examples rather than an exhaustive affected list.
The [Cloudflare response](https://blog.cloudflare.com/php-vulnerabilities-waf-protection) reports observed attack traffic and evolving payloads.
Attack-traffic observations do not establish whether a particular server was compromised.

## Fixed versions and package evidence

For unmodified upstream builds, the first fixed production releases in the maintained branches are:

| Branch | Fixed upstream release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Source: [PHP security release announcement](https://www.php.net/archive/2026.php).
PHP 8.1 and older require a maintained vendor backport or migration.
PHP supplied minimal source backports for 7.4, 8.0, and 8.1; these are not Debian or RPM packages and do not constitute an ordinary supported release.
Do not deploy prerelease PHP to solve a production incident.

### PHP 5.3 and earlier

Do not treat PHP 5.4 as a proven lower boundary for both CVEs.
The [PHP security-team explanation](https://daubois.dev/blog/cve-2026-109618-php2shell-rumors/)
identifies the out-of-memory bailout mechanism in PHP 5.3, while distinguishing
that source evidence from a demonstrated exploit on those older versions.
The [PHP 5.3 allocator](https://github.com/php/php-src/blob/PHP-5.3/Zend/zend_alloc.c)
contains `zend_bailout()` in its out-of-memory error handling. That mechanism alone
does not prove every request path or older release exploitable. The
[upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
does not establish an unaffected pre-5.4 range.

The detector's upstream-version rule returns `?` for versions before PHP 5.4.
Keep that conservative result until a reviewed version/vendor rule establishes
a fix or non-applicability. An old version must not produce `N` merely because
it predates the widely repeated PHP 5.4 starting point. Alongside fixed runtimes,
an unknown old runtime keeps the aggregate unknown; a known vulnerable runtime
still makes the aggregate `Y`. For these older releases, readable wording explains the coverage gap rather than
asserting that a backport is missing. Package-only evidence can be leftover files;
check dependencies and actual site/job use before removal or migration.

### Debian

| Release / source package | Fixed version or evidence status |
| --- | --- |
| Debian 13 trixie / `php8.4` | `8.4.27-1~deb13u1`, confirmed for both CVEs in [DSA-6574-1](https://lists.debian.org/debian-security-announce/2026/msg00489.html). |
| Debian 12 bookworm / `php8.2` | `8.2.35-1~deb12u1` is confirmed fixed by both the [109619 tracker](https://security-tracker.debian.org/tracker/CVE-2026-109619) and [109618 tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618), refreshed 22 October 2026. |
| Debian 11 bullseye | Ordinary Debian LTS ended 31 August 2026. Verify an applicable third-party support entitlement and PHP fix, or migrate. No fixed PHP package was verified in this research. [Debian lifecycle](https://www.debian.org/releases/bullseye/). |
| Debian 9/10 | Check the actual extended-support provider, package coverage, and entitlement. No CVE-specific fixed version was verified here. |
| Debian 8 jessie | No maintained vendor fix verified. See the native custom-backport recipe below. Freexian ELTS ended 30 June 2025. Disable exposed PHP applications pending migration or a separately verified maintained solution. [Freexian EOL notice](https://www.freexian.com/fr/lts/extended/updates/ela-1477-1-jessie-elts/). |

The earlier Debian 12 tracker inconsistency was resolved by refreshing both sources on 22 October 2026.

#### Jessie/i386 and native package compatibility

Research checked 24 October 2026. Target combination: Debian 8.11, i386,
Debian `php5` 5.6.38 packaging, Apache `libapache2-mod-php5`, CLI and PHP 5
extensions. A patched PHP 5.6 source exists; a compatible Jessie binary package
is a separate requirement.

- [Freexian's PHP support dates](https://www.freexian.com/lts/php/docs/end-of-life/)
  place Debian 8 end of support at 30 June 2025. Its
  [PHP2Shell announcement](https://www.freexian.com/blog/php2shell-updates/)
  confirms fixes across supported platforms and includes i386. Its
  [current platform table](https://www.freexian.com/lts/php/) starts with Debian 9.
  Ask explicitly for a custom Jessie/i386 build; a standard subscription does not
  establish availability for Jessie. Sury's homepage still mentions Jessie via
  Freexian, so use the current support table and a specific vendor confirmation.
- [Sury's repository suites](https://packages.sury.org/php/dists/) contain no
  Jessie suite. The [PHP 5.6 source/package directory](https://packages.sury.org/php/pool/main/p/php5.6/)
  contains revision `5.6.40-105+0~20261022.135+debian11~1.gbp37a17e` source files.
  Inspection of its `debian/changelog` records both CVEs in revision `-104`
  (21 October), followed by CVE-2023-0662 multipart-parser work in `-105`
  (22 October). The series includes
  `0261-Avoid-state-corruption-via-bailout.patch`.
  Source inspected: [Debian packaging archive](https://packages.sury.org/php/pool/main/p/php5.6/php5.6_5.6.40-105%2B0~20261022.135%2Bdebian11~1.gbp37a17e.debian.tar.xz).
  This identifies a maintained backport source, not a verified Jessie build.
- [TuxCare's current matrix](https://docs.tuxcare.com/els-for-runtimes/php/)
  lists Debian 10 and later and Linux x86_64, with some arm64 platforms.
  Jessie/i386 needs a custom request; its ordinary installation procedure does
  not cover that combination.
- [Freexian's public native Jessie archive](https://deb.freexian.com/extended-lts/pool/main/p/php5/)
  still contains i386 `php5-cli`, `php5-common`, `libapache2-mod-php5` and extension
  binaries at `5.6.40+dfsg-0+deb8u23`, dated April 2025. These predate PHP2Shell
  and are not the required fix. The native source is useful as a packaging
  baseline: [source descriptor](https://deb.freexian.com/extended-lts/pool/main/p/php5/php5_5.6.40%2Bdfsg-0%2Bdeb8u23.dsc),
  [Debian packaging](https://deb.freexian.com/extended-lts/pool/main/p/php5/php5_5.6.40%2Bdfsg-0%2Bdeb8u23.debian.tar.xz)
  and [original source](https://deb.freexian.com/extended-lts/pool/main/p/php5/php5_5.6.40%2Bdfsg.orig.tar.gz).
  The descriptor lists the legacy `php5-*` package family, Apache module and
  Jessie-era development dependencies. This is a closer packaging fit than
  transplanting the current Sury Debian 11 packaging. Inspect and verify source
  signatures/checksums before using it. The native `deb8u23` descriptor signature
  was verified against the Debian developer keyring on 24 October 2026.
  Both source archives matched its signed SHA256 values.
- [Dotdeb's closure announcement](https://www.dotdeb.org/?p=340) explicitly ends
  publication on 30 June 2020. Retained Jessie/i386 archives are historical
  packages, not a source for these 2026 fixes.

For third-party Debian/Ubuntu PHP, Sury is an established source to investigate:
its maintainer also packages PHP for Debian. [DEB.SURY.ORG](https://deb.sury.org/)
describes that relationship and its collaboration with Freexian.
[Freexian's FAQ](https://www.freexian.com/lts/php/faq/)
distinguishes commercial service commitments from Sury's best-effort repository.
That supports a provenance recommendation, not a measured popularity ranking or
an assumption that either repository supports every historical distribution.

Targeted searches also found community PHP 5.6 patches and Jessie-based Docker
build recipes, but no verified ready-built Jessie/i386 package set containing
both fixes. Do not substitute an old upstream `5.6.40` container, a different
architecture, or a mitigation extension for the required native patched runtime.

For matching legacy installations, first investigate vendor-built native
packages. If those are unavailable, evaluate a reproducible Jessie/i386 package
build using reviewed maintained PHP 5.6 backports and compatible Debian packaging.
Use the native `deb8u23` source packaging as the initial candidate and assess the
maintained backport's prerequisite changes before adding it. Preserve the later
multipart-parser work recorded in Sury revision `-105` when selecting patch inputs.
Use an isolated build VM/chroot with Jessie libraries. Modern Sury build
dependencies and `php5.6-*` package names need adaptation to Jessie's existing
`php5-*` layout; copying newer distro binaries or forcing dependencies is not
that adaptation. Do not compile or replace PHP directly on the production server as the build experiment.

Build and test Apache PHP, CLI and the required matching extensions together.
Retain PHP 5.6 application compatibility, configuration paths and package
relationships. The unpatched upstream `5.6.40` release alone is not the fix.
Keep source identity, authenticated source/checksum evidence, patch series,
build configuration, dependency versions and test results with the produced
packages. A custom package needs its own verified detector rule; a recent build
date must not automatically clear it.

#### Native Jessie backport inputs and compatibility

The native local package revision is `5.6.40+dfsg-0+deb8u23+rhphp2shell1`.
The detector recognises this exact revision on native Debian 8 PHP 5 engine packages.
Later local revisions require their own source and build review.
Its source baseline is Freexian's signed `deb8u23` Jessie `php5` source.
Add Sury's `0261-Avoid-state-corruption-via-bailout.patch` to the native quilt series.
The patch applies without fuzz; small line offsets reflect Debian's existing patches.
Its SHA256 is `d945982b5ab29bc5c42d1892750d72d39ae911df8b9f4f5ea47d133707ab72a4`.
The native baseline already contains the equivalent CVE-2023-0662 multipart limits.
Do not add Sury's duplicate `0262`/`0263` patches or import its entire modern packaging series.

Source verification uses two independent publisher chains:

- Native `.dsc`: Debian developer signing key `469CBAA776FDB1FCD475B304D39A499C3C21A552`, followed by signed archive hashes.
- Sury patch archive: signed Bookworm `InRelease`, `main/source/Sources.xz`, then the PHP 5.6 packaging archive checksum.
  Repository signing key: `15058500A0235D97F5D10063B188E2B695BD4743`.

This targeted backport preserves Jessie's `php5-*` package names and configuration paths.
It does not include every later security patch from current Sury PHP 5.6 packaging.
The PHP2Shell mitigation disables session upload-progress callbacks, including when the INI setting enables them.
Normal uploads and sessions require regression checks.
Memory-allocation failures terminate the worker immediately, without PHP shutdown callbacks.
Apache must remain healthy and replace such a terminated worker.

Build against Jessie/i386 dependencies in a disposable environment.
Use an isolated network namespace for tests that start a temporary MySQL server.
Check 32-bit allocation overflow, memory exhaustion, uploads, sessions, extension ABI and Apache requests.
`php5-json` has a separate source package; keep the installed JSON package when its ABI matches.
Select only installed SAPIs/extensions from the produced packages.
Retain the patched source package, input signature evidence, dependency manifest and test results beside the binary artifacts.
Local output packages are unsigned unless a separate release-signing step is performed.


### Ubuntu

These vendor package revisions fix both CVEs. They apply to the matching Ubuntu release and official package family.

| Ubuntu | Source package | Fixed vendor version | Access |
| --- | --- | --- | --- |
| 26.10 | `php8.5` | `8.5.9-0ubuntu2.1` | Standard security updates |
| 26.04 LTS | `php8.5` | `8.5.4-0ubuntu1.5` | Standard security updates |
| 24.04 LTS | `php8.3` | `8.3.6-0ubuntu0.24.04.13` | Standard security updates |
| 22.04 LTS | `php8.1` | `8.1.2-1ubuntu2.28` | Standard security updates |
| 20.04 LTS | `php7.4` | `7.4.3-4ubuntu2.29+esm5` | Ubuntu Pro |
| 18.04 LTS | `php7.2` | `7.2.24-0ubuntu0.18.04.17+esm14` | Ubuntu Pro |
| 16.04 LTS | `php7.0` | `7.0.33-0ubuntu0.16.04.16+esm22` | Pro Legacy Support |
| 14.04 LTS | `php5` | `5.5.9+dfsg-1ubuntu4.29+esm18` | Pro Legacy Support |

Sources: [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2).
Check each installed SAPI and its related packages, including FPM and Apache modules. A metapackage alone is insufficient inventory.
For example, patched Ubuntu 24.04 PHP still reports upstream version 8.3.6. An upstream-only detector would misclassify it.

### CentOS, Rocky, AlmaLinux, and RHEL

| Platform | Verified status at this research snapshot |
| --- | --- |
| RHEL | [Red Hat 109618](https://access.redhat.com/security/cve/cve-2026-109618) and [109619](https://access.redhat.com/security/cve/cve-2026-109619) identify affected products. RHEL 8 PHP 7.4 has [RHSA-2026:87080](https://access.redhat.com/errata/RHSA-2026:87080), version-release `7.4.33-8.module+el8.10.0+25117+30337cca`. Other streams need their own advisory; the detector does not clear unrecognised RHEL backports automatically. |
| AlmaLinux 8/9/10 | [AlmaLinux response](https://almalinux.org/ko/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/) now lists production fixed builds for all streams in AlmaLinux 8/9/10, rolling out from 21 October 2026 21:15 UTC. The exact advisory builds are recorded in the detector; do not apply them to other RPM vendors. |
| Rocky Linux 9 / PHP 8.0 | [RLSA-2026:87151](https://errata.rockylinux.org/RLSA-2026:87151) lists `0:8.0.30-8.el9_8.1` as fixing both CVEs. Verified 23 October 2026 against Rocky's [advisory API](https://errata.rockylinux.org/api/v2/advisories/RLSA-2026%3A87151), including `php`, `php-cli`, `php-common`, `php-fpm` and `php-embedded` on x86_64, aarch64, ppc64le and s390x. The script matches this exact revision and `Rocky Enterprise Software Foundation` vendor on Rocky 9; similar custom builds and other vendors remain unverified. |
| Other Rocky streams / supported CentOS Stream | Check the exact distribution's errata, architecture, PHP stream, and repository metadata. This detector has no reviewed backport rule for these streams. Do not copy another vendor's version threshold. |
| CentOS Linux 7 / CentOS Stream 8 | Ordinary vendor support ended in June / May 2024 respectively. Archived packages are not evidence of a new security fix. Verify a maintained third-party fix or migrate. [CentOS lifecycle notice](https://blog.centos.org/2023/04/end-dates-are-coming-for-centos-stream-8-and-centos-linux-7/). |

Alma's initial supported-stream plan covers 8: PHP 7.4/8.2; 9: default 8.0 and streams 8.2/8.3; 10: default 8.3 and PHP 8.4.
The refreshed advisory also lists fixes for the retired streams, including Alma 8 PHP 7.2.
Therefore, “the OS is supported” does not prove that the installed PHP stream will receive a fix.

DNF can report `Dependencies resolved.`, `Nothing to do.`, `Complete!` with exit
status zero. That is a successful query with no update candidates, not evidence
of an unsafe transaction plan or a verified PHP fix. Record
`package_update_plan:<phase>|dnf|no_updates`; do not request an install. An
unverified installation remains unknown with a `no_candidate` explanation.
Pending verified restart work can still proceed through the existing restart
checks. A vendor build already verified during inventory needs no update attempt.

### Third-party packages and bundled runtimes

Treat Sury/Ondřej, Remi, cPanel, Plesk, CloudLinux, custom builds, and containers as distinct package origins.

The PHP archive warned that Remi would not have updates on release day. This is a dated availability statement; recheck the provider before acting.
Do not automatically switch repositories or major PHP streams during a security update.

[cPanel's vendor notice](https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619) lists panel updates separately from EasyApache PHP updates.
It lists backported EasyApache builds for 7.4, 8.0, and 8.1, and upstream fixed releases for 8.2–8.5.
Use that vendor's current maintenance procedure for panel systems. Updating the OS PHP package may leave the web-serving panel PHP unchanged.

## Check-mode update assessment

Keep PHP restart requirements separate from other web-server maintenance. A
deleted nginx/Apache executable without a mapped PHP module does not establish a
PHP2Shell verification gap. Record the separate restart advisory without
restarting PHP-FPM or changing the CVE state. Successfully read memory mappings
are required for that conclusion; failed or unreadable inspections remain unknown.
Deleted PHP executables/modules still need restart verification. `/dev/zero
(deleted)` mappings alone are not evidence of deleted PHP code.

The detector reports update feasibility separately from vulnerability. Its
`patchability` manifest records distinguish `not_needed`, `blocked`,
`eligible_to_attempt` and `unknown`. Local package/service prerequisites can rule
out the current automatic fix without making changes. Passing them does not
establish that trusted repositories offer a verified fix or that the eventual
transaction and restarts will succeed. Check mode does not refresh package
metadata; do not treat this assessment as an available-package guarantee.

### AlmaLinux 10 stock PHP build

The stock `8.3.31-1.el10_2` PHP engine packages with vendor `AlmaLinux` predate
the fixed `8.3.33-1.el10_2.alma.1` build published in
[Alma's advisory](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
(checked 23 October 2026). The detector has an exact affected-build rule for this
case, including absent/zero RPM epoch. Other rebuilds retain their own evidence
requirements. Do not classify all older RPM versions as vulnerable by upstream
number alone: vendor backports can preserve that number.

A fixed-version executable can have a build date preceding public disclosure.
Use verified versions and vendor builds rather than a minimum build date as the
patch criterion.

## Package update procedure

The following operator procedure requires adaptation and validation on the actual distribution/runtime family. It is separate from invoking the script's guarded update action.

1. Record host identity, UTC time, OS/release, architecture, package origin, installed revisions, serving runtimes, and active service units.
2. Confirm the maintenance target and recovery path. For a cluster, drain one node and keep sufficient capacity available.
3. Refresh signed package metadata. Treat unavailable repositories, expired credentials, signature failures, holds, and stale mirrors as blockers.
4. Compare the candidate against the matching vendor's fixed revision for both CVEs. “Already newest” alone proves nothing.
5. Simulate the selected transaction. Review removals, dependencies, PHP extensions, version changes, and unrelated service actions.
6. Apply the approved package transaction. Keep PHP packages and dependent extensions consistent. Do not force configuration replacement.
7. Check configuration syntax and replace every affected runtime's workers. Package scripts may already have done this; verify the evidence.
8. Check application responses on the actual backend and each required node/runtime. Check logs and service health.
9. Restore traffic only after the fixed package and runtime checks pass. Keep unresolved nodes drained or their PHP endpoints disabled.
10. Save before/after evidence and update the status report.

### Debian and Ubuntu command examples

Run discovery before choosing package names. The following commands inspect local package state; they do not change packages:

```sh
cat /etc/os-release
dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' 'php*' 'libapache2-mod-php*'
apt-mark showhold
```

An unmatched `dpkg-query` pattern can return nonzero. Do not interpret command failure as “PHP absent.”
Inspect configured repositories and `apt-cache policy` for each serving package, including packages outside these naming patterns.

Illustrative transaction for an already-installed Debian 13 FPM installation:

```sh
sudo apt-get update
apt-cache policy php8.4-fpm php8.4-common
sudo apt-get -s install --only-upgrade php8.4-fpm php8.4-common
# After reviewing the candidate versions and proposed transaction:
sudo apt-get install --only-upgrade php8.4-fpm php8.4-common
```

Add the other installed PHP packages that need updating; the two named packages are an example, not a complete package list.
On a mod_php host, include the installed `libapache2-mod-phpX.Y` package. Include alternate versions and relevant CLI/CGI packages.
Do not run this example unchanged on Jessie or a host with a different PHP provider.

[Canonical's incident guidance](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available) recommends a system update and application restarts, or a reboot.
It explicitly warns that unattended security updates can still leave applications needing a restart.
For a targeted PHP update, a targeted transaction gives a smaller maintenance scope where dependency resolution permits it.
Plain `apt-get upgrade` may hold packages back; review its result. Do not automatically escalate to `dist-upgrade` to force a result.

Use `dpkg --compare-versions` with the full package revision. Never use string comparison or `sort -V` as a substitute for Debian version semantics.

### RPM-family command examples

First inspect the installed package family, repositories, and applicable modules:

```sh
cat /etc/os-release
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' 'php*'
dnf repolist
dnf module list php
```

Module commands apply only where PHP is delivered through modules. A failed module query is not evidence that PHP is absent.
Panel or software-collection packages may have different prefixes and service names; inventory them separately.

For a supported DNF host, refresh metadata with `sudo dnf makecache --refresh`.
Review CVE-related `dnf updateinfo` records where the vendor publishes them.
Preview an upgrade of the **explicit installed runtime package names** with `dnf --assumeno upgrade ...`, then apply the reviewed transaction.
On older YUM systems, use the corresponding YUM procedure and verify the maintained support source first.

Missing CVE metadata is not a clean result. Neither is a package changelog that happens to mention a CVE.
Use the vendor advisory and RPM epoch/version/release comparison for the correct stream and architecture.
Do not reset a module, enable a different stream, run `distro-sync`, or enable testing repositories as an incidental automated fix.

## PHP-FPM and other restart requirements

**Require every serving PHP worker to use the fixed runtime.**
An additional manual restart is unnecessary only when evidence shows the package transaction already completed the required replacement.

Debian FPM packaging includes service restart handling, but local policy can prevent it.
See the [FPM package maintainer fragment](https://sources.debian.org/src/php8.4/8.4.24-1/debian/php-fpm.postinst.extra) and [`invoke-rc.d` policy semantics](https://manpages.debian.org/unstable/init-system-helpers/invoke-rc.d.8.en.html).
These explain why an automatic action is possible; they do not prove what happened on a particular host.

Recommended handling:

| Runtime | Action and verification |
| --- | --- |
| PHP-FPM | Identify every active versioned/custom unit and pool. Test the corresponding FPM configuration. Restart that unit if a complete replacement is not established. Debian/Ubuntu often use `php8.4-fpm`; RPM distributions often use `php-fpm`. Check actual units. |
| Apache mod_php | Test Apache configuration, then restart Apache so it loads the fixed PHP module. Unit names commonly differ: `apache2` versus `httpd`. |
| nginx proxying FPM | Replace FPM workers. Restarting nginx alone does not replace PHP. Reload nginx if its own configuration changed. |
| CGI / FastCGI / LiteSpeed / FrankenPHP | Replace the process or supervisor that actually executes PHP, using its vendor's procedure. Do not assume a process called `php-fpm` exists. |
| Containers / cluster images | Rebuild from fixed packages/images and replace running containers on every node. Updating the host package or image tag alone does not update a running container. |
| Long-running PHP CLI workers | Restart the affected jobs/supervisors. A new `php -v` process says nothing about already-running workers. |

Use a full restart as the default incident procedure where a brief interruption is acceptable.
If using a graceful reload, establish that it loads the fixed runtime and that all previous workers exit. Record the drain timeout and remaining workers.
Do not report completion while an old worker can still process requests.
Resetting OPcache alone cannot replace vulnerable PHP engine code.

Example, only after confirming these exact units and binaries exist:

```sh
sudo php-fpm8.4 -t
sudo systemctl restart php8.4-fpm
systemctl is-active php8.4-fpm
systemctl show php8.4-fpm -p MainPID -p ActiveEnterTimestamp
```

Record old and new process identities and start times, package ownership of the executable/module, and service logs.
Use `/proc/<pid>/exe` and `/proc/<pid>/maps` or installed tooling to investigate old/deleted mappings.
Absence of deleted mappings alone does not prove the package contains either fix.

A protected check through the real web SAPI should report the PHP version and selected effective settings, without exposing `phpinfo()` publicly.
Correlate that check with the package provenance and replacement evidence. One request cannot prove every pool or cluster node is updated.

## Temporary containment and configuration gotchas

The [UK NCSC alert](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php) recommends considering taking systems offline when immediate remediation is not feasible.
Prefer a static maintenance response or web-server access denial that runs before PHP.
Check every hostname, alias, direct-origin path, backend, and IPv4/IPv6 listener.
Never disable a PHP handler in a way that makes the server download PHP source.

Map shared FPM-pool dependencies before stopping a pool. If disabling webmail or administration interfaces, verify mail delivery and authentication separately.

The upstream advisories describe these partial measures:

| Measure | Limit or operational cost |
| --- | --- |
| Enforce `memory_limit=-1` administratively | Removes a controllable PHP OOM trigger, but underlying allocation failure remains dangerous. Removes per-request memory protection and can increase host-wide outage risk. Do not bulk-apply without a capacity boundary. |
| Conservative body/upload limits and multipart controls | Bound decoded body size, input nesting, fields, parts, headers per part, and uploads. Cover requests without useful `Content-Length`. Where uploads are unnecessary, block multipart before PHP. Ordinary body limits alone are insufficient. |
| Container/cgroup boundary | Can limit availability damage. Prefer killing only the affected worker. Do not substitute `RLIMIT_AS` or `RLIMIT_DATA`; allocation failures can trigger the vulnerable path. |

Source: [109618 mitigation details](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).

For stale-state exposure, disable `session.upload_progress.enabled` before request parsing and replace workers.
For PHP 8.5, also disable `fatal_error_backtraces` when an immediate fix is unavailable.
Neither setting covers every state path. FPM `.user.ini` and application `ini_set()` apply too late for upload-progress containment.
Remove deprecated or invalid per-request settings that emit early diagnostics. Suppressing display/logging does not prevent the memory access.
Fix attacker-reachable fatal errors and timeouts. `pm.max_requests=1` can reduce worker reuse at a performance cost; it is not a complete fix.
Source: [109619 mitigation and audit details](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

Example FPM pool settings for the corresponding limited containment measures:

```ini
php_admin_flag[session.upload_progress.enabled] = off
; PHP 8.5 only:
php_admin_flag[fatal_error_backtraces] = off
; OOM containment only after reviewing host memory controls:
php_admin_value[memory_limit] = -1
```

Merge settings into each applicable existing pool. Do not append conflicting values blindly.
Use startup configuration where appropriate. Test the exact binary/configuration and replace workers.
[FPM configuration documentation](https://www.php.net/manual/en/install.fpm.configuration.php) explains pool `php_admin_*` settings and their resistance to application `ini_set()` overrides.
Keep a backup and a bounded rollback of the configuration edit.
After patching, review temporary limits against real application needs. Do not leave unlimited memory as an accidental permanent change.

For already-proxied sites, [Cloudflare's response](https://blog.cloudflare.com/php-vulnerabilities-waf-protection) describes protections on free and paid plans and recommends keeping them enabled while patching.
Check managed-rule deployment, block actions, exemptions, and events. Prevent direct-origin bypass where the service design permits it.
WAF protection is supplementary; do not report a runtime as fixed because a rule is enabled.
Do not assume a WAF event proves successful compromise.

## Public automation research: 22 October 2026

The following are useful implementation leads, not independent proof that a
particular package fixes both CVEs. Repository contents and first-party vendor
guidance were inspected; no third-party script, exploit or extension was run on
a production or development service. Public scripts are changing quickly. Recheck
their source before adopting anything; these are observations of this snapshot,
not endorsements or security audits of those projects.

| Source | Useful idea and limit |
| --- | --- |
| [OpenAI php2shell-checker](https://github.com/openai/php2shell-checker) | HTTP/CLI version checker. Useful version-reporting comparison; it does not replace local package provenance, multiple runtime inventory or worker replacement checks. Its Node dependency is unsuitable for older hosts. |
| [KyleClouthier/php2shell-check](https://github.com/KyleClouthier/php2shell-check) | `check-all-php.sh` inventories alternate installations. Useful path leads; executable modification times and process start times alone cannot establish that a worker runs a patched build. |
| [EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check) | Checks multiple SAPIs, panel/custom paths, containers and FrankenPHP. Embedded PHP needs `frankenphp version`, not a comparison against the FrankenPHP application version. |
| [Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) | aaPanel/LiteSpeed discovery and configuration mitigation. Modern-shell and online lookup requirements should not become dependencies of the delivered script; configuration containment is not a verified fix. |
| [MakFly/php2shell-check](https://github.com/MakFly/php2shell-check) | Package/restart/container automation. Rebuilding and redeploying an image is distinct from updating host packages or restarting an unchanged container. Broad transactions need tighter scope for production systems. |
| [Hosted Power php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) | A hosting company's native PHP extension and deployment automation detach the upload-progress handler. The project describes this as a stopgap; it requires matching PHP build tooling and does not establish that every CVE path is patched. Not an automatic fix recipe for this script. |
| [Syhunt php2shell-protection](https://github.com/syhunt/php2shell-protection) | Multipart/upload-progress containment and SAPI configuration caveats. Per-directory `.user.ini` changes can be too late for pre-initialisation paths; no clean vulnerability result based on these settings. |
| [ersinkoc/php-fix](https://github.com/ersinkoc/php-fix) | Config backups, validation and live-check ideas. Disabling upload progress is partial containment. Do not copy a live PHP test endpoint or broad automatic config rewrites into an update recipe. |

### Missed installations and restart traps

- **Panel-internal PHP is separate from website PHP.** [Plesk's advisory](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-Remote-code-execution-in-PHP-shipped-with-Plesk)
  includes `sw-engine` and fixes in Obsidian 18.0.81 Update 4 / 18.0.80 Update 11.
  Its older PHP branches can retain their upstream version after a vendor
  rebuild. [cPanel's release notes](https://docs.cpanel.net/release-notes/release-notes/?p=63801)
  also distinguish internal PHP from EasyApache PHP. Updating a site's selected
  runtime alone cannot clear the panel or its applications.
- **Detached workers survive web-server restarts.** [LiteSpeed's restart documentation](https://docs.litespeedtech.com/lsws/cp/cpanel/php/#restart-php)
  says detached PHP is not replaced by an LSWS restart. Restart-marker files take
  effect when handlers are used; touching a marker is not immediate evidence of
  replacement. Inventory bare `lsphp`, not just executables named `php`.
- **Host packages and jailed copies can diverge.** [CloudLinux's integration documentation](https://docs.cloudlinux.com/cloudlinuxos/control_panel_integration/)
  requires a CageFS skeleton update after system RPM updates. Its
  [component documentation](https://docs.cloudlinux.com/cloudlinuxos/cloudlinux_os_components/)
  also describes alt-PHP INI rebuilds. These need a vendor-specific recipe and
  verification inside the application jail, rather than an unreviewed automatic
  `cagefsctl` invocation.
- **Security-only metadata can lag fixed packages.** [CloudLinux's PHP2Shell notice](https://blog.cloudlinux.com/php-cve-2026-109618-and-cve-2026-109619)
  says UpdateInfo/OVAL metadata was not yet published, so `yum --security` could
  miss available fixes. The script uses an ordinary targeted package
  update. Native PHP, EasyApache and alt-PHP are separate package families.
- **Version numbers require provider context.** Vendor backports can keep an
  apparently vulnerable upstream number. Build dates and changelog mentions are
  useful observations but do not prove both fixes. A repository index or public script alone does not justify a new backport recognition rule. The separate [Sury review](sury-backport-evidence.md) records authenticated source and binary evidence.
- **Containers and chroots are separate inventories.** A process can appear in
  host `/proc` while its executable path belongs to another filesystem. Do not
  query the host package owner or restart a host unit based on that foreign path.
  Conversely, [PHP-FPM's service template](https://github.com/php/php-src/blob/master/sapi/fpm/php-fpm.service.in)
  uses `PrivateTmp`, which creates a mount namespace without moving PHP off the
  host filesystem. Namespace differences alone are not proof of a container;
  verify matching root and runtime file identities, including mapped PHP modules.

## Evidence required for additional recipes

Keep observation dates separate from publication dates. Distinguish authenticated vendor claims, locally verified observations and proposed procedures.

- Identify the provider, OS suite, PHP branch, package architecture, installed source identity and full binary revision.
- Authenticate repository metadata and tie the source archive, enabled patch series and binary packages to that metadata. Review both CVEs and any prerequisite patches.
- Confirm support entitlement and an actually available fixed candidate. Archive availability and a familiar maintainer name are insufficient.
- Review the whole transaction: SAPIs, extension ABI, configuration preservation, selectors, module streams, holds, dependency additions and removals.
- Identify service ownership, active configuration and every old worker that needs replacing. Test vendor restart behaviour on a disposable instance.
- Add offline positive and negative fixtures for the exact provider rule and transaction boundaries. Include lookalike versions from another provider, unsupported architectures, partial failures and surviving workers.
- Check application behaviour on a representative instance. A package checksum or successful updater command cannot establish application compatibility.

Provider migrations need their own explicit operator choice and rollback plan. The reserved `--disruptive` action currently performs no such migration. Keep sensitive server evidence private when proposing a new recipe.

## Source confidence

Use PHP and each package vendor as the authority for their own fixes. Researcher publications establish their reported demonstrations. WAF-provider publications describe those providers' protection and traffic observations. Popularity, a changelog mention or a recent build date cannot replace package evidence.

- [PHP Foundation context](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) describes discovery and remediation.
- [Canonical guidance](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available) and the linked USNs cover Ubuntu revisions, support requirements and restart advice.
- [Debian trackers](https://security-tracker.debian.org/tracker/CVE-2026-109618), [AlmaLinux's response](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/) and vendor advisories above apply to their own package families.
- [UK NCSC guidance](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php) covers incident-response choices when immediate patching is infeasible.

The dated source review did not execute third-party exploits, establish absence of active exploitation or investigate compromise of any particular server. Speculative posts and unverified exploit repositories are not detection rules.
