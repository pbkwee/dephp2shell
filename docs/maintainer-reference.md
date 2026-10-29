# Maintainer reference

Implementation details and evidence requirements for `dephp2shell.sh`. Diagnostic prose states the observed result, any unmeasured scope and the practical next check. Start with [usage](usage.md) and [coverage](coverage.md) for operator instructions. Vulnerability mechanisms and research are in [security background](security-background.md).

## Script organisation

Keep the shipped script in one file so it can run on an old VM without companion
files or a downloader. Function definitions are grouped by responsibility; the
entry guard runs `p2s_cli` only after all definitions are loaded. It parses the
public options, prepares logging when requested and calls the `p2s_main` engine. Internal
function names are not an external shell API. CLI arguments, output records and
exit statuses form the integration contract.

| Prefix | Responsibility |
| --- | --- |
| `p2s_manifest_*`, `p2s_message_*` | Structured evidence, URL redaction and readable messages. |
| `p2s_command_*`, `p2s_work_directory_*` | Command lookup, deadlines and private temporary directories. |
| `p2s_distro_*` | Read distribution identity from release files. |
| `p2s_version_*`, `p2s_state_*` | Version/backport rules and aggregate patch evidence. |
| `p2s_package_*` | Package classification, ownership, publisher and repository evidence and diagnostics. |
| `p2s_package_deb_*`, `p2s_package_rpm_*` | Backend-specific policy checks and guarded package updates. |
| `p2s_disruptive_*` | Explicitly selected method checks and repository changes; shared transaction guards still apply. |
| `p2s_repository_*` | Read repository definitions. |
| `p2s_panel_*` | Detect hosting panels and dispatch vendor updates. Small cPanel/Plesk branches share this path. |
| `p2s_process_*`, `p2s_web_*` | Process scope, scheduled PHP tasks and web listeners. |
| `p2s_runtime_*` | Runtime paths, executable version probes and PHP startup warnings. |
| `p2s_service_*` | Configuration checks, supported restart commands and worker replacement verification. |
| `p2s_summary_*`, `p2s_inventory_*`, `p2s_fix_*` | Readable summaries, inventory coordination and fix eligibility/execution. |

Functions that capture command output keep diagnostics out of that captured
value. Shared `P2S_*` variables hold one run's working state, not user-facing
configuration. Preserve the existing Boolean/state contracts when renaming a
helper. Keep `P2S-MUTATION` markers beside mutating functions, their key callers
and the commands that change packages or services.

## Human console styling

`p2s_output_print_human` applies colour and emphasis after the raw stream passes
through `tee`. Keep machine output and detailed logs outside that formatter.
Text inherits the terminal's default colours; optional coloured markers do not
carry meaning on their own. Auto mode checks the actual output descriptor and
terminal capabilities once per run, with no required `tput` dependency.
See [terminal readability](usage.md#terminal-readability) for controls and precedence.

## Detection

The script inventories Debian/RPM PHP packages, package-owned executables and
Apache modules, conventional alternate PHP paths, control panels, and relevant
running processes. The readable summary groups core components by PHP version,
package publisher and patch state, with a plain explanation of verified backports.
Main-process start times are shown in UTC. Different conclusions for the same PHP
version remain separate. Aliases and extension packages do not create repeated readable messages. Full package
revisions, paths, version output and individual worker details stay in the manifest.

Informational messages report when no recognised web-server process is found and
whether TCP ports 80/443 have listeners. The port check reads `/proc/net/tcp` and
`tcp6` without requiring `ss` or `netstat`; unavailable/failed inspection is not
reported as absence. `web_process`, `web_process_summary`, `web_listener`,
`web_listener_table` and `web_listener_scope` preserve the observations. These
checks do not affect vulnerability state or select services for restart. Process
names, other ports, firewall reachability and separate network namespaces limit
what can be inferred about whether a website is serving requests.
After a package installation or service restart attempt, a `dss:warn:` identifies
each previously observed web-server type no longer detected. Worker PID changes
and Apache's `apache`/`httpd` names do not count as a stopped server. An unavailable process inventory leaves disappearance unverified. The `web_server_missing`
manifest record preserves the comparison; it does not change the PHP CVE state
or trigger an automatic restart. Check service logs and website availability.

Each version group distinguishes installed-package evidence from discovered
executables or Apache modules. A running-process reference is matched by runtime
path, including resolved executable aliases, rather than by version number alone.
Website routing and the code loaded by each process require separate checks. Package-only entries can be leftovers;
check their dependencies before removal. Failed version probes do not supply
executable-version evidence. CVE assessment uses the full package revision or executable version as well as running-process observations.
Package directories named `php` and cron, init and logrotate definitions are excluded
from runtime paths. Those configuration files can share executable basenames such
as `php-fpm` or `sw-engine`, even when the definitions have execute permissions. Missing runtime
files, failed package file lists, unrecognised version output and unreadable
process details produce verification warnings and `inventory_gap` records.
Processes can exit during inspection; a check-only rerun can resolve that gap.
Successful update/restart commands do not override an incomplete final inventory.
`fix_commands` records their exit statuses; readable text distinguishes successful
commands with incomplete verification from a failed update/restart operation.

The final result names patched PHP, unverified versions or incomplete checks.
When all assessed versions are fixed but a specific running-process or inventory
gap remains, the result separates those fixed versions from the outstanding check.
Installed Docker/Podman/LXC tools are informational and do not force an unknown
state. A separate web-server process with readable mappings and no mapped PHP is
also informational. Detected isolated PHP, a mapped PHP module, or failed module
inspection requires a separate-environment review and keeps the result unknown.
Foreign paths and processes are always excluded from host probes and restarts.
A blocked update in that case recommends reviewing the separate environment
rather than repeating host package updates.
`verification_scope` records this distinction without changing the aggregate CVE
result. A web-server process such as nginx is not labelled as evidence of PHP use;
its process name/executable and review reason remain in `process_scope_review`.
Detected control panels are named with their update method or automatic-update restrictions.
If the known locations contain no recognised panel, the summary says so without
claiming that no custom panel exists.
For Virtualmin, check each virtual server's PHP selection and application
compatibility before updating or removing old PHP packages. See
[Virtualmin's multiple-PHP-version guidance](https://www.virtualmin.com/docs/server-components/configuring-multiple-php-versions/).

When parallel PHP branches remain vulnerable or unverified, the final summary
names the versions needing attention. It recommends migrating their websites,
applications and scheduled jobs if no supported security update is available.
Test those workloads before removing unused older packages. Review and change each website's PHP selection explicitly. Check vendor support for unverified backports before selecting migration.

One aggregate marker is emitted per phase:

```text
dss:isvulnerable:beforefix: CVE_2026_109618Y
dss:isvulnerable:afterfix: CVE_2026_109618N
```

`Y` means a package or runtime is identified as vulnerable, for example an
official package below its verified fixed revision or an affected unpackaged
runtime. `N` means no vulnerable PHP was found within the inspected scope.
`?` means a specific inventory, vendor-backport or running-worker check is incomplete.
Verified fixed PHP keeps its fixed assessment when the publisher is unfamiliar, an update recipe is missing or a restart target is unmapped. Those restrictions still block automatic
changes when an update is needed. Deleted PHP files, failed version probes,
package/runtime mismatches and unreadable process details remain verification gaps.
Recognised fixed upstream releases count as fixed for packages and executable
versions, including custom and selector-owned executables. An embedded product's
package revision is kept separate: sw-engine/FrankenPHP require an actual PHP
version probe, and missing probes remain unknown.
Vendor packages can retain older upstream numbers. Assess their full revisions against reviewed backport rules; unrecognised backports remain unknown.
A vulnerable runtime wins over every other result; otherwise an unknown runtime prevents clearance.
A failed fix cannot produce an after-fix `N`, even if packages appear current.
Unpatched packages remain a problem even if PHP is currently stopped.
When a complete check finds no PHP engine, no PHP update recipe is needed.
The script records `update_recipe` as `not_needed` in the manifest and suppresses
OS update-recipe warnings. Incomplete inventories still show those warnings.
Operating-system security-update coverage requires a separate check.
Unknown-version summaries name the missing evidence and show the installed package
revision where available. A missing vendor fix rule, unavailable package inventory,
unassessed engine owner and package/runtime version mismatch are distinct gaps.
Main-process observations include the PID and executable so separate web-server or
PHP masters can be identified. Repeated inventory observations appear once per run;
before/after PHP version assessments retain their phase and attempted update command.
The read-only retry assessment retains raw records without another version summary.
Sury summaries distinguish the PHP engine version from the installed binary
package names and full package revision. `package_fix_reference` records the
reviewed fixed build and `dpkg` version comparison. Older/newer comparisons explain
an unknown result; they do not broaden the exact backport recognition rules.
Equal versions still require the reviewed source identity and architecture.
Different Sury package revisions stay separate even when `php -v` is identical.

Installed Sury/ondrej packages with no recognised active binary APT source matching
the OS release and package architecture produce an update-source warning.
The check reads conventional source definitions, including comments, Deb822
`Enabled`, package architecture options and Ubuntu ondrej sources. Cached APT
indexes do not count as an active source. A missing source does not change an
otherwise verified fixed package's CVE assessment. Source activation retains
its existing explicit opt-in requirements.

Operational results omit routine application-testing reminders. Specific material
compatibility changes remain documented alongside the proposed operation.

Each engine package retains its own fixed, vulnerable or unknown manifest result;
readable messages group only matching versions and conclusions. For
example, fixed PHP 8.3/8.4 alongside vulnerable PHP 8.2 still produces aggregate
`CVE_2026_109618Y`, regardless of discovery order. Unknown evidence prevents an
aggregate `N` but does not override a known vulnerable result.

Fixed upstream floors are 8.2.35, 8.3.36, 8.4.27 and 8.5.12, separately by branch.
Build dates are displayed as package metadata; fix classification uses reviewed version and backport rules. Prereleases and unrecognised
versions are unknown. Debian PHP metapackages are inventoried but not mistaken
for engine versions, including the unversioned `libapache*-mod-php` selectors.
Panel and LiteSpeed extension/library package versions are not PHP engine versions.
For example, `cpanel-php84-xml-serializer` version `0.21.0` is the extension's version; query the PHP executable for its engine version.
Supporting packages stay in the manifest. Bundled-runtime warnings are grouped by
package publisher, and unmapped service warnings by process name, executable and service.
Each unmapped PID remains in the manifest and prevents an automatic update that needs its restart.
CGI/FastCGI warnings explain that the launcher or supervisor needs identifying;
restarting PHP-FPM alone may not replace CGI workers. `process_parent` records
the child PID, parent PID, parent process name, executable and systemd unit when
readable. These observations do not authorize a restart based on parent names.

PHP CLI processes launched under `cron.service` or `crond.service` are handled
separately when the executable belongs to an inventoried CLI engine package.
They do not block package updates or become service restart targets. The script
never terminates those tasks or restarts cron to replace them. CGI/FPM, custom
binaries and unverified owners keep their existing restart restrictions.
Cron can launch long-running applications as well as short scheduled jobs; inspect each task's lifetime before planning replacement.

`scheduled_php` records each task's PID, owning package, cron unit, numeric user ID,
start time and kernel start ticks. Command arguments are omitted because they
can contain credentials. Before changes, the script saves task PID/start-tick
identities separately from web-service workers. If an original task still exists
or its identity is unreadable afterwards, `verification_gap` keeps the result
unknown unless a vulnerable installation already makes it vulnerable. A reused PID with different start ticks identifies a different process. Deleted PHP files
remain independent evidence that a task needs replacement.

The readable message explains that installed PHP can be updated while an already
running task retains old code. Let original jobs finish, or arrange an
application-aware stop/rerun, then use check mode again. Restarting Apache or
PHP-FPM does not replace unrelated CLI jobs. A newer `php -v` result verifies the on-disk CLI executable. Verify existing jobs and Apache workers separately using their process identities and loaded files. `/etc/cron.d/php` is a package-owned schedule definition and is
excluded from runtime paths.
Whether stopping a service kills its children depends on its
[systemd KillMode configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html#KillMode=).
Do not use a cron service restart as an application-aware task replacement.

Pre-5.4 PHP stays unknown without a reviewed rule. The archived CentOS 5 stock
engine packages `php`, `php-cli` and `php-common` at `5.1.6-44.el5_10`, with vendor
`CentOS` and no epoch or epoch zero, are presumed vulnerable. This bounded rule
uses the [PHP2Shell advisory](https://cert.europa.eu/publications/security-advisories/2026-018/)
including end-of-life PHP and the obsolete vendor build. Exploit testing was outside this review's scope. Its package assessment records
`presumed_affected_legacy_vendor_build`, the summary explains the presumption,
and both machine markers emit `Y`. Custom revisions, other vendors and other
unreviewed builds remain unknown. CentOS 5 automatic updates remain blocked.
Classify PHP builds using their exact package revisions and reviewed version/backport rules. Previously saved results
need a fresh check to change.

`function_checksum` records POSIX `cksum` output for the loaded shell functions,
or `unavailable` if that optional command is absent. It fingerprints delivered code for run comparison even when SSH supplies source on stdin. Verify download integrity separately.
Compare equivalent invocations and Bash versions: shell formatting and other
loaded functions can affect it. Integrations must deploy the updated script and rerun the check to obtain new results.

Actual PHP output is compared with assessed engine-owner packages; unexpected
differences require manual review. Selector packages such as `ea-php-cli` can have
independent versions. Assess the launched executable's PHP version independently of the selector package revision;
a recognised fixed PHP release can establish its patch status.

The exact local Jessie revision `5.6.40+dfsg-0+deb8u23+rhphp2shell1` is recognised
for native Debian 8 PHP 5 engine packages with Debian maintainer metadata.
It contains the reviewed PHP2Shell mitigation recorded in
[the native Jessie backport evidence](security-background.md#native-jessie-backport-inputs-and-compatibility).
The revision hint identifies these as a RimuHosting backport rather than official Debian updates.
Other local revisions remain unknown. This evidence rule does not enable automatic
package updates on Jessie or add a repository.

Vendor backport rules cover matching official Debian 12/13 packages and the
Ubuntu releases in USN-8948-1/-2, using `dpkg --compare-versions`. AlmaLinux 8/9/10
rules accept the exact builds published in its advisory. RPM versions are never
compared lexically or with Debian ordering. Unlisted RPM backports, unknown
package publishers and later Alma builds below the upstream floor need further evidence.
Rocky Linux 8's x86_64 `0:7.4.33-8.module+el8.10.0+40393+c071e357`
engine packages are verified by
[RLSA-2026:87080](https://errata.rockylinux.org/RLSA-2026:87080). The
AppStream x86_64 updateinfo lists both CVEs for this exact build of `php`,
`php-cli`, `php-common`, `php-fpm` and `php-embedded`; other architectures and
custom revisions below the upstream floor still need evidence.
Rocky Linux 9's official `0:8.0.30-8.el9_8.1` engine packages are verified by
[RLSA-2026:87151](https://errata.rockylinux.org/RLSA-2026:87151), covering both CVEs.
The rule matches the distro, vendor, package name and exact revision; it does not
clear another vendor or a custom rebuild with a similar version. The readable
summary explains verified backports that retain an older upstream PHP number.
Unknown results identify the package publisher and explain when a vendor fix
has not been verified. Full revisions remain in the manifest.
Package metadata and version checks classify the reported builds. Review binary integrity and compromise indicators separately.

The exact stock AlmaLinux 10 build `8.3.31-1.el10_2` (no epoch or epoch zero)
is identified as affected for the `php`, `php-cli`, `php-common`, `php-fpm` and
`php-embedded` packages with vendor `AlmaLinux`. Its summary identifies the vendor
security-update path. Other epochs, vendors, distro majors and unlisted rebuilds
retain their existing verification rules. This rule follows Alma's published
fixed PHP 8.3 build `8.3.33-1.el10_2.alma.1`; it does not infer RPM ordering from
lexical comparison. Newer PHP `8.3.36-1.el10_2` is covered by the upstream fixes.

Sources:

- [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [Debian 109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [Debian 109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Ubuntu USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)
- [AlmaLinux builds](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
- [Rocky Linux 9 PHP backport](https://errata.rockylinux.org/RLSA-2026:87151)

## Package publishers and repository evidence

Machine record and blocker names containing `provider` refer to PHP package
publishers or repositories. Their identifiers stay unchanged for integrations.

Preserve the installed PHP package publisher during an ordinary security update. Switching
between distro packages, third-party package publishers, control-panel builds or custom
builds is a migration requiring an explicit operator choice. Never treat an
unverified source as permission to replace it with the distro default. Keep PHP
branches, extensions, configuration, application compatibility, licences and
service restarts in that migration review.

**Enforcement boundary:** Ordinary Sury APT updates use a bounded path that preserves the package publisher. Mixed native and Sury engines are assessed per package; finding Sury no longer leaves the native engines outside the update. Unversioned branch selectors remain frozen.
Versioned PHP packages can be selected. Keep `php-common`/`php-pear` at their
installed versions: an unnecessary helper upgrade can break older extension
selectors. Verified necessary upgrades of reviewed installed native libraries are included by default;
other dependency changes still block the plan. Mixed panel-vendor and Sury Debian updates are refused before
either updater runs.

Every selected Sury package must use its normal APT candidate. The candidate
must match a canonical Sury/PPA URI, expected release Origin and measured OS
suite. Its package architecture and source-package name must match the installed
package. Engine candidates must retain the PHP branch and have a reviewed fix
for both CVEs. Duplicate candidate versions from another origin are refused.
The exact approved `name:architecture=version` is passed to both simulation and
installation. The ordinary transaction cannot add or remove packages, change package publishers,
override pins or trust settings, or install an unreviewed dependency.
The existing supported-OS guard remains in place.

Packages already at their approved candidate are not requested for upgrade.
Every other inventoried PHP package receives an exact installed-version constraint
for this command. This prevents APT from advancing branch selectors through
shared `php-defaults` dependencies. No persistent pins or holds are added.
`--only-upgrade` preserves automatic/manual installation marks. Simulation still
rejects changes outside the approved upgrade set. An empty upgrade set does not
run an installation; an already-needed service restart can still proceed.

The script recognises 40 exact `amd64` EOL backport tuples: PHP 5.6, 7.0–7.4,
8.0 and 8.1 across Debian 11/12/13 and Ubuntu 22.04/24.04. Recognition requires
matching source-package identity and source revision. These are exact rules,
not minimum-version floors. See [Sury backport evidence](sury-backport-evidence.md)
for signed-index/source review, complete versions and limits. The EOL backport
can terminate a worker immediately on allocation failure and disables session
upload-progress handling.

Ordinary non-Sury APT/DNF/YUM paths still have their separate transaction guards.
Ordinary APT mode also refuses a proposed switch from non-Sury packages to Sury. Package publisher continuity checks for other vendors remain specific to their package/update paths. Panel updaters retain
the broader scope described under panel update planning. The `source_preservation`
record distinguishes the guarded Sury path from those remaining boundaries.

### Explicit equivalent-package migration

`--enable-extra-fixes --migrate-php-to-sury` permits versioned native Debian/Ubuntu PHP
packages to use the normal candidate from an already configured official Sury
source. `DP2S_MIGRATE_PHP_TO_SURY=true` is the environment equivalent of the
method flag, but still requires `--enable-extra-fixes`. Use ordinary `--fix` first.
The disruptive flag implies fix mode unless the operator explicitly selects
`--check`; check mode remains observational. Missing method consent, malformed
booleans and inconsistent option combinations exit 64 before inventory or logs.

The reviewed combinations are Debian 11/12/13 and Ubuntu 22.04/24.04, amd64.
Keep the installed binary names, branch, architecture and source-package identity.
Versioned native core packages are eligible; unversioned selectors, `php-common`,
`php-pear` and native third-party extensions remain at their installed versions.
A SAPI package (CLI/FPM/CGI/Apache) must establish the same `phpapi-*` value before
and after for every selected engine branch. The common package does not itself
provide that API marker. Exact fixed Sury engine candidates and all existing
transaction/restart safeguards still apply. Reject cPanel/Plesk-managed PHP, unknown
engine owners, missing equivalents, removals, additions and unrelated dependency changes.
Migration retains the PHP branch. Test application compatibility with the selected publisher's PHP packages.

`--add-sury-repository` / `DP2S_ADD_SURY_REPOSITORY=true` additionally permits
one matching official repository, only with both migration consents. It uses an
existing `curl` or `wget` and `gpg`; it does not install prerequisite tooling.
A dedicated source and `Signed-By` keyring are created without overwriting existing
files. New directories and key/source files are readable by APT's sandbox user.
The downloaded key's sole primary fingerprint must match the reviewed Debian
`15058500A0235D97F5D10063B188E2B695BD4743` or Ubuntu
`B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6` key. HTTPS bootstraps the key; APT
must then verify repository signatures. Global trusted keys, trust overrides,
other source definitions and PHP selectors are not changed.

The exit trap removes only the newly created source/key pair if no PHP package
installation was attempted. After any installation attempt it retains that source,
including after failure, so recovery and subsequent updates can use it. There is
no automatic package rollback. An issue-specific fix does not restore OS support.
See [resolution options](resolution-options.md) for the customer-facing choices.

The check collects source evidence without refreshing indexes, installing query
tools or contacting package publishers:

- `package_provider`: name, full revision, architecture, inferred package
  publisher, evidence type, unverified historical download origin and a static
  public package publisher URL when recognised. Namespaces take precedence over revision
  hints, then vendor/maintainer metadata. Sury-style revisions are identified
  before the Debian maintainer field; that field can be shared by Debian and
  third-party builds. Generic PPA revisions leave publisher identity unspecified; inspect the source metadata.
- `repository_file` and `repository_definition`: conventional APT `.list` and
  deb822 `.sources` paths, suites, components, enabled flags and repository
  hosts; conventional YUM/DNF configuration paths, repo IDs, URLs reduced to
  hosts and configured signature-check flags. Enabled state is reported where specified; repository reachability, effective trust and historical package origin require separate checks. Missing flags retain the
  package manager's defaults; the script does not infer their effective values.
- `apt_repository_cache`: offline APT release metadata, including Origin, Label,
  Suite and Codename where retained. `o=Debian`, `n=trixie` and a repository host
  describe different things: publisher, release and download endpoint.
- `package_repository_match`: package, version, match role and cached repository
  entry. Roles distinguish installed-version matches, candidate matches, matches
  to both and other available versions. An identical version in a cached repository entry records availability at that source. Historical download origin remains unverified. Missing matches can follow stale/removed indexes or local `.deb` installation. Cache output may reflect custom APT paths not covered by the
  conventional configuration-file inventory.
- `rpm_package_build`: name, version-release, architecture, vendor, packager,
  source-RPM filename, build time and install time (Unix seconds). The source-RPM field identifies the source package used to build the binary RPM; repository history comes from retained installation metadata. Retained YUM `from_repo` files produce `package_repository_record` with the
  exact metadata path; cache-only YUM/DNF installed-package info produces
  `rpm_repository_cache`, including `From repo` when supported. `@System` or
  `installed` is not a package publisher. These records can be missing after history or
  metadata cleanup. Old tools that lack a query simply produce `source_gap`.
- `deb_source_package`: binary name, full binary version, package architecture,
  source name, source version and evidence type. An explicit `Source` version
  preserves the distinction between source and binary-only rebuild revisions.
  An omitted source name/version falls back to the binary name/version, as
  defined by Debian package metadata. This local query needs no APT indexes.
  It identifies installed build inputs. Authenticate the corresponding source archive separately.
- `runtime_source`: an executable with no verified package owner has an unknown
  installation method. Possible installation methods include source builds, copied binaries, bundled runtimes and management by another environment; the method remains unknown.

Installed packages with explicit older release markers get a grouped customer
warning and per-package `package_release_mismatch` evidence. This is separate
from CVE state, runtime use and automatic-update eligibility. A package can be
left over from an OS upgrade and still serve websites; it is not declared unused
or removed. `config-files`/`not-installed` dpkg records are already excluded from
the installed inventory, so removed `rc` entries do not trigger this warning.

The same marker parser also recognises Debian build labels on Ubuntu and Ubuntu
build labels on Debian. These cross-distribution mismatches get a separate readable
warning, with binary/source evidence in the existing `package_release_mismatch`
record. Distribution identity takes precedence over comparing release numbers:
Debian 12 is not an older Ubuntu release. Unlabelled builds and generic maintainer
names cannot prove which distribution built a package. Cross-distribution findings
also use the existing runtime/configuration usage checks; enabled Apache PHP
configuration suppresses removal suggestions even when APT labels packages as
no longer required.

After runtime inspection, `package_release_usage` reports each older-release or mismatched
PHP installation as `running`, `configured`, `no_running_use_observed` or
`unverified`. Package namespace/branch groups keep native `php8.2`, EasyApache
`ea-php82` and CloudLinux `alt-php82` separate; CLI/FPM/common/extensions of the
same installation share usage evidence. This does not claim each extension is
loaded. Runtime ownership and path matches include CLI jobs launched by cron,
FPM workers and mapped Apache PHP modules. Debian 8 executable names `php5-fpm`
and `php5-cgi` are recognised alongside newer `php-fpm8.4`/`php-cgi8.4` names.
Enabled `/etc/apache2/mods-enabled/php*.load` and
`/etc/apache2/conf-enabled/php*-fpm.conf` references suppress removal suggestions,
including broken enabled links that still require configuration review.

Only a completed root process inspection with no current blockers, unknown
runtime ownership, missing runtime paths, separate-environment review, pending
restart or panel-managed PHP can support `no_running_use_observed`; at least one
runtime of that installation must have identified package ownership. Otherwise
the result remains `unverified` unless positive running/configuration evidence
exists. This reporting never changes CVE state or update permissions.

The process snapshot covers the script's recognised PHP/web processes. It does
not audit all nginx/panel configuration, user jobs, application code or reverse
package dependencies. The customer suggestion therefore says **no running use
was found**, asks whether websites, scheduled tasks and other packages still need
that PHP installation, and suggests reviewing the package manager's proposed
removals. It neither declares the packages unused nor performs their removal.

The comparison reuses installed binary versions and the exact matching
`deb_source_package` record when a binary version has no marker. Source fallback
matches binary name, version and architecture. No extra package, repository or
network query is needed. Supported labels are native Debian `+deb8u12`/`~deb12u1`,
Sury `+debian12~1`, Debian `~bpo12+1` (which takes precedence over the base revision),
legacy `~bpo60+1`/`~bpo70+1` (Debian 6/7), explicit Ubuntu release labels such as `ubuntu0.22.04.1` or `+ubuntu22.04.1`, and
`.el8`/`~el8` RPM build labels on Enterprise Linux systems. Ubuntu `ubuntu1.5`
is a package revision, not an OS release. Numeric OS identity is required;
Debian/Enterprise Linux compare major releases, Ubuntu compares its release number.
Current or newer labels do not produce this older-release warning.

[Debian binary control fields](https://www.debian.org/doc/debian-policy/ch-controlfields.html#debian-binary-package-control-files-debian-control)
do not require a target-distribution field. The
[Debian Developer Reference](https://www.debian.org/doc/manuals/developers-reference/pkgs.html)
describes `+debXuY` release numbering; [Debian backport conventions](https://wiki.debian.org/BuildingFormalBackports)
include both modern and historical target labels. Release labels identify the build
naming convention; they do not authenticate download history or establish that
all unlabelled packages belong to the current release. The script does not guess
from a PHP branch, maintainer, build date or a missing APT-cache match. Custom
version labels can retain earlier release markers and need administrator review.

Package-cache semantics: [APT policy](https://manpages.debian.org/bookworm/apt/apt-cache.8.en.html),
[APT cache paths](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html#DIRECTORIES)
and [DNF cache-only queries](https://dnf.readthedocs.io/en/stable/command_ref.html#options).

APT binary cache writes are disabled for policy queries. YUM/DNF origin queries
use cache-only mode, disable plugins and redirect their logs into the private work
directory; unsupported query options leave an evidence gap. Repository credentials
are omitted: URL userinfo, paths, queries and fragments are removed, including
subscription identifiers embedded in paths. Authentication/proxy fields and
inline signing keys are not collected. All observations remain manifest data,
not additional per-module readable warnings. A metadata failure does not change
the PHP vulnerability verdict; security-fix assessment uses the package revision and reviewed fix rules.

For fleet planning, group engine packages by package publisher hint plus repository host,
suite and RPM repo ID; retain the full package revision, architecture and evidence
level. Investigate conflicts rather than assigning a VM one package publisher: a VM can
mix distro PHP, Sury streams and panel-internal PHP. Check candidate package publisher
continuity, support entitlement, architecture and exact fixes for both CVEs before
choosing a future update recipe.

Failed Debian package-state preflights retain redacted `package_audit` diagnostics.
`package_audit_status` records name, installed version, architecture and dpkg status
for audit-named packages and other nonconfigured packages. `package_audit_metadata`
reports whether their standard package file lists and checksum files are readable.
These observations distinguish pending configuration from missing metadata; they
do not repair packages or relax the preflight. `package_audit_gap` records a failed
or unrecognised status query. No package metadata contents are copied.

During an update attempt, `apt_candidate_policy` records the exact per-package
policy used for selection. `apt_candidate_metadata` retains only identity,
provided APIs and dependency/conflict fields, including continuation lines.
`apt_candidate_api` compares the installed and proposed PHP API when migration
reaches that check. Rejected queries retain their operation, exit status and
URL-redacted stderr in `apt_candidate_error`. These records are emitted before
the relevant rejection, where that query was reached. Check mode does not run
fix-only queries or refresh repositories to obtain more evidence.

### Package publishers to investigate

Package publisher research checked 23 October 2026. These links identify packaging/support
options. Obtain approval for repository changes and verify the selected package build before installation.

| Package publisher | Relevant scope and caveat |
| --- | --- |
| [Sury / ondrej PHP](https://sury.org/) | Debian PHP repository and Ubuntu `ondrej/php` PPA; alternate parallel branches. The revision format supplies a package publisher hint; repository identity and support entitlement require their own checks. |
| [Freexian PHP LTS](https://www.freexian.com/lts/php/) | Commercial extended PHP security maintenance for specific Debian/Ubuntu and PHP combinations, working with the Sury maintainer. Check its platform/architecture matrix and subscription terms. |
| [Remi](https://rpms.remirepo.net/) | PHP RPM repositories and stream/parallel-install choices for supported RPM platforms. Check its configuration wizard and release-specific support; archived repositories alone do not supply ongoing fixes. |
| [TuxCare / alt-PHP](https://docs.tuxcare.com/els-for-runtimes/php/) | Commercial maintenance of EOL PHP with distro/PHP/architecture-specific availability. CloudLinux also uses the alt-PHP namespace; check supplier metadata and licence entitlement separately. |
| [Ubuntu security / Pro](https://ubuntu.com/security/notices) | Distro updates and extended support where the package/release is covered; ESM entitlement is separate from merely having an Ubuntu package. |

TuxCare publishes trackers for [109618](https://tuxcare.com/cve-tracker/cve/details/cve-2026-109618/)
and [109619](https://tuxcare.com/cve-tracker/cve/details/cve-2026-109619/). Verify the installed package against the exact product advisory and build; record the specific product and support entitlement. Panel integrations need their own recipes:
[cPanel's TuxCare ELS documentation](https://docs.cpanel.net/knowledge-base/third-party/tuxcare-extended-lifecycle-support-els-php/)
and [Plesk's extension](https://www.plesk.com/extensions/tuxcare-php/).
None of these discoveries clears an installed package without an assessed fix rule.

## Resolution method plan

Methods reviewed 27 October 2026. This section distinguishes implemented bounded
methods from unresolved setup-specific work. A reported blocker is a diagnosis, not a repair recipe.
Test application compatibility and verify all affected server components after the selected method runs.

### Routine and disruptive operations

`--fix` covers a reviewed update of the existing PHP packages, package publisher, branch
and architecture, with verified service replacement. These updates can still
interrupt requests or workers. Plan for request or worker interruption during routine updates.

`--enable-extra-fixes` permits only a separately selected method. Persistent repository
or trust changes, package publisher changes, extra dependency changes and package-state
repairs belong here. The flag never bypasses a failed safety check.
Waiting, read-only diagnosis and correcting an inventory defect do not require it.

### Blockers and feasible next steps

| Blocker | Reliable automated path and next step | Classification |
| --- | --- | --- |
| Missing OS update recipe | Verify a maintained same-release, same-architecture package route first. Existing Sury on reviewed Debian 11 is one implemented case. Otherwise investigate a cohort-specific backport or plan OS/server migration. | Routine where the existing package publisher has a reviewed fix; otherwise disruptive or outside this script. No universal repair. |
| No approved candidate | Diagnose missing security sources, holds, entitlement, unavailable builds and unreviewed fix evidence separately. Retry the current package publisher first; consider the explicit Sury method only when equivalent packages exist. | Diagnosis first. Obtain approval for the specific repair or migration after diagnosing candidate availability. |
| Repository access or trust | Retry a transient failure within a bound. A persistent repair must identify one known vendor key or same-release source definition and verify its replacement. DNS, TLS, subscription and retired-source failures need different remedies. | Persistent source/trust repair is disruptive. No generic repair-all method. |
| Incomplete package configuration or metadata | Read exact package states and audit categories. Distinguish pending configuration, missing checksum metadata and genuine database damage. Configure or reinstall only a reviewed package set. | Disruptive repair; unrelated broken packages need a separate system-maintenance procedure. |
| Candidate package publisher unverified | Retain policy errors; identify suite, source identity and every origin of the exact candidate. A recognized parser defect can be fixed without changing package policy. Wrong-suite or ambiguous candidates stay blocked until their source definitions are reviewed. | Diagnosis is routine. Source edits or migration are disruptive. Never relabel a candidate as trusted. |
| Script transfer or launcher failed | Fix the runner to capture transfer and exit errors and invoke an installed compatible Bash. Retry check mode first. Do not change the customer's login shell. | Runner correction; no PHP repair flag. |
| Restart mapping unavailable | Add support only for an identified standard package service with verified configuration. Application-specific Supervisor workers still need the documented stop, fix, restore and check procedure. | Verified standard restarts are routine but interrupt service. Custom application shutdown needs a separate procedure. |
| Package-manager lock | Wait for a bounded time, then repeat inventory and preflight. If still busy, report the owner and stop. Never delete a lock or kill the other package job. | Waiting is not disruptive. |
| Insufficient space | Report affected mounts and distinguish reclaimable cache from a disk/filesystem needing growth. Do not delete arbitrary files or cached recovery packages. | No general automatic repair. Disk growth or selected cleanup needs a separate reviewed procedure. |
| Fixed host PHP with isolated PHP unverified | Identify the container/chroot/image and its deployment owner. Update or rebuild that environment, then verify its PHP separately. | Disruptive application deployment outside the host-package method. Repeating host updates does not fix it. |
| Runtime or package ownership unverified | Extend detection for a proven standard package layout. Custom builds need their own reproducible update and restart procedure. | Detection can be routine; arbitrary runtime replacement is not supported. |
| Dependency transaction exceeds scope | Avoid unnecessary helper/selector updates. Normal APT fixes include verified necessary upgrades of reviewed installed native libraries from matching official OS sources. Other dependency changes need manual review. | Removals, additions, replacements and broad system upgrades remain separate decisions. |
| Partial update or restart | Reinventory package state and running workers before retrying. Verify applications and continue only from the observed state. Do not infer rollback from a failed command. | Recovery; classify each remaining operation separately. |
| Panel, CageFS or other isolated PHP | Use a verified vendor procedure for that product, version and entitlement. Check the host and isolated copies afterwards. | Potentially broader than PHP; no blanket permission to edit panel or tenant configuration. |
| Other incomplete inventory | Retry a transient process race; retain unreadable evidence as unknown. Diagnose persistent failures before selecting an update method. | Read-only diagnosis. No force-clear option. |

A missing `md5sums` file is different from an unpacked package awaiting
configuration. Old packages may lack checksum metadata. Select a repair from the exact package state and audit category; keep unrelated libraries outside that repair. Review that
classification against real package states and historical fixtures first.
Hashes of current files record their present contents. Compare them with authenticated package metadata when verifying original package contents.
See [Debian package metadata](https://www.debian.org/doc/manuals/debian-handbook/sect.package-meta-information.en.html)
and [checksum-file scope](https://manpages.debian.org/bookworm/dpkg-dev/deb-md5sums.5.en.html).

### Default native-library upgrades

Ordinary APT `--fix` includes upgrades of reviewed installed native amd64 libraries:
`libpcre2-8-0`, `libonig5`, `libargon2-1`, `libxml2`, `libzip4`/`libzip5`
and `libsodium23`. Each upgrade needs versioned, non-alternative PHP dependency
proof, including transitive edges, plus matching binary/source/architecture,
a newer normal candidate exclusively from matching official OS sources and no
library hold. Pin exact approved candidates, repeat the simulation and recheck
scope, versions and architecture before installation. Additions, removals,
replacements, downgrades, RPM and base-system library changes remain excluded.
Check-mode assessments use cached metadata only and perform no package mutations.
See the [operator limits and risks](resolution-options.md#allow-the-native-libraries-php-needs).

### Method flags

For an operator deciding whether to grant permission, use the
[option effects and risks](resolution-options.md#compare-the-options). It explains
file changes, package/key download sources, benefits, interruption risks and recovery.
The table below describes implementation limits. Package setup scripts and applications still require verification on the target server.

The options below are implemented. Each method has a bounded supported subset;
selecting an option does not authorize general system repair.
Every Boolean method defaults to false and requires command-line
`--enable-extra-fixes`. Environment names match their action flags with `DP2S_`
and uppercase underscores. The two repository methods are mutually exclusive,
including selections combined across environment and command line. Explicit
`--option=false` overrides its environment default. Private `P2S_` settings and
manifest method identifiers retain their existing internal names.

| Method option | Environment setting | Status and limit |
| --- | --- | --- |
| [`--migrate-php-to-sury`](resolution-options.md#use-sury-packages) | `DP2S_MIGRATE_PHP_TO_SURY=true` | Implemented. Keep reviewed package names, PHP branches, architecture and extension APIs; use authenticated normal candidates. |
| [`--add-sury-repository`](resolution-options.md#add-the-sury-or-ppa-repository) | `DP2S_ADD_SURY_REPOSITORY=true` | Implemented. Also requires migration consent; add only the matching official source and verified dedicated key. |
| [`--refresh-sury-signing-key`](resolution-options.md#repair-the-existing-sury-signing-key) | `DP2S_REFRESH_SURY_SIGNING_KEY=true` | Refresh only the standard package-owned Debian Sury signing keyring, with a verified fingerprint and persistent backup. No source rewrite; custom and extrepo layouts stay blocked. |
| [`--add-os-security-repository`](resolution-options.md#add-a-missing-native-security-source) | `DP2S_ADD_OS_SECURITY_REPOSITORY=true` | Add only matching main security metadata using the existing packaged archive keyring. No Virtualmin or general source rewrite method exists. |
| [`--configure-pending-php-packages`](resolution-options.md#finish-pending-php-package-configuration) | `DP2S_CONFIGURE_PENDING_PHP_PACKAGES=true` | Only reviewed unpacked/half-configured versioned PHP packages with matching repository and package publisher identity. Explicit PHP-only triggers can finish; unrelated pending state or trigger chains remain blocked. No blanket pending configuration is used. |
| [`--reinstall-php-same-version`](resolution-options.md#reinstall-the-exact-php-package-version) | `DP2S_REINSTALL_PHP_SAME_VERSION=true` | Reinstall identified PHP packages from authenticated exact installed-version normal candidates with unchanged package publisher, source and architecture. The simulation must contain every target and no dependency/version changes or unrelated configuration. Missing archives and unrelated legacy libraries stay blocked. |

`--wait-for-package-lock SECONDS` / `DP2S_WAIT_FOR_PACKAGE_LOCK_SECONDS`
has its [operator explanation](resolution-options.md#wait-for-another-package-operation) in the option guide. It
waits before fix operations on APT systems with `fuser`. The bound is 0–600 seconds. Default zero preserves current behavior.
The open-file probe is conservative; a file can exist without being held. Unknown
probe results stop an explicitly requested wait. No locks or processes are removed.

Package configuration runs maintainer scripts and triggers. APT dependency repair
can select packages outside PHP, and a simulation does not lock package state.
Do not append `dpkg --configure -a` or `apt-get --fix-broken install` to normal
updates. Revalidate package state before applying any reviewed repair.
See the [dpkg configuration contract](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html)
and [APT repair and simulation behavior](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html).
Repository recipes must retain [APT authentication](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html).

### Function names and review boundaries

Name method-specific functions `p2s_disruptive_<method>_<operation>`.
The Sury helpers are now `p2s_disruptive_sury_validate_equivalents`,
`p2s_disruptive_sury_add_repository` and
`p2s_disruptive_sury_cleanup_added_repository`.
They form one contiguous group in the delivered script.

The package methods are `p2s_disruptive_package_configure_pending_php` and
`p2s_disruptive_package_reinstall_exact_php`. Repository methods dispatch through
`p2s_disruptive_repository_apply_recipe`. The shared-library approval function is
`p2s_package_deb_dependency_approve_plan`; its actual installation uses the
shared APT backend and requires fix mode after the pinned transaction checks.

Keep `p2s_package_deb_update` and the package candidate/transaction validators
shared. They serve routine and explicitly enabled methods, so a `regular` prefix
would misdescribe their scope. A future entry point serving only ordinary updates
can use `p2s_regular_<backend>_<operation>` when that separation is needed.
Do not duplicate transaction code or add wrappers only to manufacture prefixes.
Keep `P2S-MUTATION` markers and enforce permissions at the mutation boundary.
Function names are a review aid, not authorization.

### Check recommendations and recovery

`p2s_fix_recommend_options` evaluates installed/cached evidence after normal local
preflight. A cached call to the shared APT backend sets `P2S_MODE=check`, disables
binary cache paths, skips refresh and source addition, and returns before install.
Alternative assessments run in subshells and do not change current blocker keys.
A proven dependency plan recommends ordinary `--fix`, including required native-library upgrades. Standard Sury key
replacement requires local expiry/fingerprint evidence before recommendation.
Missing-source suggestions remain explicitly conditional on future candidates.

After an unresolved fix, plain `--fix` recommendations are suppressed in both readable output and machine
records. Fresh checks can still recommend a specific additional repair. When no
additional method is identified, the result directs the operator to the detailed
log, remaining PHP findings and a check after resolving the blocker.

Repairs may handle only their matching persisted blocker keys. Other OS, runtime,
service or ownership blockers cannot be cleared by selecting repair flags. The
repair path repeats the shared space, service and hold checks before mutations.
Fresh audit exit/stderr and complete status evidence must be usable. Successful
repairs clear old blocker observations only by collecting inventory again.
Newly activated verified services and processes join the original restart scope.
Failed package mutations still reach service replacement and final verification.
Repository/key repair changes and key backups persist after later failure.
No automatic package rollback is provided.

### Remaining validation and coverage work

1. Refine package-audit categories and candidate diagnostics; fix runner failures.
   Retry checks and measure remaining blockers before estimating new coverage.
2. Validate routine fixes and updates from existing package publishers on disposable matching
   systems, including old interpreters. Verify fixed packages, worker replacement
   and application health. No source changes are needed for this stage.
3. Extend repository repair only through named recipes from captured evidence.
   Test valid and wrong fingerprints, foreign suites, modified definitions,
   failed writes, repeated runs and cleanup. Preview the exact changed files.
4. Validate the existing explicit Sury migration on disposable supported suites.
   Keep the present equivalent-package and dependency limits. Check applications
   before using the method on a customer server.
5. Validate the PHP configuration/reinstallation methods on matching disposable
   systems before customer canaries. Test unrelated pending packages and trigger escape, missing exact
   archives, changed state, configuration retention and partial failure.
   Consider dependency expansion only after these smaller methods are exhausted.
6. Investigate native backports by exact OS/PHP/architecture cohort when no
   maintained equivalent route exists. Build outside customer hosts, authenticate
   source and outputs, review both patches, and verify SAPIs, extension ABI,
   dependencies and restart behavior. Do not offer a generic backport flag until
   an exact recipe has passed matching-system tests. Otherwise use a separately
   planned OS, PHP-branch or server migration.

For every method, report diagnosis, selected operation, remaining prerequisites,
actual package/service changes and final verification separately. State when no
verified automatic repair exists. After a successful command, verify the affected PHP installations and applications.

## Automatic fix scope

The ordinary update strategies use APT for recognised Debian/Ubuntu releases,
DNF/YUM for recognised RPM-based releases, the existing Sury source when installed
Sury PHP is detected, and the recognised cPanel/Plesk vendor updater where required.
They do not add repositories, switch PHP package publishers or perform an OS upgrade.
The separately opted-in Sury migration is described above.
Each path still requires its package, transaction and restart checks to pass.
A missing update recipe means this script has no implemented procedure for that OS release; check package publisher support and maintained package routes separately. No approved candidate means no package met this script's checks in the configured sources. An unverified build has an unknown backport status and needs exact revision or build evidence.
Keep these limitations and the specific blockers factual in public messages;
do not assign the work to a hosting provider or an unspecified support service.
Separately, the final unresolved result offers an optional no-cost, no-obligation
RimuHosting investigation and mitigation/migration report, including for servers
hosted elsewhere. The manifest and investigation are coordinated afterwards;
changes or further work require separate agreement. Emit this offer only once
per run, after a final vulnerable or unknown result, and omit it for clear results.

Check mode reports a separate automatic-update assessment without changing the
CVE result. `not_needed` means no PHP update is needed within the checked scope.
`blocked` means the current script's local prerequisites fail or inventory has
already identified a blocker. `eligible_to_attempt` means the inventory identifies
vulnerable PHP, has no unresolved inventory gaps, and passes local prerequisites.
`unknown` means no local blocker was found and fix feasibility remains unresolved.
These assessments appear as readable messages and `dss:manifest:patchability`
records, including the inventory state and evidence limits.

The shared read-only preflight checks root access, command supervision, available
disk space, package-manager availability and supported service configurations.
For ordinary Debian-based PHP updates, check mode also checks dpkg consistency
and PHP package holds. Panel paths additionally require a recognised panel version
and an installed vendor updater. Fix mode repeats these checks rather than
trusting a saved assessment.
Check mode does not refresh repository metadata, run a package transaction or
restart services. Available fixed packages, support entitlements, repository
access, dependency conflicts and successful service restarts remain unconfirmed
until an update attempt. A missing disk-space tool prevents an optimistic
assessment, though the existing fix path still permits an attempt without it.

Search `dephp2shell.sh` for `P2S-MUTATION` to trace package/cache writes and service
restarts from the fix entry point through dispatchers to the actual commands.
Routine work files, logs, locks and supervision of the script's own subprocesses
are excluded from these markers. The RPM test transaction is marked because it
can download packages and write caches without installing PHP.

Fix mode checks privileges, free disk space, OS support, package inventory and
service/configuration prerequisites before requesting installation. APT also
checks incomplete dpkg operations and held PHP packages. Failed metadata refresh,
including APT warnings that returned zero, prevents installation. Errors explain
repository, network/DNS, signature and subscription possibilities.

The ordinary APT path simulates an upgrade of the explicit installed PHP package set. Additional
packages and removals require manual review. The real command uses `--only-upgrade`
and `--no-remove`, retains local configuration, and requests noninteractive
operation. It does not run a general `dist-upgrade`.

The ordinary RPM path prefers DNF, then YUM, uses signature/TLS checks, and runs a test transaction.
Only recognised English DNF4/YUM plans updating the selected PHP packages proceed.
Dependency additions, removals, unknown plan formats and failed test transactions
require manual review. Metadata refresh and package operations have time limits.
DNF's successful `Nothing to do.` result is recorded as `no_updates`, with no
install requested. It permits pending restart work; otherwise an unverified build
gets a no-update-candidate warning. The installed build retains its assessed fixed, vulnerable or unknown status when no upgrade is available.
Automatic mutation requires a timeout implementation with a kill-after option;
alternatively, an embedded Bash/sleep watchdog supervises the command's process
group, with TERM followed by KILL. Perl is an inspection-only last resort when
neither supervisor is available. A command that handles TERM and exits zero still
counts as timed out. Children that deliberately detach into another process group
remain outside this supervision, as with conventional timeout utilities.

Supported active systemd units and unambiguous traditional init scripts can be
restarted. PHP-FPM and Apache configuration checks run first. Apache is selected
only when a PHP module is mapped into it. FPM validation uses active master
executables, not every installed FPM version or matching package filename (which
can include manual pages). It uses the config path in the native master-process
title, or supported config options retained in NUL-separated startup arguments.
Unreadable executables/configs, relative paths and unrecognised arguments require
manual review. A rewritten process title does not preserve all original php.ini,
prefix or environment overrides; custom service setups need additional operator
validation. These checks do not recreate arbitrary service startup environments.
Validation arguments, exit status (124 for timeout), and output are kept under
`dss:manifest:configtest_*`, with URL and common credential diagnostics redacted.
No package installation or service restart is attempted after failed validation.
A blocked run suppresses unchanged readable inventory messages while retaining
both raw manifests and any new warnings. Its final message distinguishes no
installation/restart attempt from an attempt that may have partially changed the
server. nginx start times are reported, but
nginx is not restarted as a substitute for replacing PHP workers. After a real
transaction, service status and disappearance of the saved old workers are
checked, including after a partially failed installation. A failed refresh or
simulation alone does not trigger restarts. Deleted executable/module mappings
prevent a clean result until resolved.

Restart requirements affect the PHP CVE result only for PHP executables and
web-server processes that map PHP modules. A replaced nginx or Apache executable
with successfully inspected mappings and no PHP module produces a separate
maintenance advisory. It does not force an unknown PHP result or trigger a
PHP-FPM restart. Failed/unreadable map inspections remain unknown; deleted PHP
modules and PHP executables retain their restart requirement. Anonymous mappings such as `/dev/zero (deleted)` are excluded from PHP replacement requirements.
If a process disappears during inspection, its exit is recorded without creating
a verification gap. An unreadable process that remains present still needs review.
`web_restart_advisory` preserves each affected PID, process name and executable;
readable advisories are grouped by name/path. `php_restart_pending` records
deleted PHP-serving executables. nginx mapping a PHP module requires manual
restart planning rather than being silently treated as an ordinary reverse proxy.

The script does not configure alternative repositories, install Sury, switch module
streams or website PHP selections, convert distributions, force dependency repair,
reboot or automatically shut down applications. Vendor panel installers manage
their own component dependencies; their resulting packages and services require
verification. The Plesk operation is not constrained by the ordinary PHP-only
transaction checks. An unsuccessful fix can have changed packages; retain its output
and inspect package-manager state before retrying. A surviving lock directory
`/var/run/rh-php2shell.lock` requires operator review before removal. The legacy
lock name is retained so old and renamed scripts cannot patch concurrently.

## APT locks and index-download space

Before check/fix results and before fix operations, the script warns when an
APT/dpkg kernel write lock has an owner running for at least one hour. It matches
`/proc/locks` device/inode records to the four standard APT/dpkg lock paths.
`package_manager_long_running_lock` records the path, PID, parent PID, process
name and elapsed runtime. Arguments are omitted. Runtime is measured from process
start; lock acquisition time is unavailable. The warning includes commands to
recheck the owner and send `kill -TERM PID` after confirming it is stuck. No job
is stopped, no lock file is removed and warning collection leaves update eligibility
unchanged. Missing/unreadable process or lock metadata yields no age warning;
APT/dpkg still enforce locking. Existing wait and failure diagnostics remain active.

`package_manager_busy` identifies lock contention separately from repository or
network failures. When APT reports a numeric holder PID, `package_manager_lock_holder`
records its parent, elapsed time, UTC start time, state and command name when `ps` supports
that query. `package_manager_lock_service` records a readable service association.
Arguments are omitted because they can contain credentials. Inspect the owner's age and progress before stopping a job; the lock record identifies its current owner.
The script never kills competing package operations or removes lock files.
See the [Debian dpkg lock guidance](https://wiki.debian.org/Teams/Dpkg/FAQ#What_can_be_done_when_the_dpkg_lock_is_held.3F).

`disk_full` identifies write failures caused by space, inode or quota exhaustion.
Actual metadata downloads and unpacked files can require more space than the preflight minimum.
APT `Contents` maps support file searches, for example through apt-file. They
can be hundreds of megabytes each and are not required to select PHP updates.
The fix refresh uses command-only `DefaultEnabled=false` settings for standard
Contents targets and disables translations. Required package indexes and trust
checks remain enabled. Source files and persistent APT settings stay unchanged.
Explicit per-source targets and custom hooks can still request extra downloads.
See the [apt-file disable example](https://sources.debian.org/src/apt-file/3.4/examples-apt-conf/60disable-contents-fetching.conf).
`apt_refresh_scope` records the selected defaults. Check mode does not refresh indexes.

APT refresh blockers distinguish a missing signing key (`NO_PUBKEY`) from other
signature failures, including when APT exits successfully with warnings. Command
records retain repository hostnames and signing errors; URL credentials, paths
and queries remain redacted. APT can retain old indexes for a failed repository
even when other lists are current. The script blocks installation until that
repository is repaired or deliberately disabled if no longer needed.

Shared package diagnostics also report `repository_failure_source`: the failing
URL host or quoted RPM repository ID, plus possible source files from the current
redacted inventory. The customer message names the host or repository ID and
possible source files in plain language. For a Webmin connection refusal, this
identifies `download.webmin.com` and a matching source such as
`/etc/apt/sources.list.d/webmin.list`; the connection error remains in the redacted
update log. Only failure lines supply identities; successful `Hit`/`Get`
lines do not implicate other repositories. Host matches can include multiple
sources or disabled definitions. Confirm the repository and suite before changing
a file. Unmatched mirrors or custom configuration paths remain unidentified.

HTTP 404 classification requires an explicit missing-file status (`404 Not Found`,
`HTTP Error 404`, or `Status code: 404`), not a substring of a download size or
APT item number. APT `Hit`/`Get`/`Ign` progress rows cannot supply failure identities.
For example, `Get:4 ... Packages [3404 B]` is a successful 3,404-byte download.
A local module/file “not found” diagnostic without HTTP context is not a repository
404. Real warnings include up to three distinct URL-redacted matching diagnostic
lines; `repository_failure_source` continues to identify possible host/source-file
matches. The original `repository_failure|http_404` classification remains intact.
These diagnostics do not change package/update eligibility or retry behavior.

Old partial Contents downloads can still occupy space after this change.
An operator can inspect and remove those regenerable files while APT is idle.
Do not delete lock files or assume `apt-get clean` removes index-list downloads:
that command clears the package-archive cache. Automatic cache cleanup, journal
vacuuming, disk growth and stopping scheduled APT jobs are outside this recipe.

## Package pins, exclusions and dependency failures

APT preferences can block a security update even when the correct repository and
newer PHP versions are visible. A reported version priority of `-1` prohibits
installing that matching version; the repository row underneath can still say
`500`. Inspect APT preferences for pins separately from the `apt-mark showhold` result.

One observed Virtualmin setup had this rule in
`/etc/apt/preferences.d/debian-virtualmin-restricted-packages`:

```text
Package: libapache2-mod-php*
Pin: release *
Pin-Priority: -1
```

With mod_php already installed, its exact-version dependency on `php8.2-common`
prevented other PHP components from upgrading. APT proposed removing the Apache
module instead. `--no-remove` correctly rejected that plan. The same APT mechanism
applies to Ubuntu and other APT-based systems; it is not specific to Virtualmin.
A pin can also freeze a version, favour another package publisher or release, or affect
unrelated security updates. Read the pin's package and release selectors to determine its effective scope.

The script reports `apt_package_candidate` and `apt_version_priority` separately
from repository matches. Installed PHP packages with no candidate produce a
readable warning. A negative priority strengthens the policy explanation, but
missing repositories or stale metadata can also cause missing candidates.
Cached candidate gaps make check-mode patchability uncertain, without changing
CVE state or preventing the fix from refreshing metadata. Failed APT simulations
collect policy again from the refreshed cache. No diagnostic query downloads metadata.

`package_policy_file`, `apt_pin`, `rpm_policy` and `rpm_versionlock` identify
standard configuration paths and selected policy fields. Global/wildcard rules
are included. RPM reporting covers excludes/includes, priorities, plugin enable
flags, version locks and stored module-stream selections. These are possible
restrictions, not a calculation of effective DNF/YUM policy. DNF `info` and similar
queries do not apply versionlock filtering even when update transactions do.
Custom configuration/lock paths and complete policy precedence are not evaluated.
`package_policy_scope` and `package_policy_gap` record these limits. Each collection
reads at most 64 files, 200 lines per file and 512 characters per reported line.
Truncation and unreadable files are identified. Password/proxy fields are omitted;
URLs are redacted. No plugins run for the static policy inspection.

`p2s_package_rpm_stream_guidance_report` adds manual stream advice for native
Rocky/Alma 8 PHP 7.2/7.3/8.0, native Rocky/Alma 9 PHP 8.1, and existing Remi
PHP 7.x/8.0/8.1. It requires a unique installed `php-common` engine-family
record, no detected hosting panel, and no blocker other than `no_candidate`.
This advice leaves CVE state and automatic-fix eligibility unchanged. A verified
same-branch backport can already fix these CVEs even on a retired stream.

The query uses cached DNF4 module metadata, disabled plugins and private log paths.
It never refreshes metadata in check mode. A unique enabled stream must match the
installed provider and PHP branch. Only reviewed destinations actually present
and not disabled in that cache are offered: native EL8 7.4/8.2 (7.4 only from
7.2/7.3), native EL9 8.2/8.3, or existing Remi 8.4. Missing, failed or ambiguous
metadata produces an instruction to refresh/review the module list instead.
`php_module_cache` and `php_module_gap` retain the evidence; additive
`php_stream_migration` records carry preview/apply command text, architecture,
cached availability, `fixed_candidate=not_queried` and `manual_only`. They are
not `fix_recommendation` records and expose no automatic migration option.

The printed `dnf --refresh --assumeno module switch-to php:...` previews a
transaction and declines confirmation; it can refresh local metadata/cache.
The separate apply command remains interactive. DNF's switch-to can remove old
stream packages missing from the destination and update modular dependencies;
review its whole plan. Remi uses `/common` per its vendor procedure. No repository
is added. See [manual stream migration](resolution-options.md#move-a-retired-rockyalma-php-stream).
Published destination fixes do not prove the server's current candidate; rerun
`--check` after installation and service replacement. Compatibility and custom
Apache handler configuration need application-specific review.

Research checked 2026-10-29: native EL8 PHP 7.4 is a Full Life vendor stream,
not retired merely because upstream PHP 7.4 is EOL; native EL8 8.2 is maintained
to May 2029. Native EL9 PHP 8.0 also has Full Life status, so this advice does
not label it retired from its upstream number. Alma published same-branch
PHP2Shell fixes even for retired EL8 PHP streams. Sources:

- [RHEL Application Streams lifecycle](https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle)
- [AlmaLinux PHP2Shell response](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
- [Rocky AppStream update metadata](https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/repomd.xml), RLSA-2026:87080 (7.4) and RLSA-2026:87073 (8.2)
- [DNF module switch-to](https://dnf.readthedocs.io/en/latest/command_ref.html#module-command)
- [Remi's fixed stable releases](https://blog.remirepo.net/post/2026/10/22/PHP-version-8.2.35-8.3.36-8.4.27-8.5.12)
- [Remi's EL8/9 PHP 8.4 switch procedure](https://blog.remirepo.net/post/2024/12/18/Install-PHP-8.4-on-Fedora-RHEL-CentOS-Alma-Rocky-or-other-clone)

Do not remove pins, clear version locks, disable exclusions or switch module streams
automatically. These may protect the application's handler, package publisher or compatibility.
If an installed Apache PHP module is still used, review a narrowly scoped policy
change and simulate updates to the matching installed PHP package set without removals.
If it is unused, verify every site's PHP handler before planning removal and
retaining/restoring the desired panel policy. FPM and mod_php can serve different sites on the same server; inspect every site's PHP handler. These policy or handler changes require operator review.
The `php` metapackage is not the engine version; `apt-get upgrade php` can also update
many unrelated system packages. Use explicit installed package names for a PHP-only plan.

A successful version/configuration command can still print an extension-loader
warning, such as `pdo_mysql` reporting an undefined symbol. The script reports these
as `php_startup_warning` and a readable warning, separately from CVE state.
After an installation attempt, active service configurations are validated again
using the newly observed FPM masters. A failed validation prevents a clean fix result.
The `-n` engine version probes intentionally skip php.ini and configured extensions;
test applications and CLI extensions with their actual configuration after maintenance.

References, checked 24 October 2026 NZDT:
[Debian APT preferences](https://manpages.debian.org/trixie/apt/apt_preferences.5.en.html),
[Ubuntu APT preferences](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html),
[DNF configuration](https://dnf.readthedocs.io/en/latest/conf_ref.html),
[DNF versionlock](https://dnf-plugins-core.readthedocs.io/en/latest/versionlock.html),
and [Virtualmin PHP execution modes](https://www.virtualmin.com/docs/server-components/php-execution-modes/).

## Panel update planning

Fix mode supports these panel paths when the OS, panel version, installed updater
and remaining safety checks permit an attempt. Check mode inventories the panel
and updater without running the updater. A panel directory can be a leftover. Check its installed updater, version and support status before choosing a panel update path.

| Panel | Automatic fix path and scope |
| --- | --- |
| cPanel 110 and later | Run the installed `upcp --security` without `--force`, then update the explicit installed website PHP package set, including EasyApache. Exclude `cpanel-php*` and `sw-engine*` from that ordinary package pass: the panel updater owns those internal components. Respect update preferences. Check the installed cPanel release's security-support status before planning the update. |
| Plesk 18 | Run the installed `plesk installer --select-release-current --upgrade-installed-components`. Do not follow it with an ordinary APT/DNF/YUM PHP transaction. The installer can update databases, web servers and other installed components. This is broader than PHP-only maintenance. |
| Virtualmin | Permit the ordinary explicit PHP package update and supported service restarts. Virtualmin's presence alone is not a blocker or a verification gap. Check each virtual server's PHP selection before removing or migrating old PHP branches. |

`--select-release-current` retains the selected Plesk release instead of requesting
the latest release. It does not make the component update security-only or promise
that every dependency, package publisher or PHP branch remains unchanged. The ordinary panel path does
not rewrite package sources or website PHP selections. Vendor dependency decisions
and enabled-repository candidates still require review.

Sury/ondrej migration, repository addition and Sury key repair are neither
recommended nor permitted on cPanel/Plesk paths, including with explicit retry
options. The low-level source-write and repair assessments enforce the same rule.
Existing Sury packages on those panels require mixed-source review before updates.
A missing-source warning asks for that review rather than suggesting activation.
This is panel-specific, checked against vendor documentation on 29 October 2026:

- [cPanel PHP integration](https://docs.cpanel.net/ea4/php/about-php/) supports
  vendor-prefixed SCL PHP on non-Ubuntu systems. Sury/ondrej Debian packages do
  not replace EasyApache or cPanel-internal PHP.
- [Plesk custom PHP instructions](https://support.plesk.com/hc/en-us/articles/12376921077783-How-to-add-custom-PHP-versions-in-Plesk-for-Ubuntu-Debian)
  demonstrate Sury/PPA installations with explicit PHP handler registration, and
  label that custom procedure unsupported. The script does not perform it.
- [Virtualmin multiple-PHP instructions](https://www.virtualmin.com/docs/server-components/configuring-multiple-php-versions/)
  explicitly use Sury on Debian and ondrej/php on Ubuntu. Its existing bounded
  opt-in package migration remains available; website PHP selections still need
  the panel's configuration checks.

CloudLinux, CageFS, LiteSpeed, unsupported operating systems, custom PHP and
unmapped service restarts retain their existing blockers. Other detected panels
without a reviewed recipe remain blocked. Vendor commands can fail after partial
changes, so retain their output and inspect service health before retrying.
The post-update PHP and running-process inventory determines the fix result; updater exit status is recorded separately. Panel-internal PHP, WP Toolkit
and independent-version `sw-engine` builds can still require separate verification.
cPanel output containing an explicit fatal update error or a nonzero child-command
error also fails the attempt, even when `upcp` returns zero. Routine certificate
housekeeping does not count as a TLS failure. An unconfigured cPanel CLI selector
is reported separately from a PHP binary that cannot load.
Current cPanel output is checked for explicit license problems, update blockers
and package conflicts. Each selected reason is shown to the customer, including
package names/builds; licensing and conflicts are both reported when they coexist.
These errors fail the attempt even if the updater exits zero. The script does
not change licensing, erase conflicting packages or broaden updater options.

Internal cPanel PHP rules, checked 29 October 2026 NZDT, use the
[cPanel response](https://www.cpanel.net/blog/security/php-cve-2026-109618-and-cve-2026-109619-cpanel-response/)
and official RPM listings. Fixed upstream PHP 8.4 starts at 8.4.27. The exact
`cpanel-php81` RPM `8.1.34-2.cp110~el7`, `~el8` or `~el9` includes both backports.
The corresponding `8.1.34-1` packages and stock `cpanel-php84`
`8.4.22-1.cp130~el8`, `~el9` or `~el10` are affected. These exact rules accept
x86_64 builds with no epoch or epoch zero. Custom revisions and other unreviewed
older builds remain unknown. These rules do not use the cPanel release number
as proof that its installed PHP packages were updated.
Package references: [PHP 8.1 EL7](https://httpupdate.cpanel.net/RPM/11.110/centos/7/x86_64/),
[EL8](https://httpupdate.cpanel.net/RPM/11.110/centos/8/x86_64/),
[EL9](https://httpupdate.cpanel.net/RPM/11.110/centos/9/x86_64/);
[PHP 8.4 EL8](https://httpupdate.cpanel.net/RPM/11.130/centos/8/x86_64/),
[EL9](https://httpupdate.cpanel.net/RPM/11.130/centos/9/x86_64/),
[EL10](https://httpupdate.cpanel.net/RPM/11.130/centos/10/x86_64/).

A successful `upcp --security` exit can mean that no update started. The
[official updater source for 136.0.29](https://httpupdate.cpanel.net/cpanelsync/11.136.0.29/cpanel/scripts/upcp.static.bz2)
returns zero before logging when its preliminary security-target check fails.
That check excludes `SECURITY_UPDATES=never`, an exact release pin, missing
release metadata and an absent or unchanged eligible security release.
The script records documented `CPANEL`, `SECURITY_UPDATES`, `RPMUP` and `UPDATES`
settings from `/etc/cpupdate.conf`, and explains disabled security updates or
an exact release pin. Selecting a release series such as `CPANEL=136` is not
an exact release pin. If internal PHP still lacks a verified fix after cPanel
returns success, the warning names the installed build, required fixed version,
WHM Update Preferences and `/var/cpanel/updatelogs`. A possible skip reason is
not reported as the actual cause without matching evidence.

Every cPanel inventory, including `--check`, examines the last recorded cPanel
update log under `/var/cpanel/updatelogs`. It also supplies context if internal
PHP remains unfixed after an updater that returns success.
It reads only a regular file inside that directory and only its final 256 KiB.
`panel_previous_update_log` records the modification time and historical scope;
up to 20 selected, URL-redacted failure lines are retained separately.
Customer messages identify recorded missing-licence, Apache package-conflict and
component-update failures. These messages describe that dated log, not the
current updater's output or proof that an older blocker is still present.

The updated [cPanel advisory](https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619)
also describes `/scripts/autorepair update_cpanel_php8`. Its
[implementation](https://httpupdate.cpanel.net/autofixer2/update_cpanel_php8)
only operates on panel branches 112–132. It is not an automatic fallback in this
script and cannot repair a branch 136 installation. Use the supported cPanel
update process and investigate its settings/logs.

`panel_version`, `panel_update_tool` and `panel_update_scope` retain the detected
version, installed executable paths and operation scope for troubleshooting.
Broad `update-packages`/`rpmup` system updates and `upcp --force` are not used.
`panel_update_recipe`, `panel_update_command` and `panel_update_exit` distinguish
an available recipe from a command actually attempted and its exit status.
Vendor operations use the process-group watchdog with a 30-minute limit.
A timeout can leave partial changes;
review vendor logs and service health before another attempt.

Primary references, checked 24 October 2026 NZDT:

- [cPanel PHP2Shell advisory](https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619)
  and [EA4 change log](https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/)
  confirm backports for EA PHP 7.4, 8.0 and 8.1. These streams are not automatically
  unfixable because their upstream version is old. Verify the full package publisher build.
- [cPanel upcp options](https://docs.cpanel.net/whm/scripts/the-upcp-script/)
  and [update configuration](https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-update-configuration-file-cpupdate-conf/)
  describe update scope and preferences.
- [Plesk PHP2Shell advisory](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk)
  identifies fixed vendor builds for older PHP streams and separate internal
  `sw-engine` fixes in 18.0.80 Update 11 and 18.0.81 Update 4. Its build-date advice
  applies to those vendor builds, not all PHP compiled on that date.
- [Plesk update scope](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-updates-and-upgrades.59215/)
  distinguishes panel updates from third-party component updates.
- [Plesk's current-release installer example](https://support.plesk.com/hc/en-us/articles/12377218924695-Can-t-upgrade-Plesk-on-Debian-or-Ubuntu-Failed-to-fetch-autoinstall-plesk-com-404-Not-Found)
  uses `--select-release-current --upgrade-installed-components` and illustrates repository failures on older systems.
- [Virtualmin's package-update guidance](https://www.virtualmin.com/docs/faq/)
  describes OS package-manager updates, including updates to specific packages.

`sw-engine` also serves cPanel's WP Toolkit. Its product package revision can be
6.61.1 while its embedded PHP reports 8.3.6. The script keeps the product revision
in `embedded_runtime_package` and uses executable output for the PHP summary.
It does not emit PHP 6.61.1 or compare that product number with the embedded PHP
version. `runtime_assessment` keeps both values and the independent-version reason.
Both Plesk and cPanel WP Toolkit use `sw-engine`; identify the panel from its installation paths and updater. See
[cPanel's sw-engine explanation](https://support.cpanel.net/hc/en-us/articles/1500011785822-How-To-Enable-Debug-Level-Logging-In-sw-engine).

Disk preflight records the checked `df -Pk` output as `disk_preflight`. Low-space
warnings identify the filesystem, mount and available KiB, with duplicate mounts
removed from the message. The 128 MiB threshold is a minimum prerequisite; it is
not a package download/unpack space estimate. Check inodes and compare VM disk,
partition/LVM and filesystem sizes before choosing a growth or cleanup operation.
The script does not grow disks or delete application files.

## Older and custom installations

Release detection reads files as data; it never sources them. It falls back from
os-release to lsb-release, debian_version and redhat-release, including Whitebox.
Package inspection falls back from dpkg-query to dpkg and from DNF to YUM for RPM
updates. The script avoids Bash 4 features and new package-query field names.
The fixture suites run with Bash 2.05b, Bash 3.1 and current Bash. A missing
`mktemp` falls back to atomic directory creation with private permissions.
No wget, curl, HTTPS download, Python, Node, compilation or helper installation is
needed on the checked host. Basic Unix utilities and a supported timeout backend
are still required; automatic updates also need a working installed package
manager and authenticated, reachable package sources. Repository TLS, 404, DNS
and signing failures get separate diagnostics; the script never disables trust
checks to make an old repository work.

Recognising an old distro does not create a maintained PHP fix for it. Debian 3,
Whitebox 3, retired CentOS releases and other unsupported combinations are
inventoried but blocked from automatic updates. Older Ubuntu LTSs can proceed
with an appropriate configured support entitlement. Missing tools or repositories
are reported rather than bootstrapped from untrusted or archived packages.

Arch Linux is displayed as a rolling release. Arch package inventory, vendor
patch verification and automatic upgrades are not implemented. This is a script
limitation, not an OS support-lifecycle claim. An executable reporting an affected
upstream version remains unknown when its package ownership cannot be checked.
Pacman/vercmp availability is recorded for planning later support. Arch requires
a reviewed full system upgrade; a PHP-only update is not a supported substitute.
See the [Arch advisory](https://security.archlinux.org/ASA-202610-1) and
[partial-upgrade guidance](https://wiki.archlinux.org/title/System_maintenance#Partial_upgrades_are_unsupported).

Panel update paths are described above. DirectAdmin, aaPanel, CloudLinux and
LiteSpeed installations still require another reviewed update and restart recipe. Discovery
includes panel-internal PHP (`cpanel-php*`, `sw-engine`), EasyApache, alt-PHP,
Software Collections, DirectAdmin/aaPanel paths, bare `lsphp`, and FrankenPHP's
embedded PHP version. A package owner outside the PHP inventory requires a
separate update procedure; its executable's PHP version is assessed independently.
Finding `/etc/cagefs` requires a separate review of CageFS activity and the applications using it. If applications use CageFS PHP copies, those
copies need refresh and verification as well as the host packages.

Supervisor-managed PHP applications and workers remain blocked because the script
has no verified restart procedure for them. Supervisor and RoadRunner are standard
software; their application configuration still requires review. Automatic
updates support verified package and service procedures, without changing local
Supervisor/Laravel/RoadRunner configuration. The warning directs operators
to match `service_mapping` process IDs and `process_parent` launchers to named
Supervisor programs using `supervisorctl status` with the correct system configuration.
During maintenance, safely stop only the affected programs, confirm their PHP
children have stopped and stay stopped, then retry `--fix`. All other package-source and safety checks still apply. Restore the
applications afterwards even if the update was blocked, verify application health,
then rerun `--check`. Do not stop Supervisor itself or restart all its programs.
Plesk Web Socket has a separate reviewed Debian restart path. Its unit must be
owned by `plesk-web-socket`, match the reviewed unit digest, and have no systemd
drop-ins. Validation repeats before restart; modified and unreviewed units remain
blocked. This supports the vendor-managed service without authorizing arbitrary
supervised applications.

The script does not invoke Supervisor or change application configuration. RoadRunner documents
[`rr reset`](https://docs.roadrunner.dev/docs/app-server/cli) for worker replacement.
Supervisor supports [individual program restarts](https://supervisord.org/running.html);
child shutdown depends on the application and its
[process-group settings](https://supervisord.org/configuration.html#program-x-section-values).

Detached LSPHP workers can survive a LiteSpeed restart. They are reported as a
blocker rather than killed indiscriminately. Chrooted processes and unverified
mount namespaces cannot supply host package paths or restart targets. A private
mount namespace can proceed when its root and runtime paths share host file
identities, so PHP-FPM's `PrivateTmp` alone does not cause a blocker. Mapped PHP
modules also require matching filesystem paths. Detected isolated PHP or a failed
PHP-module inspection keeps the result unknown. Installed container tools alone
do not. Container PHP needs its own update, usually an image rebuild/redeployment.
These separate-environment verification gaps do not by themselves block host
PHP package updates.
Foreign process paths and PIDs never become host inventory or restart targets.
Existing host package, service, panel and repository safety checks still apply.
A host update can therefore complete while the VM remains unknown because
container PHP is unverified. If assessed host PHP is already fixed and no PHP
restart is pending, the script skips another host update. Repeated isolated worker
warnings are grouped by executable/process type and detected container platform;
per-PID `process_scope_review` and `verification_gap` records remain available.
Container image enumeration is outside the check. Package-owned Software
Collection paths are inventoried. An unmapped service blocks an automatic update
that needs its restart; a missing package publisher backport rule keeps that PHP version
unknown. These are separate restrictions.

Installed RPM/DEB changelog mentions of either CVE are collected as supporting
evidence only. A mention could concern an incomplete or reverted fix. Neither
those mentions nor build dates change the verified package rules. See the
[public automation research](security-background.md#public-automation-research-22-october-2026)
for sources and recipes still needing work.

Discovery covers the configured paths and process scope. Review other home directories, chroots, mounted images and renamed embedded applications separately. `N` is not a compromise
assessment or an application health check. Check actual websites, APIs and panels
after maintenance; verify actual application responses as well as process health.

## Machine manifest

Every new manifest line starts `dss:manifest:<record>:<phase>|<payload>`.
`phase` is `beforefix` or `afterfix`; payloads can contain further pipe-delimited
fields and colons. Capture records by their prefix, not arbitrary colon splitting.
Multiline command/version output becomes separately prefixed lines.

```sh
grep '^dss:manifest:' check-output.log > php-manifest.log
grep '^dss:manifest:package:' check-output.log
grep '^dss:manifest:blocker:' check-output.log
```

Records include `schema`, `observed_at`, `kernel`, `hostname`, `uptime`, `disk`,
`distro`, `package_backend`, `package`, `package_state`, `runtime`, `php_version`,
`process`, `process_scope`, `process_scope_shared`, `repository_file`, `repository_failure`, `panel`,
`backport_mention`, `bash`, `capability`, `command`, `blocker` and `aggregate`.
Additional diagnostic records preserve the reasons behind readable summaries:

- `repository_layout`: source file, recognised package publisher, layout, enabled state
  and whether a Sury suite matches a reviewed installed Debian release. APT list
  lines, Deb822 continuation fields and Virtualmin RPM definitions are inspected.
  The classification omits URLs, credentials and inline signing keys.
- `repository_guidance`: a manual review recommendation and `not_executed`, or
  a disabled/unknown-state review marker. Modern sources get no legacy warning.
  Extrepo is recognised by `extrepo_sury.sources` or its
  `/var/lib/extrepo/keys/sury.asc` signing path; edited layouts still exclude
  package-owned Sury key repair. Review the detected manager's installed tools and configuration before running repository repair. See [repository repair advice](resolution-options.md#repository-repair-advice).
  Active Sury Debian and ondrej Ubuntu PPA definitions are checked against the
  measured OS and expected suite. A mismatch warning includes the source file,
  configured distribution/suite and host release, and `repository_guidance`
  adds `configured`, `host` and `expected_suite`. Wrong-distribution sources
  receive this warning before layout/key repair advice (including extrepo advice).
  Disabled/commented sources do not get an active mismatch warning. Both legacy
  `.list` and Deb822 `.sources` definitions use the existing parser; it keeps
  folded fields, exact official hosts/paths, redaction and architecture filtering.
  This source finding does not infer installed package provenance or change CVE
  status. Replacing a source alone does not replace installed packages. The normal
  package candidate check already refuses a Debian Bookworm Sury candidate on
  Ubuntu Jammy; APT metadata may have refreshed before that rejection. These
  diagnostics add no repository rewrite or package conversion procedure.
  Primary publisher distinction: [Sury Ubuntu PPA and Debian DPA](https://deb.sury.org/),
  reviewed 2026-10-29.
- `panel_path`: cPanel core and updater paths, plus a detected CloudLinux selector
  directory. Records include file type, readability, executability, symlink target
  and resolved path when `readlink` is available. Missing and inaccessible paths
  share a status; panel activity requires a separate process and updater check.
- `runtime_path`: the same file metadata and queried package owner for missing,
  non-executable or failed-probe PHP files. An existing executable returning 127
  can have a missing interpreter, loader or wrapper target; inspect the startup diagnostic to identify the missing component.
- `package_install_status`: backend, PHP package name, architecture and package
  installation status, including records retained only for configuration files.
  RPM inventory reports installed packages; the limited `dpkg -l` fallback does
  not expose removed or incomplete package states.
- `package_classification`: package name, supporting/selector classification and reason.
- `package_assessment`: name, full version, architecture, vendor, package publisher, state,
  rule reason and upstream-only state. `package_state` retains its existing format.
- `runtime_identity`: observed path, resolved path, owner, full package version,
  package publisher and ownership reason. The original `runtime` record is unchanged.
- `runtime_assessment`: path, owner, reported PHP version, package version,
  package publisher, assessed state, reason and upstream-only state.
- `runtime_probe` and `runtime_error`: executable path, version-probe exit status
  and separately prefixed startup diagnostics when the probe fails.
- `runtime_observation`: path and observed evidence type (`executable`, `module`
  or `running_path`). `running_path` indicates a process reference, not a loaded-version check.
- `process_runtime_reference`: PID, executable/module kind and original mapped
  path, retaining any deleted-file suffix.
- `container_tool`: detected product, command and `installed_only`.
- `scope_note`: installed container tools or a separate web server with no PHP
  in its inspected mappings; informational observations, without a CVE-state change.
- `process_container_evidence`: isolated process PID, product inferred from its
  cgroup (or `unidentified`) and the cgroup evidence. Readable warnings name a
  container product only when that process's cgroup supports the identification.
  Filesystem and mount-namespace details remain in `process_scope`. PHP in these
  separate environments requires its own update and restart review; verify the PHP packages and workers inside each affected environment after its update.
- `service_mapping`: PID, process name, executable, observed service and missing-restart reason.
- `process_summary`: matching process count and pending deleted-file restart flag.
- `inventory_gap`: missing package-manager support or unavailable package inventory.

`script_revision` identifies the script behaviour revision; maintain it when
changing checks or update actions. The function checksum separately fingerprints
the loaded functions. The schema record identifies the rule snapshot and both CVEs. Repository filenames
are recorded without dumping configuration credentials. PHP package-command URLs
are redacted.


## Offline tests and release checks

Run the suites from the repository root:

```sh
python3 tests/dephp2shell.test.py
python3 tests/dephp2shell-cli.test.py
python3 tests/dephp2shell-output-style.test.py
python3 tests/dephp2shell-sury.test.py
python3 tests/dephp2shell-apt-solver.test.py
python3 tests/dephp2shell-panel-diagnostics.test.py
python3 tests/dephp2shell-runtime-inventory.test.py
python3 tests/dephp2shell-compatibility.test.py
bash -n dephp2shell.sh
shellcheck -S warning dephp2shell.sh
```

The fixtures load script functions with fake package/service commands and temporary filesystem roots. They do not install host packages or write to application databases. The APT solver suite uses synthetic packages, private APT state, no network methods and a disabled `dpkg` command. It checks dependency plans and automatic/manual installation marks with an isolated no-op transaction.

To exercise an older shell or AWK implementation:

```sh
DP2S_TEST_BASH=/path/to/bash python3 tests/dephp2shell.test.py
DP2S_TEST_BASH=/path/to/bash python3 tests/dephp2shell-runtime-inventory.test.py
DP2S_TEST_BASH=/path/to/bash python3 tests/dephp2shell-panel-diagnostics.test.py
DP2S_TEST_BASH=/path/to/bash DP2S_TEST_AWK=/path/to/awk \
  python3 tests/dephp2shell-compatibility.test.py
```

The compatibility suite starts harmless child processes to test command deadlines and cleanup, including a child that ignores TERM. Tests for old interpreters need those interpreters to be installed separately; they are development dependencies only.

Before release, review the selected source files and history for credentials and identifying server data. Keep the deliverable self-contained. Record a release version and checksum; use the function checksum to compare runs, and verify download authenticity separately. Run check-only canaries on the actual distribution/runtime families and verify fixes on disposable instances before unattended deployment.
