# Coverage and update boundaries

DePHP2Shell assesses the October PHP2Shell vulnerabilities CVE-2026-109618 and CVE-2026-109619 by default. Use `--november-2026` for the November security release. Both modes inspect local installations and processes using maintained version and vendor-backport rules. The script sends no exploit probes and does not download a rule feed.

## Discovery

The inventory includes Debian/RPM PHP packages, package-owned executables and Apache modules, conventional alternative paths, recognised hosting-panel paths, and relevant running processes. It also reports operating-system identity, control-panel observations and web listeners on ports 80 and 443.

`php -v` reports command-line PHP, which can differ from the PHP serving a website. Each discovered PHP branch is assessed separately against reviewed version and vendor-backport rules. Build dates and process start times describe when files were built and processes launched; fix status uses the reviewed rules.

| PHP branch | October fixed upstream release | November fixed upstream release |
| --- | --- | --- |
| 8.6 | Use the November check | 8.6.0 |
| 8.5 | 8.5.12 | 8.5.13 |
| 8.4 | 8.4.27 | 8.4.28 |
| 8.3 | 8.3.36 | 8.3.37 |
| 8.2 | 8.2.35 | 8.2.36 |
| 8.1 and earlier | Matching reviewed vendor build required | Matching reviewed vendor build required |

The table records upstream package fixes. Check [PHP's support dates](https://www.php.net/supported-versions.php) before choosing a migration target. Distribution and third-party backports use separate package rules. See [package sources by OS and publisher](resolution-options.md#package-managed-php-sources) and the [November RPM rule coverage](maintainer-reference.md#november-rpm-rules). Unrecognised builds that require a backport remain unverified.

### Debian and Ubuntu November package evidence

| OS release | Reviewed package evidence |
| --- | --- |
| Debian 6–8 | Selected exact releases from Community Backports. |
| Debian 9–10 | Selected Community Backports, native Freexian Extended LTS builds, and the [StackX main releases](stackx-backport-evidence.md). |
| Debian 11 | Native Freexian Extended LTS builds and the [StackX main release](stackx-backport-evidence.md). |
| Debian 12–13 | Debian security advisories and [reviewed Sury builds](sury-backport-evidence.md). |
| Ubuntu 14.04 and 16.04 | Native Ubuntu Pro Legacy advisories and selected Community Backports. |
| Ubuntu 18.04 and 20.04 | Native Ubuntu Pro advisories and selected Community Backports. |
| Ubuntu 22.04, 24.04 and 26.04 | Canonical advisories and [reviewed Sury builds](sury-backport-evidence.md). |
| Ubuntu 26.10 | Canonical advisories. |
| Other Debian and Ubuntu releases, including old interim releases | Upstream fixed-version rules still apply. A backport needs evidence for its publisher and exact build. |

The same checks apply to recognised older native packages left after an OS
upgrade. The checker records their original advisory release and can show
APT's proposed removal plan for manual review. See [installed build and
removal verification](resolution-options.md#verify-older-release-packages-and-republished-builds).

## Updates

| Setup | Automatic update approach |
| --- | --- |
| Supported Debian/Ubuntu | Refresh APT metadata and simulate a targeted installed-PHP update. Reject removals and unapproved new dependencies. Preserve local package configuration. |
| Existing Sury/ondrej PHP | Use an authenticated, recognised fixed candidate from the existing package publisher, retaining the source package, branch and architecture. |
| Supported RPM systems, including installed Remi PHP | Use a supported DNF implementation to test an update from the current publishers. DNF4 can also install verified required runtime libraries. Stream changes require manual review. |
| Compatible Virtualmin | Use the existing package-manager procedure. |
| Supported cPanel | Request critical panel security updates, then update installed website PHP packages separately. |
| Supported Plesk | Use the Plesk installer for installed components within the current Plesk release. This can update other components, including databases, mail and web servers. |

Configuration checks and service restarts require a recognised safe procedure. Unmapped launchers, incompatible panel setups, package conflicts or unverifiable transactions can block an automatic fix.

Ordinary APT fixes include verified required additions and upgrades of native
runtime libraries from matching official OS sources. Separate disruptive options cover
bounded repository/package repairs. These do not authorize general system repair. Check mode recommends matching options using installed/cached evidence. See [resolution options](resolution-options.md).

Normal updates keep each PHP package with its existing package publisher and preserve unrelated PHP selectors. The tool adds no persistent pins or holds. A native-to-Sury package publisher change requires a separately enabled `--enable-extra-fixes` method and a compatible proposed transaction. Adding the matching official source requires a further repository opt-in. See [resolution options](resolution-options.md) and [the bounded Sury evidence](sury-backport-evidence.md) for exact recognised older builds.

## Separate work

Custom PHP builds, unsupported package branches, CloudLinux/CageFS/LiteSpeed combinations and embedded runtimes can need a separate vendor or administrator procedure. Automatic fixes require a supported update procedure for the detected setup.

PHP running inside containers or isolated environments needs checking and updating there. Installed container software alone is an observation. The script does not inventory all container images or rebuild them.

The tool does not upgrade the operating-system release, choose another website PHP branch, reboot, terminate scheduled application jobs or disable websites. Changing the default PHP command does not move every website or scheduled task to another PHP branch.

A PHP fix does not restore operating-system security support. If maintained packages are unavailable, plan migration or a supported vendor update. Application testing and investigation of possible compromise remain separate tasks.

## Runtime requirements

The runtime requires Linux. macOS, BSD, Solaris and Windows POSIX shells are
rejected before inventory, log creation or updates; a failed OS query also stops
the run. `--help` remains available. Unsupported Linux distributions can still
be checked, but updates require a supported recipe.

The script is self-contained Bash using syntax intended for older Bash versions. It uses ordinary Unix utilities such as `awk`, `sed`, `grep`, `sort`, `tr`, `cat` and `readlink`. Root access is needed for complete checks and updates.

A usable command-deadline mechanism is required. Update mode also requires supervision of command process groups. Package updates need working authenticated sources and a supported package manager. Arch package inventory and upgrades are not implemented.

## Security references

- [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory for CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Debian tracker: CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [Debian tracker: CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [Ubuntu notice USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Ubuntu notice USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)
