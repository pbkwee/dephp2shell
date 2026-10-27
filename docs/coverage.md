# Coverage and update boundaries

DePHP2Shell assesses CVE-2026-109618 and CVE-2026-109619 in the PHP installations and processes it can inspect locally. Checks use locally maintained version and vendor-backport rules. The script sends no exploit probes and does not download a rule feed.

## Discovery

The inventory includes Debian/RPM PHP packages, package-owned executables and Apache modules, conventional alternative paths, recognised hosting-panel paths, and relevant running processes. It also reports operating-system identity, control-panel observations and web listeners on ports 80 and 443.

`php -v` alone is insufficient: command-line PHP can differ from the PHP serving a website. Each discovered PHP branch is assessed separately. A recent build date or process start time does not establish that the security fixes are present.

Fixed upstream branch releases are PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Older distribution or vendor versions need a matching reviewed backport rule. Unrecognised older builds remain unverified.

## Updates

| Setup | Automatic update approach |
| --- | --- |
| Supported Debian/Ubuntu | Refresh APT metadata and simulate a targeted installed-PHP update. Reject removals and unapproved new dependencies. Preserve local package configuration. |
| Existing Sury/ondrej PHP | Use an authenticated, recognised fixed candidate from the existing provider, retaining the source package, branch and architecture. |
| Supported RPM systems | Check the proposed transaction, then use DNF or YUM. |
| Compatible Virtualmin | Use the existing package-manager procedure. |
| Supported cPanel | Request critical panel security updates, then update installed website PHP packages separately. |
| Supported Plesk | Use the Plesk installer for installed components within the current Plesk release. This can update other components, including databases, mail and web servers. |

Configuration checks and service restarts require a recognised safe procedure. Unmapped launchers, incompatible panel setups, package conflicts or unverifiable transactions can block an automatic fix.

Separate disruptive options cover bounded repository/package repairs and necessary upgrades of reviewed installed native libraries. These do not authorize general system repair. Check mode recommends matching options using installed/cached evidence. See [resolution options](resolution-options.md).

Normal updates keep each PHP package with its existing provider and preserve unrelated PHP selectors. The tool adds no persistent pins or holds. A native-to-Sury provider change requires a separately enabled `--disruptive` method and a compatible proposed transaction. Adding the matching official source requires a further repository opt-in. See [resolution options](resolution-options.md) and [the bounded Sury evidence](sury-backport-evidence.md) for exact recognised older builds.

## Separate work

Custom PHP builds, unsupported package branches, CloudLinux/CageFS/LiteSpeed combinations and embedded runtimes can need a separate vendor or administrator procedure. Detecting a panel or distribution does not guarantee that an automatic fix exists.

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
