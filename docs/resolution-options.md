# Choosing a resolution

If a PHP security update cannot finish, these options let you choose what else may change on your server. Some finish an interrupted installation; others restore access to updates or switch the PHP package publisher. Each section starts with the purpose, then explains the files, downloads, service changes and risks.

Start with `--check` to identify who supplies each PHP installation. Review the [panel update paths](#hosting-panel-update-paths) first when a hosting panel manages PHP. Use `--fix` to attempt the supported update path. Read the specific blocker if that attempt cannot finish. When the script has no procedure, check the package publisher's maintained package routes or arrange a separate update procedure.

Choose the smallest change that can leave every PHP installation patched. Updating one PHP branch does not fix another branch, and changing the default command-line PHP does not move individual websites or scheduled jobs.

## Keep the existing packages first

| What the check reports | Next step |
| --- | --- |
| A hosting panel manages PHP | Check the [panel update paths](#hosting-panel-update-paths) for what `--fix` can do and which steps need an operator. |
| Native distribution PHP with an available security update | Repair or enable the appropriate existing distribution security source, then retry. A third-party PHP source is unnecessary when the distribution supplies a fix. |
| Older Ubuntu with fixes available through Ubuntu Pro or Legacy support | Review the required support entitlement and repositories. The script does not obtain or enable a subscription. |
| A package-manager lock or broken repository access | Let an active package operation finish, or repair the reported repository problem, then retry. Keep signature and certificate checks enabled. |
| Fixed packages installed, but old PHP processes remain | Replace the affected processes using their application's shutdown and restart procedure, then rerun `--check`. |
| Supervisor or another application launcher cannot be restarted safely by the script | During maintenance, stop only the affected programs and confirm their PHP children stay stopped. Retry `--fix`, restore the programs even if patching fails, test them and rerun `--check`. |
| A package build has no verified fix rule | Obtain evidence for that exact package revision or update it to a verified fixed build. Vendor backports can retain older upstream numbers; check the complete package revision against the package publisher's fix information. |

Existing Sury/ondrej packages can use a recognised fixed revision from their configured source and PHP branch.

A successful package update still needs an application check. Other PHP copies, isolated environments and workers using old code can keep the overall result unresolved.

## CentOS 7 archive updates

CentOS Linux 7 [reached end of life on 30 June 2024](https://blog.centos.org/2023/04/end-dates-are-coming-for-centos-stream-8-and-centos-linux-7/).
Its standard archives retain historical packages. For example, a YUM upgrade
from PHP `5.4.16-36.el7_1` to `5.4.16-48.el7` installs an older maintenance update:
the [CentOS archive](https://vault.centos.org/7.7.1908/cr/x86_64/Packages/)
lists the latter package in April 2020. It lacks the PHP2Shell fixes released in
2026. Repairing archive mirror access or completing that upgrade leaves
PHP2Shell unresolved.

The script keeps automatic CentOS 7 updates blocked and explains this in both
check and fix reports. Use a maintained PHP publisher with a verified fix for
the exact build, or migrate the applications to a supported OS and patched PHP.
Review website and extension compatibility before changing the PHP branch or
publisher. A full `yum upgrade` also changes unrelated system packages.

Evidence checked 5 November 2026. Red Hat's
[PHP2Shell bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)
identifies the default RHEL 7 PHP as affected by CVE-2026-109619; its vulnerable
code for CVE-2026-109618 is absent. The CentOS archive date establishes that the
offered build predates the fixes. This diagnostic keeps the existing package
assessment rules and aggregate CVE status.

## Move a retired Rocky/Alma PHP stream

An OS can still receive updates while its selected PHP stream has retired.
`dnf upgrade php` stays in that stream, which explains “Nothing to do” on a
Rocky 8 server still using native PHP 7.2. First try the ordinary `--fix`:
a same-branch vendor security update changes less application behaviour than a
branch migration. Alma has published PHP2Shell backports even for retired streams.
A fix for these two CVEs and ongoing PHP maintenance are separate findings.

For native PHP 7.2/7.3 on Rocky/Alma 8, PHP 7.4 is a smaller compatibility step
than PHP 8. Despite upstream PHP 7.4 being EOL, this vendor stream has Full Life
status in the [EL8 lifecycle](https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle).
Native PHP 8.2 is another maintained option, through May 2029. Rocky's published
fixed 7.4 x86_64 engine build is
`7.4.33-8.module+el8.10.0+40393+c071e357` (RLSA-2026:87080);
the 8.2 fix is `8.2.35-1.module+el8.10.0+40394+d21b33fb` (RLSA-2026:87073).
Check the complete installed package build, not just `php -v`.

Review the application/framework/plugin PHP requirements, then choose **one**
destination. For example, native PHP 7.2 to native 7.4:

```sh
sudo dnf --refresh module list php
sudo dnf --refresh --assumeno module switch-to php:7.4
# After reviewing application compatibility and the full package plan:
sudo dnf --refresh module switch-to php:7.4
```

Use `php:8.2` instead if the applications support PHP 8.2 and you choose that
route. A preview refreshes local metadata/cache, then declines the transaction.
[DNF switch-to](https://dnf.readthedocs.io/en/latest/command_ref.html#module-command)
can remove packages absent from the destination, including extensions; review all
changes before applying. There is no universal compatibility guarantee: even
[PHP 7.2 to 7.3 changes regular-expression behaviour](https://www.php.net/manual/en/migration73.other-changes.php),
and [PHP 8 removes old functions and changes errors/type handling](https://www.php.net/manual/en/migration80.incompatible.php).
PHP 8.2 on EL8 still supplies mod_php, but custom Apache module names/paths and
handler configuration can need changes.

For an existing Remi PHP 8.1 installation, the script offers stable Remi PHP 8.4
when that stream is available. This retains the existing provider and has a longer
upstream support window than PHP 8.2, whose upstream security support ends in
December 2026. Confirm the application's supported branches; the version jump
itself does not establish compatibility. Do not choose a higher stream simply
because it appears in the list; it may be a development release.

```sh
sudo dnf --refresh --assumeno module switch-to php:remi-8.4/common
# After application and package-plan review:
sudo dnf --refresh module switch-to php:remi-8.4/common
```

See [Remi's procedure](https://blog.remirepo.net/post/2024/12/18/Install-PHP-8.4-on-Fedora-RHEL-CentOS-Alma-Rocky-or-other-clone)
and [PHP's support dates](https://www.php.net/supported-versions.php).
After applying the chosen switch, check `rpm -q php-common`, validate the actual
PHP handler/configuration, and restart the PHP/web services that use it. The
script names observed `php-fpm.service`/`httpd.service` validation and restart
commands. Long-running CLI jobs also need replacement through their application's
procedure. Rerun `--check` to assess the resulting installed builds and processes.

This is manual maintenance advice. The check uses cached metadata to match the
enabled stream and installed provider, and offers only reviewed available targets.
It explicitly reports that a fixed candidate has not yet been queried. Hosting
panels need their own PHP selection/update procedure; these commands are not
offered on detected panel servers.

## What refreshing and installing mean

A repository is a configured package source. Its **source definition** tells APT
where to look. A **signing key** lets APT authenticate the repository's published
metadata. A **package index** is the downloaded catalogue of available versions.
The package archive contains the software itself.

Refreshing indexes, like `apt-get update`, downloads catalogues and writes APT's
local list/cache files on this server. It does not change the package publisher's repository,
install PHP or edit the source definitions. Installation is a separate step that
downloads or reuses package archives and runs their setup scripts. See the
[APT manual](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html#update).

A normal `--fix` uses the existing configured sources. Depending on the server,
these can be Debian/Ubuntu mirrors, an existing Sury/PPA source or another supported
package publisher. APT resolves package URLs from its authenticated metadata. The APT methods here
do not fetch a standalone PHP `.deb` from a hard-coded URL to bypass the configured
repositories. The explicit key operations below are different: they download public
signing keys from named HTTPS endpoints.

Routine APT PHP updates do not directly rewrite source definitions. A supported
hosting-panel update invokes vendor tooling with a broader scope: Plesk can update
non-PHP components, and panel tools can manage their own repositories/configuration.
Check the detected panel's update description as well as the option chosen here.

## Repository repair advice

Checks and fixes report recognised source layouts without changing them.
A suite matching the OS codename does not establish that maintained packages are
available; confirm current publisher support. Mismatch advice describes configured
sources and does not prove the origin of installed packages. Changing or disabling
a source does not replace packages or verify PHP fixes.

Deb822 suite lists are checked one distinct suite at a time, so a mixed definition
names its wrong suite and repeated matching tokens do not create a mismatch.
Named suites need components; exact-path suites ending `/` must omit components.
A definition with invalid components is reported and is not counted as an active
matching source. Other APT syntax or repository problems can still require review.

The recognised layouts have these manual recovery routes:

- Legacy or custom Sury PHP definitions receive a recommendation to review the
  [Sury instructions](https://packages.sury.org/php/README.txt), the installed OS
  suite and `debsuryorg-archive-keyring`. Correct the existing definition after
  review instead of adding a duplicate. A different Debian suite needs separate
  review before using its packages.
- Extrepo-managed Sury definitions receive a recommendation to review
  `extrepo update sury` when repair is needed. Check enabled state and duplicate
  definitions first. `--refresh-sury-signing-key` refuses these layouts because
  extrepo manages a different keyring. `extrepo enable sury` can re-enable an
  existing definition without refreshing metadata; see the
  [Debian manual](https://manpages.debian.org/bookworm/extrepo/extrepo.1p.en.html).
- Legacy Virtualmin sources receive a recommendation to review
  `virtualmin configure-repos`, or `virtualmin setup-repos` on older versions.
  The legacy repository can be intentional. Switching to the production source
  can change Webmin module packaging. Review the
  [vendor procedure](https://www.virtualmin.com/docs/installation/troubleshooting-repositories/),
  including its script alternative when the CLI is unavailable.

Disabled Deb822 stanzas remain visible in the manifest. The advice does not enable
those sources, replace keys or execute repository setup commands. Layout findings describe configured sources. Repository failures are reported from package-manager output, and PHP fix status comes from package/runtime assessment.

### Authentication overrides and custom APT paths

The Sury trust check reports the effective blocking APT key and value, or the
source filename, line and option. `apt_trust_setting` records retain the same
evidence. Global configuration output does not identify the file that set a value:
review `/etc/apt/apt.conf`, `/etc/apt/apt.conf.d` and any file selected by
`APT_CONFIG`. A selected `apt-config dump` value is effective configuration,
not proof that a particular file supplied it. Avoid sharing a full configuration
dump: proxy settings can contain credentials.

There are two different problems:

- Authentication overrides such as `APT::Get::AllowUnauthenticated=true`,
  `Acquire::AllowInsecureRepositories=true`, disabled HTTPS `Verify-Peer` or
  `Verify-Host`, and source-local `trusted=yes` bypass checks. Review the named
  setting and the repository's actual signing/TLS failure. A new key alone does
  not remove these overrides. HTTP alone is not proof that APT package-signature
  verification is disabled.
- Custom `Dir`, `Dir::Etc`, `Dir::Etc::sourcelist` or `Dir::Etc::sourceparts`
  settings redirect source lookup outside the script's reviewed paths. They may
  be intentional; they are not evidence of disabled signatures. Inspect the actual
  sources and their owner before restoring conventional paths. Do not discard an
  intentional custom layout merely to make this check pass.

The trust check conservatively examines all conventional source files, including
non-PHP definitions. A finding does not prove that Sury supplied the override or
that an installed package failed authentication. Raw source contents, proxy
credentials and inline signing keys are not copied into these diagnostics.

There is no general automatic conversion from arbitrary custom sources to a
supported configuration. Use the route matching the measured OS and source owner:

| Existing setup | Recovery route |
| --- | --- |
| Supported Debian with the standard Sury source | Follow the [publisher's keyring and same-release source instructions](https://packages.sury.org/php/README.txt). Use a dedicated `Signed-By` keyring. The script's narrower `--refresh-sury-signing-key` repair applies only to its reviewed standard Debian layouts; it does not rewrite sources or remove overrides. |
| Supported Ubuntu with ondrej PHP | Follow the [Ubuntu PPA's instructions](https://launchpad.net/~ondrej/+archive/ubuntu/php) and verify its published signing-key identity. Retain the installed Ubuntu suite. Debian keyring repair is not the Ubuntu PPA key procedure. |
| Extrepo or hosting-panel managed sources | Use the owning tool's documented repair procedure and reconcile duplicate definitions. Do not overwrite a managed source with a generic Sury example. |
| Old release, mixed releases, local mirror or third-party PHP PPA | Establish publisher support and package provenance before replacing anything. The [current Sury archive suites](https://packages.sury.org/php/dists/) and PPA support policy determine availability; the OS codename alone does not. Never substitute a newer release's suite on an older OS. |
| RPM distribution | Use the actual distribution, panel or RPM PHP publisher's repository/key procedure. APT/Sury source recipes do not apply. Preserve package-signature and TLS verification. |

For example, Ubuntu 16.04/Xenial is outside the public ondrej PPA's current LTS
support. Removing an override or refreshing a key cannot make that archive
maintained. Ubuntu Pro/Legacy coverage for eligible Canonical packages does not
patch third-party PPA PHP; review the [coverage and release schedule](https://ubuntu.com/security/esm)
and the actual PHP publisher, or plan a supported OS/application migration.

For a reviewed same-release repair, save the old definition and key references,
establish the authentic publisher key and matching source, then remove only the
identified bypass. Retain signatures and TLS checks. Refresh indexes and resolve
all signature/download errors, inspect exact package candidates and simulate the
proposed transaction before installation. Verify PHP fixes and application health
afterward. These are separate steps: a secure source configuration does not prove
that its PHP package includes either PHP2Shell fix.

## Virtualmin blocks an installed Apache PHP module

Virtualmin normally creates
`/etc/apt/preferences.d/debian-virtualmin-restricted-packages` (or the Ubuntu
counterpart) to prevent installing `libapache2-mod-php*`. Its preferred setup uses
PHP-FPM pools under separate website accounts. The negative pin also blocks
updates to an already-installed Apache PHP module and can hold back other PHP
packages with matching-version dependencies. It does not unload the module.
[Virtualmin explains the isolation concerns](https://www.virtualmin.com/docs/server-components/php-execution-modes/).

Inspect the named pin file and effective policy, and list Apache's loaded modules
and virtual hosts:

```sh
apt-cache policy 'libapache2-mod-php*'
apt-mark showhold
apache2ctl -M
apache2ctl -S
```

Then choose a manual path:

- Check every site's selected PHP handler in Virtualmin. If sites still use
  mod_php, migrate them to a supported, patched FPM version and test them. If all
  sites already use FPM, investigate removing the unused mod_php packages while
  keeping the restriction. Running FPM processes alone does not prove every site
  uses FPM. Review Apache includes and `.htaccess` files for `php_value`, `php_flag`
  and `php_admin_*` directives, including directives inside module guards that
  could silently stop applying. Simulate removal with `apt-get -s remove` and the
  exact unused package names; check dependencies, configuration validity and site
  behaviour before proceeding. Disabling a module alone leaves its installed
  package and dependency restrictions in place.
- If mod_php must remain, review a narrow APT exception for the existing package
  names and intended Debian/Ubuntu source, confirm candidates with `apt-cache
  policy`, then retry `--fix`. Changing package policy alone does not change
  website handlers. Keeping mod_php retains Virtualmin's isolation concerns;
  removing the entire restriction permits future mod_php installations too.
  Re-running Virtualmin's configuration action can recreate its restriction file.

Adding Sury does not remove the pin. The script gives manual guidance and
suppresses extra repository/migration suggestions while an installed PHP package
has no candidate and a negative priority. It does not alter pins or website
handlers, disable modules or remove packages. After an operator changes the
configuration, rerun `--check`, apply the remaining PHP updates and verify the
websites. Removing unused mod_php does not patch FPM, CGI or CLI.

## Compare the options

These options permit specific additional changes during a fix attempt. The attempt checks candidate availability before installing packages. After a successful repair, the script checks PHP again and can continue
with the ordinary PHP update and service restarts. A command selecting a key or
package repair is therefore **not a repair-only command**.

The table describes the selected action's direct changes. Package installation
scripts and hosting-panel updaters have their own effects, explained below.

| Option | APT source or signing-key files | Selected action | Main benefit and risk |
| --- | --- | --- | --- |
| `--fix` | No direct source/key edits by this script. Panel tools have their own scope. | Refresh indexes, install allowed PHP updates and replace supported workers. | Obtain fixes through existing sources; package scripts and restarts can interrupt sites. |
| `--add-debian-php-backports` | Can add or expand the dedicated signed source and preferences for approved branches. | Use a reviewed community build after higher-priority options are exhausted. | Obtain a last-resort update for the listed legacy branches. |
| `--migrate-php-to-sury` | Unchanged unless repository addition is separately permitted. | Replace eligible distribution PHP packages with Sury/PPA builds of the same PHP branch. | Obtain a verified fix from Sury/ondrej; future PHP updates use that repository and applications still need testing. |
| `--add-sury-repository` | Can add one source file, a dedicated key and a scoped preference. | Make the matching Sury/PPA repository available for the approved migration. | Supply missing candidates; the new source can affect future package-manager choices. |
| `--refresh-sury-signing-key` | Replace the standard Sury keyring; retain a backup. Source definitions stay unchanged. | Repair trust for an existing, verified standard Sury definition. | Restore authenticated repository access; a bad URL, wrong suite or unavailable package remains a separate problem. |
| `--add-os-security-repository` | Add a source file using the installed Debian/Ubuntu archive keyring. | Enable the matching native `main` security repository. | Make native security updates available; the persistent source also affects future updates outside PHP. |
| `--configure-pending-php-packages` | No direct source/key edits. | Finish setup for explicitly identified pending PHP packages. | Complete an interrupted installation; package setup scripts can change configuration and services. |
| `--reinstall-php-same-version` | No direct source/key edits. | Download and reinstall the same PHP package version. | Restore package files/metadata; setup scripts run again and the version may still be vulnerable. |

The additional repair and package source methods require
`--enable-extra-fixes` and are otherwise disabled.
`--enable-extra-fixes` alone does not grant all these permissions
or bypass a blocker. It selects fix mode unless `--check` is explicitly present.
Examples below include `--fix` to make that action clear.

Method environment variables mirror the option names: replace hyphens with
underscores, uppercase the name and prefix it with `DP2S_`. They default to false;
explicit `--option=false` overrides an enabled environment setting. The consent
gate `--enable-extra-fixes` is command-line only. Choose only one of
`--refresh-sury-signing-key` and `--add-os-security-repository` per attempt; selecting
both is an argument error before any check or change starts.

An explicit `--check` with the same method flags remains an assessment. It does
not add sources, replace keys, refresh package indexes, install packages or restart
services. Its information comes from cached indexes; refresh the repaired or newly added source to inspect current candidates. The normal logging rules still apply.

## Use Sury packages

Switch from distribution PHP packages to third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages while keeping the PHP version branch your applications use. This also changes where future PHP updates come from.

The script checks the current package publishers first and applies any verified
updates it finds there. Sury or the PPA is a fallback for eligible PHP branches
that still lack a verified fix from their current source. The ordinary
November update considers an eligible configured Sury or PPA repository.

**Compatibility option:** `--migrate-php-to-sury`

**Environment equivalent:** `DP2S_MIGRATE_PHP_TO_SURY=true`

On Debian, the alternative package repository is Sury's PHP repository at
`https://packages.sury.org/php`. On Ubuntu, it is Ondřej Surý's PHP PPA, hosted at
`https://ppa.launchpadcontent.net/ondrej/php/ubuntu`. These are third-party PHP
sources, separate from Debian's and Ubuntu's own security repositories.

With this option alone, the fallback repository must already be configured.
If a branch needs the fallback and its source is missing, separately select
`--add-sury-repository`. The script honours existing APT priorities. It
refreshes APT indexes and asks APT for eligible packages through that source. It
checks the normal selected candidate, package publisher, OS suite, architecture and exact
package version. It does not fetch a guessed `.deb` URL or search an old archive
for any package that happens to install.

Migration retains the reviewed binary package names, PHP branch, architecture and
extension API. For example, an eligible PHP 8.2 installation remains PHP 8.2; this
is not permission to move its websites to PHP 8.4. Unversioned selectors,
`php-common`, `php-pear` and unreviewed extensions remain at their installed versions. A plan requiring new packages,
removals or unrelated changes is refused. Verified necessary upgrades of reviewed installed native libraries are included
as part of the update. On Debian 11, explicit Sury migration can also upgrade
the already-installed shared PCRE2 library from Sury when the chosen PHP build
requires it. That library can be used by other applications.

The supported migration combinations are Debian 11/12/13 and Ubuntu 22.04/24.04,
on amd64. Panel-managed installations and unverified equivalents stay blocked.
Keeping a PHP branch reduces the size of the change; publisher patches, packaging
and configuration can still differ. Test the affected sites and scheduled jobs.
The PHP packages and future updates now come from Sury/ondrej, and there is
no automatic package rollback.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --migrate-php-to-sury
```

## Use an existing Freexian repository

When a November check finds no verified update plan, it can report Freexian
setup or subscription guidance for installed PHP branches, including on a
server without a configured Freexian feed. Automatic use requires a fresh,
signed Extended LTS index and a successful package simulation. Eligible
native PHP updates can use a required installed library from the same
verified public ELTS suite. The package plan must establish the exact
installed library, its selected build and the PHP version requirement.

The ordinary November check and fix consider an already configured, signed
public Extended LTS feed for the reviewed native Debian PHP branches below.
APT keeps signature and priority checks. A verified native Debian candidate
at the same APT priority takes precedence over Extended LTS. Existing
commands using `--allow-freexian` are accepted for compatibility.

| OS | Native PHP | Reviewed November build |
| --- | --- | --- |
| Debian 9 Stretch | 7.0 | `7.0.33-0+deb9u27` |
| Debian 10 Buster | 7.3 | `7.3.31-1~deb10u17` |
| Debian 11 Bullseye | 7.4 | `7.4.33-1+deb11u15` |

The installer checks the fresh signed release from
`https://deb.freexian.com/extended-lts` for the matching suite or its
`-lts` variant. Make the published Freexian Extended LTS key available in
an existing Freexian-named APT keyring and resolve any failed repository
refreshes. The method changes only reviewed native PHP packages and any
already-permitted required libraries. It preserves the PHP branch and
extension API. Package updates can interrupt services. Test websites and
jobs after the change. [Freexian feed setup](https://www.freexian.com/lts/extended/docs/how-to-use-extended-lts/)

### Repository access for subscribers

The public Extended LTS feed above uses no login. Freexian also offers a
subscriber ELTS feed at `security.freexian.com`. Store that feed's username
and password in a root-owned APT authentication file such as
`/etc/apt/auth.conf.d/freexian-elts.conf` with mode `0600`.
[Subscriber ELTS setup](https://www.freexian.com/lts/extended/docs/how-to-use-extended-lts-repositories/#configuring-authentication-for-apt)

Freexian PHP LTS is a separate subscription for versioned PHP packages,
including PHP 5.6 on Buster. Freexian issues an APT URL with an access token
in its path. Add the issued source locally in
`/etc/apt/sources.list.d/freexian-php-lts.list` and scope the published PHP
LTS signing key to that entry with `signed-by`. Keep the source file and logs
private. APT can put the token in local index filenames, so check local
visibility on multi-user hosts. [PHP LTS APT setup](https://www.freexian.com/lts/php/docs/access-apt-repositories/)

Run `--check --november-2026` after setup. DePHP2Shell reports matches from
the cached PHP LTS index and redacts the token. The full installed revision
and a vendor advisory or package changelog are needed to verify a backported
fix. A listed candidate can still return HTTP 403 if the subscription does
not cover its PHP branch and OS. [PHP LTS entitlement FAQ](https://www.freexian.com/lts/php/faq/)

## Add the community Debian PHP Backports repository

The ordinary November check and fix can use an eligible, configured Debian
PHP Backports repository as a last resort. The feed must supply an exact
reviewed security build for the installed PHP branch. Check mode refreshes
the enabled APT metadata and simulates the package transaction.

If the check offers adding or expanding the community feed, approve only
the PHP branches it lists. This example approves the two source package
names shown. Use `php5` for a legacy native source package with that name.

```bash
bash dephp2shell.sh --check --november-2026
bash dephp2shell.sh --fix --november-2026 --enable-extra-fixes \
    --add-debian-php-backports --php-source-branches=php5.6,php7.4
```

The fix uses the matching HTTPS suite and a dedicated signing key. Before
offering to add a missing source, the check looks for equivalent packages in
the authenticated index. A changed index is usable when the reviewed package
names, versions, architectures and archive SHA256 hashes still match. A
same-version rebuild with different archive bytes requires fresh review.
The update verifies the hashes of the actual archives APT will install. The fix
simulates the approved PHP transaction before applying changes. Automatic
setup requires APT 1.1 or newer and working HTTPS transport. The managed preference permits the exact reviewed versions of the
approved installed packages. Review later community versions before changing
that preference. A later check cannot add branches to an earlier approval. Commands using
`--use-debian-php-backports` remain accepted for compatibility.

On Debian 10 Buster, the community `sury` component publishes reviewed
PHP 5.6 revision `5.6.40-110+debsuryorg12.1+1+debian10+animaa1`.
Freexian PHP LTS lists PHP 5.6 under a separate subscription. The public
Debian Extended LTS feed supplies native PHP 7.3.
[Community repository instructions](https://github.com/animaartificialis/debian-php-backports#apt-repository)

The community project publishes source archives and build workflows.
The reviewed Buster PHP 5.6 source archive contains upstream Sury source files
that match the signed Sury index. The project applies its build changes and
produces its own binaries. The reviewed release passed container install tests
on amd64 and arm64. The publisher skips the full upstream PHP test suite.
Independent reproduction of the binaries and production adoption remain
unverified. Use this last-resort update while planning an OS migration.
[Build configuration](https://github.com/animaartificialis/debian-php-backports/blob/cf06126cf0b933a984e0b5a7f5373d8a2840b4e7/targets/debian10-buster/php5.6-sury/target.conf)
[Publisher CI run](https://github.com/animaartificialis/debian-php-backports/actions/runs/45085778049)

## Repair a retired distribution mirror

The ordinary November fix can repair a stock, matching Debian or Ubuntu APT
source when its refresh returns 404 or reports a missing Release file. The
script keeps the same OS release and uses the official distribution archive.
The repaired sources must pass a fresh authenticated APT refresh. If the retry
fails, the script restores the changed source entries. Check mode reports the
failure with the source files intact. Review failing third-party sources and
repository authentication separately. The live Ubuntu archive remains the
source for Trusty, Xenial, Bionic and Focal. An archived Ubuntu suite uses
`old-releases.ubuntu.com` where the installed PHP has an eligible update path.
[Debian archive](https://www.debian.org/distrib/archive)
[Ubuntu old release package archive](https://old-releases.ubuntu.com/ubuntu/dists/)

## November source choice by PHP branch

Identify who manages each PHP installation. Start with the panel's update
path for the PHP it supplies. Use the installed package publisher for
separate system PHP, including binaries used by cron or the command line.

### Hosting panel update paths

`--check` inventories PHP and reports blockers. The `--fix` column describes
what DePHP2Shell attempts when its prerequisites pass. Verify the running
PHP and test the affected sites and jobs after an update.

| Panel | PHP update source | What `--fix` handles | What the operator handles |
| --- | --- | --- | --- |
| cPanel | cPanel's security updater for internal PHP. Configured EasyApache 4 package repositories for EasyApache website PHP. [EasyApache 4 docs](https://docs.cpanel.net/ea4/basics/about-easyapache-4/) | On a supported install, runs `upcp --security`, then attempts to update installed website PHP packages through the package manager. Rechecks panel and website PHP separately. | Resolve licensing, update preferences, or package conflicts if the updater skips or fails. Review unsupported handlers and choose any site PHP version changes in WHM. |
| Plesk | Plesk's component updater for Plesk-supplied PHP. A separate system or custom handler follows its own publisher. [Plesk update docs](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-updates.59215/) | Runs the Plesk Installer for installed components within the current supported Plesk release. The component update can also affect databases, mail, and web servers. | Review the wider component update and separately patch system or custom PHP still flagged by the check. |
| DirectAdmin | DirectAdmin CustomBuild for the PHP branches it builds. [CustomBuild update docs](https://docs.directadmin.com/custombuild/upgrading-services.html) | Detects DirectAdmin and inventories PHP. The script blocks automatic changes on this setup. | Review the configured PHP branches and update them through CustomBuild. Check its version overrides and rebuild affected extensions as needed. |
| Virtualmin | The installed distro or third-party repository supplies PHP through APT or DNF. Virtualmin selects the handler and version per site. [Virtualmin PHP docs](https://www.virtualmin.com/docs/server-components/configuring-multiple-php-versions/) | Attempts eligible package-managed PHP updates from the existing repositories and restarts supported services. Reports APT pins that can block Apache `mod_php` updates. | Review each site's PHP handler, resolve pins or source issues, and make any handler changes in Virtualmin. Update custom PHP builds separately. |

CloudLinux or CageFS detection sends the setup to manual review, including on
a host with a supported panel updater. Review the PHP publisher and the
runtime copies each site actually uses.

### Package-managed PHP sources

Start with the installed publisher. Keep the PHP branch and verify the signed
OS suite, full fixed revision, and extensions. If the current publisher
cannot supply a fix, check the distro security feed and eligible alternatives.
The ordinary November update uses eligible configured Sury/ondrej and public
Freexian Extended LTS repositories, then Community Debian PHP Backports as a
last resort. Adding or expanding an offered source requires explicit approval
for that repository and the recommended PHP branches.

| OS | Native PHP and preferred source | Alternatives for installed non-native PHP |
| --- | --- | --- |
| Debian 13 Trixie and 12 Bookworm | PHP 8.4 from Debian security and 8.2 from Debian LTS, respectively. | Keep an eligible installed Sury branch on Sury. Check subscribed Freexian PHP LTS for listed pairs. |
| Debian 11 Bullseye | PHP 7.4 from Freexian Extended LTS. | The checked Sury index had October builds. Check subscribed Freexian PHP LTS for other branches. |
| Debian 10 Buster | PHP 7.3 from Freexian Extended LTS. | For PHP 5.6 or 7.4, check subscribed Freexian PHP LTS first. Community Backports publishes reviewed builds for both. |
| Debian 9 Stretch | PHP 7.0 from Freexian Extended LTS. | Check subscribed Freexian PHP LTS. Community Backports publishes reviewed builds for 5.6, 7.3, and 7.4. |
| Debian 8 Jessie, 7 Wheezy, and 6 Squeeze | Community Backports for installed PHP 5.6 on Jessie or 5.4 on Wheezy and Squeeze. Squeeze's native PHP 5.3 needs a branch migration. | Community Backports also publishes versioned PHP 5.6 and 7.1 for Jessie. |
| Ubuntu 26.10 Stonking | PHP 8.5 from Ubuntu security. | The checked Sury and Launchpad PPA suites had no candidates. |
| Ubuntu 26.04 Resolute, 24.04 Noble, and 22.04 Jammy | PHP 8.5, 8.3, and 8.1, respectively, from Ubuntu security. | Use the eligible installed Sury family source. The PPA has verified Jammy and Noble candidates. Resolute has signed Sury mirror candidates and an empty PPA index. Check subscribed Freexian PHP LTS for listed pairs. |
| Ubuntu 20.04 Focal and 18.04 Bionic | PHP 7.4 and 7.2, respectively, from Ubuntu Pro. | Check subscribed Freexian PHP LTS. Community Backports publishes reviewed builds for 5.6, 7.2, and 7.4 on both releases. |
| Ubuntu 16.04 Xenial and 14.04 Trusty | PHP 7.0 and 5.5, respectively, from Ubuntu Legacy. | Community Backports publishes reviewed builds for Xenial PHP 5.6, 7.3, and 7.4 and Trusty PHP 5.6 and 7.4. |
| AlmaLinux 8, 9, and 10 | Prefer the installed AlmaLinux stream. Reviewed November builds cover 7.4 and 8.2 on EL8, 8.0 and 8.2–8.4 on EL9, and 8.3–8.4 on EL10. [AlmaLinux advisories](https://almalinux.org/blog/2026-11-19-php-security-release/) | For other branches, check the installed vendor's advisory or review a supported stream change. |
| Rocky Linux 8, 9, and 10 | Prefer the installed Rocky Linux stream. Reviewed November builds cover 7.4 and 8.2 on EL8, 8.0 and 8.2–8.4 on EL9, and 8.3–8.4 on EL10. [Rocky Linux advisories](https://errata.rockylinux.org/) | Check the installed vendor and architecture. Where the native branch has retired, review a maintained stream or a verified fix from the installed publisher. |
| CentOS Stream 9 and 10 | Stream 10 publishes fixed PHP 8.3 and 8.4. The checked Stream 9 packages predate the November release. [Stream 9 AppStream](https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/Packages/) · [Stream 10 AppStream](https://mirror.stream.centos.org/10-stream/AppStream/x86_64/os/Packages/) | Check the installed vendor, such as Remi, before planning a supported stream change. |
| RHEL, Oracle Linux and Fedora | Prefer a verified build for the installed distribution and PHP stream. The checker recognises upstream fixed releases. Vendor backports below those releases require a matching reviewed rule. | Consult the publisher's advisory for the exact release and package. Fedora RPMs can be checked, but Fedora has no automatic update recipe. |
| CentOS Linux 6–8 and CentOS Stream 8 | The distribution archives preserve historical PHP packages. Use an installed vendor with a verified fix or plan an OS migration. [CentOS lifecycles](https://www.centos.org/cl-vs-cs/) | Check the existing panel or PHP publisher, such as cPanel, CloudLinux, or TuxCare. |

The community rows describe standard builds reviewed from `v2026.11.25`.
The project publishes amd64 packages for all listed targets and arm64 packages
for its Buster and Focal targets. The script requires the canonical signed
HTTPS feed. Old APT clients that cannot reach that endpoint need a manual
plan. On Ubuntu 18.04 the stock `php-common` is below the minimum for the
reviewed PHP packages. The fix verifies and pins the matching Backports
`php-common` update when this stock package is installed. It stops if the
simulation needs changes outside the approved cohort and verified dependencies.
[Community release](https://github.com/animaartificialis/debian-php-backports/releases/tag/v2026.11.25)

### Remi PHP on Enterprise Linux

Keep Remi as the publisher for an existing Remi deployment. On a native PHP
deployment, prefer the installed distro stream when it has a verified fix.
Remi supplies additional maintained PHP branches on EL8–10 for x86_64 and
aarch64 through `remi-modular` and parallel Software Collections in
`remi-safe`. Its November versions include 8.2.36, 8.3.37, 8.4.28 and
8.5.13. Remi also publishes 8.6.0 and selected backports for retired branches.
Check the exact build and plan migration from retired branches to a maintained
one. [Remi November releases](https://blog.remirepo.net/post/2026/11/19/PHP-version-8.2.36-8.3.37-8.4.28-8.5.13) · [Remi 8.6 release](https://blog.remirepo.net/post/2026/11/20/PHP-version-8.6-is-released)

For an existing Remi PHP 8.1 stream, the same-branch `8.1.34-7` rebuild is
the smaller application change. Its November session mitigation relies on
`session.upload_progress.enabled` remaining off for affected applications.
Review effective PHP-FPM and Apache settings when local configuration overrides
the package defaults. [Remi PHP 8.1 backports](https://blog.remirepo.net/post/2026/01/08/PHP-8.1-is-retired) · [Backport changelog](https://github.com/remicollet/php-src-security/blob/PHP-8.1-security-backports/NEWS)

On supported DNF4 systems, the script can install verified runtime libraries
required by the PHP update. For example, Remi's `php-intl` can require
`libicu78`. DNF omits weak additions such as `icu-tzdata`. Packages with
unverified contents or publishers still require manual review.

## Use the StackX PHP fallback

StackX offers amd64 PHP 5.6 and 7.0–7.4 on Debian 9 Stretch, 10 Buster and
11 Bullseye. Its main repositories also offer PHP 8.0–8.1 on Stretch, 8.0–8.3
on Buster and 8.0–8.5 on Bullseye. The fallback covers those published branches
on machines without a detected hosting panel and on Virtualmin. Virtualmin keeps
its per-site PHP handlers, pool configuration and existing APT restrictions.
[StackX release notes](https://www.christophe-casalegno.com/en/contributions/stackx-php-maintenance-and-fixes-for-debian-9-10-11/)

The StackX choice configures the matching repository when needed. It verifies
the publisher signing fingerprint
`AF97 ED98 AACE 4CE1 29A0 3B6E 2C97 36B5 93BA BF7F`, installs a dedicated keyring
and creates an APT preference scoped to the selected installed PHP packages.
It retains an existing signed StackX source and its settings. A new source,
keyring and preference are removed if validation stops before installation.
They are retained after an installation attempt so packages can be recovered.
[StackX public key](https://mirrors.scalarx.net/stackx-php/stackx-repository.asc)

A check inspects the signed candidate index when StackX needs setup and
simulates the update when the source is already configured. Use `--fix` in
the maintenance window to configure the repository and run the simulation
before installing. The November patch page offers the same scoped choice.

```sh
sudo bash dephp2shell.sh --check --november-2026 --enable-extra-fixes \
  --use-stackx --php-source-branches=php5.6,php7.3
```

`DP2S_USE_STACKX=true` is equivalent to `--use-stackx`. Run StackX on its own.
APT must select the exact reviewed revisions from the canonical signed feed. The script
matches the source package and PHP extension API, checks archive hashes and
retains unselected PHP branches at their installed versions. If a plan needs
an unapproved dependency, such as a StackX-supplied shared PCRE2 library, it
stops before installing.

Start with test hosts. After the update, rerun the November check and test the
affected websites and scheduled jobs. [Reviewed StackX builds](stackx-backport-evidence.md)

### Verify older-release packages and republished builds

On Debian and Ubuntu, a package left over after an OS upgrade can still be
assessed against the advisory for its original release when its native
revision and installed source identity agree. The update still uses the
running OS release when considering package sources. Review other PHP
packages with uncertain origins using the complete source revision and a
published advisory or a source comparison.

For a higher-assurance check after a same-version rebuild, obtain the exact
binary archive using a signed repository or publisher release manifest.
Compare its SHA256 with the reviewed digest, extract it in a temporary
directory with `dpkg-deb -x`, and compare the installed executable and
security-relevant modules with those files. For a running service, check the
executable or module mapped by the process too. A service can still be
running the earlier file after a package update.

For leftover PHP, review the recorded processes and enabled handlers, the
default CLI and scheduled jobs. A check can simulate removal with APT and
list packages that would be changed, including dependent packages. Use that
plan to identify what must be migrated before removal.

## Add the Sury or PPA repository

Allow the script to add an offered missing Sury or PPA source. Each
repository approval covers the PHP branches listed by the check. The new
source is limited to the approved scope and the reviewed Debian 11 PCRE2
dependency where applicable.

For November PHP, review the listed branches before approving this repository
change. Candidate selection follows a signed index refresh and validates the
exact build, origin, and compatibility before applying changes. The older
migration procedure uses `--migrate-php-to-sury` with `--enable-extra-fixes`
and a supported migration combination.

**Option:** `--add-sury-repository`

**Environment equivalent:** `DP2S_ADD_SURY_REPOSITORY=true`

The script can create exactly these dedicated files:

- `/etc/apt/sources.list.d/dephp2shell-sury-php.list`
- `/etc/apt/keyrings/dephp2shell-sury-php.gpg`
- `/etc/apt/preferences.d/dephp2shell-sury-php.pref`

The source uses the matching installed OS suite, `main`, amd64 and a `Signed-By`
reference to that dedicated key. The file names are the same for the Ubuntu PPA.
Existing active definitions and disabled Deb822 stanzas (`Enabled: no`) are
retained, including recognised extrepo-managed sources. The script does not repair
these by creating a duplicate or overwrite a conflicting dedicated file. Commented-out
lines in a classic `.list` file are ignored; those comments do not prevent adding
a new source.

The **public signing key** is downloaded directly: from
`https://packages.sury.org/php/apt.gpg` on Debian and Ubuntu 26.04, or
`https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6`
on Ubuntu 22.04 and 24.04. The script checks the reviewed primary fingerprint before using it.
The key is limited to the dedicated source instead of being added to global APT
trust. Existing `curl` or `wget`, plus `gpg`, are required; the script does not
install those tools.

PHP packages are then obtained by APT from authenticated repository metadata,
using verified repository candidates. The new files are removed on exit if the
script stops before attempting a migration installation. Once it attempts that
installation, the files are kept for recovery and future updates, even if the
installation fails.

A retained source can affect later APT operations. This is an ongoing package-source
choice, not a temporary one-package download. Review the migration risks above.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes \
  --migrate-php-to-sury --add-sury-repository
```

For November, add `--november-2026` and the exact `--php-source-branches`
argument shown by the check.

## Repair the existing Sury signing key

Restore access to an existing Sury update source by replacing the key used to verify its downloads. The script keeps a backup of the old key.

Use this when the recognised standard Sury source has an expired or mismatched
installed key. The benefit is restoring authenticated access to the existing
source, without changing PHP package publisher or adding another repository.

**Option:** `--refresh-sury-signing-key`

**Environment equivalent:** `DP2S_REFRESH_SURY_SIGNING_KEY=true`

The repair downloads the public key from `https://packages.sury.org/php/apt.gpg`,
checks its reviewed primary fingerprint, and replaces
`/usr/share/keyrings/debsuryorg-archive-keyring.gpg`. It does not download the
`debsuryorg-archive-keyring` package or a PHP `.deb` directly. A persistent copy of
the original key is saved as `/usr/share/keyrings/dephp2shell-sury-backup.*`; the
run reports its actual path.

No source definition is rewritten. The keyring must be a regular, package-owned
file and the Sury definition must match the reviewed same-release format.
Extrepo-managed sources, custom key layouts, disabled/nonstandard definitions and
wrong suites need the separate review described under [repository repair advice](#repository-repair-advice).
This recipe covers Debian 11/12/13, not the Ubuntu PPA's key management.

The replacement key and backup persist if the subsequent PHP update fails.
Repairing a key does not repair DNS, an incorrect repository URL, missing packages
or an unsupported release. APT still checks repository signatures and candidates.
The fix attempt may then download PHP updates and restart services.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --refresh-sury-signing-key
```

## Add a missing native security source

Give the server access to the matching Debian or Ubuntu security repository. This adds a lasting update source that can also affect software beyond PHP.

Use this when the supported OS has a verified native main source but lacks its
matching security definition. It can make a distribution-provided PHP security
update available without moving PHP to Sury.

**Option:** `--add-os-security-repository`

**Environment equivalent:** `DP2S_ADD_OS_SECURITY_REPOSITORY=true`

The script adds `/etc/apt/sources.list.d/dephp2shell-native-security.list` with
`main` and the installed release's security suite:

| Distribution | Repository | Signing key already installed on the server |
| --- | --- | --- |
| Debian 11/12/13 | `https://security.debian.org/debian-security`, using `bullseye-security`, `bookworm-security` or `trixie-security` | `/usr/share/keyrings/debian-archive-keyring.gpg` |
| Ubuntu 22.04/24.04 | `https://security.ubuntu.com/ubuntu`, using `jammy-security` or `noble-security` | `/usr/share/keyrings/ubuntu-archive-keyring.gpg` |

It downloads no new signing key and does not rewrite the existing main source.
An existing matching security definition, including a disabled Deb822 stanza,
needs review rather than duplication. Commented-out classic `.list` lines are
ignored. Mixed native suites or an unverified keyring block this repair. An existing exact file created by this method is retained.

The fix then refreshes indexes and checks PHP candidates through APT. This adds a
persistent security source for all packages in that component, although the PHP
transaction remains scoped. It does not enable `universe`, other components,
Ubuntu Pro/ESM, subscriptions or a different OS release. The new source remains if
later patching fails. A usable security source still might not contain the PHP
fix needed by this installation.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes \
  --add-os-security-repository
```

## Finish pending PHP package configuration

Before configuring a pending PHP-FPM package, the script checks the accounts in
its standard pool configuration. An unresolved user blocks package repair.
Check the account and the site's pool assignment before retrying. The script
can still report newer candidates from configured APT sources while repair is
pending. Candidate availability alone does not establish a security fix or a
successful installation plan.

If package configuration fails, the report names the targets and dpkg exit code.
For FPM packages it also collects limited service state, recent unit journal entries
and a standard-configuration test. Fix the reported startup/configuration problem
before retrying; the same incomplete configuration is not offered again in that
fix run. Website assignments and scheduled jobs determine whether an old PHP
installation can instead be removed. The script does not edit FPM settings or
remove packages automatically.

Finish setting up PHP packages left incomplete by an interrupted or failed installation. Their setup scripts run again and can change configuration or services.

Use this when PHP package files have been unpacked but their installation setup
has not finished. This can happen after an interrupted update or a failed package
setup script. Finishing setup can restore a usable package state and let the PHP
security update proceed.

**Option:** `--configure-pending-php-packages`

**Environment equivalent:** `DP2S_CONFIGURE_PENDING_PHP_PACKAGES=true`

This repair downloads no packages and changes no repository definitions. It runs
`dpkg --force-confold --no-triggers --configure` for an explicit list of verified
PHP packages. It uses noninteractive package setup, then explicitly finishes
pending package callbacks, called *triggers*, only for the approved PHP targets.
Unrelated pending packages or trigger chains stop the repair. The package/source
identity must be recognised; panel-managed repairs and broader broken state are
excluded. The subsequent ordinary fix can still refresh indexes and download
newer PHP packages.

### Is this the same as configuring everything pending?

No. `dpkg --configure -a` finishes setup for **all** unpacked, unconfigured packages.
`dpkg-reconfigure` is a different command that repeats setup for already configured
packages and can ask their setup questions again. DePHP2Shell runs neither blanket
operation. See the [dpkg manual](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html#ACTIONS)
and [dpkg-reconfigure manual](https://manpages.debian.org/bookworm/debconf/dpkg-reconfigure.8.en.html).

Completing interrupted configuration is a normal recovery operation. Debian's
[package policy](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html#maintainer-scripts-idempotency)
expects setup scripts to cope with being run again. Review the original failure and resolve its cause before retrying that package's setup script. On a fully configured
system there is no pending configuration to finish.

If an update was interrupted but its original problem has been resolved, finishing
setup can be the appropriate next step. If disk space, dependencies, invalid
configuration or a package bug still prevents setup, rerunning it can fail again.
An existing package problem does not make further changes harmless. A blanket
operation could also run unrelated database, mail or other service setup scripts.

Even the scoped PHP operation executes package setup code. It can create or
regenerate files, enable extensions, update caches or change services. The script
uses `--force-confold` to retain existing locally modified dpkg-managed
configuration files. That does not prevent every configuration change made by a
package's own scripts. Noninteractive mode avoids setup questions; it does not
make setup observational or prevent all service changes.

The script checks the package audit, identities, holds, free space, detected PHP
runtimes and supported service configuration/restart procedures before proceeding.
These checks cover the listed prerequisites. Earlier setup failures and website behaviour require their own review and application tests. Review the original package error
and saved diagnostics before retrying an unexplained failure.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --configure-pending-php-packages
```

## Reinstall the exact PHP package version

Repair PHP package files and records by installing the same version again. Local edits to package files can be overwritten, and that version may still need a security update.

Use this when the diagnostic identifies missing or unreadable PHP package
checksum (`.md5sums`) or installed-file-list (`.list`) metadata. These are dpkg
records about the package's files. The automatic method selects otherwise-installed
packages with this specific metadata problem. Eligibility requires the specific missing package metadata; investigate other missing or damaged executable files separately. Reinstallation also restores
package-supplied files without selecting a new package publisher or replacement version.

**Option:** `--reinstall-php-same-version`

**Environment equivalent:** `DP2S_REINSTALL_PHP_SAME_VERSION=true`

The script refreshes authenticated APT indexes, then requires the **exact installed
version** to remain the normal candidate for that package and architecture. The
reviewed native Debian/Ubuntu or Sury/PPA source and OS suite must match. This
method covers Debian 11/12/13 and Ubuntu 22.04/24.04. It does not search old mirrors,
fetch a guessed `.deb` URL, substitute another release or downgrade to whatever
archive is available. If the installed version is no longer the normal candidate,
automatic exact reinstallation is blocked, even if someone could find its archive
manually.

APT downloads or reuses its cached authenticated package archive through the
configured, validated source. The exact-version plan must reinstall every target
without changing other versions, adding/removing packages or configuring unrelated
packages. The script then uses APT's `--reinstall` and `--only-upgrade` controls,
retains modified dpkg conffiles and restricts triggers as above. No repository file
is added or rewritten by this method.

Reinstalling runs package installation scripts again and overwrites package-supplied
files, so local edits outside protected conffiles can be lost. Services may change
or need restarting. Reinstalling the same vulnerable version does not patch the
vulnerability: the ordinary PHP fix and a fresh assessment follow. Unrelated old
libraries and general package-database repair are outside this option.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --reinstall-php-same-version
```

## Allow the native libraries PHP needs

Update supporting software that PHP needs before its own security update can proceed. Other applications may use that software and also need testing.

Use this when an otherwise acceptable PHP update needs a newer shared library.
A shared library is code that several applications can use. The library update can
unblock the PHP security update, but its effects can extend to other applications
using that library.

This is part of ordinary `--fix`; no separate library option or
`--enable-extra-fixes` permission is needed.

The script must prove that the proposed library is required by the selected
PHP packages or their necessary dependency chain. APT identifies new runtime
libraries through `Section: libs` in the authenticated package metadata and
verifies the final archive hashes. An APT upgrade of an already-installed
library still uses the reviewed amd64 list, including `libpcre2-8-0`,
`libonig5`, `libargon2-1`, `libxml2`, `libzip4`, `libzip5` and `libsodium23`.

Candidates come from the matching official native distribution sources through
APT. An explicit Debian 11 Sury migration can additionally select Sury's
`libpcre2-8-0` candidate from its authenticated matching bullseye source, retaining
the source package and amd64 architecture, when a versioned PHP dependency proves
the upgrade necessary. This exception does not permit other Sury libraries or
apply to an ordinary native update. Packages are never fetched from a hard-coded
package URL. The supported dependency
method covers Debian 11/12/13 and Ubuntu 22.04/24.04/26.04. Other selected methods
still have their own OS limits. The script pins the approved normal candidate
versions, repeats the simulation and checks the actual plan before installation.
DNF4 uses the tested package's shared-library ABI, files and publisher to
verify required additions from reviewed native repositories or `remi-safe`
for installed Remi PHP. It skips weak dependencies.

Fix mode installs the approved libraries as part of the PHP update. APT package
holds remain in effect. Review proposed removals, replacements, downgrades and
other package changes separately. Use `--check` to inspect without installing.

Package scripts can run, PHP/web services may be restarted, and other applications
using these libraries need consideration. The tool does not restart every process
on the server or test all those applications. Arrange application checks alongside
the PHP website checks.

```sh
sudo bash dephp2shell.sh --fix
```

## Package-manager locks

A lock conflict stops the update. Ask an administrator to investigate the owning
operation's progress and logs before retrying. The script does not offer a timed
wait as a repair. Stopping a package manager or removing its lock can leave package
installation or configuration unfinished.

An early warning identifies APT/dpkg lock owners running for at least one hour,
including their PID, parent, process name and runtime. Lock acquisition time is
unavailable. The warning supplies read-only `ps` and `lslocks` commands for review;
it does not suggest killing the owner. Warnings never stop jobs or delete locks.
They cover standard APT/dpkg lock paths when kernel-lock and process metadata are
readable.

## Temporarily stop PHP exposure

After an unresolved fix attempt, DePHP2Shell suggests commands to stop the PHP
services it observed. Stopping them can interrupt websites, background work and
panel functions sharing those services. The script prints these commands for you
to review and run; it never shuts down applications as a mitigation automatically.

For PHP-FPM, each identified instance gets its own service stop command. Apache
and nginx can keep serving other content when PHP runs only in separate FPM
workers; PHP requests may fail until PHP is restored. When Apache embeds PHP or
launches PHP CGI workers, the suggested Apache stop affects every site in that
instance, including sites without PHP.
Do not generically disable Apache's PHP module or remove its handler: configuration
may fail, and some configurations can serve PHP source instead of executing it.
PHP's [Apache integration guide](https://www.php.net/manual/en/install.unix.apache2.php)
and Apache's [handler documentation](https://httpd.apache.org/docs/2.4/mod/mod_mime.html)
describe the separate FPM and embedded-module arrangements and handler mappings.

The commands include observed systemd socket, timer and path activation triggers
that could restart the PHP service. An unavailable or incomplete trigger query
is reported explicitly. A service stop does not disable it at boot or prevent a
panel, supervisor or administrator from starting it again. See
[systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

The listed commands cover identified services only. Stop separately managed PHP
workloads in their own environments. Review PHP-specific schedules and background
jobs; stopping FPM or Apache does not stop running CLI jobs. For Supervisor, use
`sudo supervisorctl status` to identify the affected PHP programs, then
`sudo supervisorctl stop PROGRAM`, replacing `PROGRAM` with an affected program's
exact name. Do not stop all of cron or Supervisor.
Unidentified launchers require an administrator's review rather than a guessed
stop command. Verify that the affected PHP workers have stopped and cannot be
relaunched. Keep those applications offline until their PHP fixes are verified;
stopping a service does not install a security fix.

## Shared limits and recovery

A package simulation checks the proposed transaction; it does not execute the
package setup scripts or test the applications. Approval of the package list does
not sandbox those scripts. The script preserves existing trust checks and package holds. Review package-provided setup actions and their configuration/service effects before proceeding.

Configuration, reinstallation and updates can interrupt websites. After a package
transaction attempt, the script still attempts the supported saved PHP/web service
restarts and verifies them, including after a package command fails. A failing
restart can leave an application unavailable. An already running CLI job can keep
old PHP code even after the on-disk executable has been updated.

There is no automatic package rollback. A failure or timeout can leave packages,
configuration or services partly changed. Retained repository definitions and key
backups follow the individual rules above. Review the complete log and package
state before repeating a failed command; repeatedly adding permissions is not a
substitute for identifying the blocker. Check websites, background jobs and
application logs after the maintenance, then run `--check` again.

The script does not upgrade the operating system, reboot the server, change
individual website PHP selections or rebuild custom PHP. A PHP fix does not restore
operating-system support. Application-specific Supervisor configuration and
separate environments still need their own procedures.

## When these methods do not fit

| Setup without a suitable automatic path | Practical next step |
| --- | --- |
| Retired OS release or architecture with no maintained package route | Plan migration to a maintained OS and test the applications there. An archive preserves old packages; it does not add new security fixes. |
| Several PHP branches, with an older branch lacking a suitable fix | Move its websites, applications and scheduled jobs to a patched branch. Test them before removing unused older packages. |
| Custom, embedded or panel-specific PHP without a verified update path | Use a procedure for that product or build. Replacing the host's PHP packages may leave that runtime unchanged. |
| Containers or other separate application environments | Check and update PHP inside each affected environment. Assess their PHP packages and running workers inside each environment. |
| No compatible fixed candidate from the current or explicitly approved alternative source | Review a patched PHP branch or move applications to a server with a supported OS and PHP. A new server can use your current hosting provider. Do not force packages from a different OS release. |

These categories describe the current automation coverage. Check the exact package publisher, package revision and installation for a maintained fix route.

For an upgrade or migration you plan to do yourself, see the [DistroRejuve guide](https://github.com/pbkwee/distrorejuve/blob/master/docs/ai-assisted-migration.md).

RimuHosting offers a free, no-obligation assessment for servers hosted here or elsewhere. The report covers ways to reduce exposure or move to supported OS and PHP versions. You can keep your current hosting provider and approve any further work separately. [Request an assessment at DistroRejuve](https://distrorejuve.com/).
