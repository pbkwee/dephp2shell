# Choosing a resolution

If a PHP security update cannot finish, these options let you choose what else may change on your server. Some finish an interrupted installation; others restore access to updates or switch the PHP provider. Each section starts with the purpose, then explains the files, downloads, service changes and risks.

Start with `--check`, then use `--fix` to attempt an update through the server's existing PHP package sources. Read the specific blocker if that attempt cannot finish. A missing script procedure does not establish that no fixed package exists.

Choose the smallest change that can leave every PHP installation patched. Updating one PHP branch does not fix another branch, and changing the default command-line PHP does not move individual websites or scheduled jobs.

## Keep the existing packages first

| What the check reports | Next step |
| --- | --- |
| Native distribution PHP with an available security update | Repair or enable the appropriate existing distribution security source, then retry. A third-party PHP source is unnecessary when the distribution supplies a fix. |
| Older Ubuntu with fixes available through Ubuntu Pro or Legacy support | Review the required support entitlement and repositories. The script does not obtain or enable a subscription. |
| A package-manager lock or broken repository access | Let an active package operation finish, or repair the reported repository problem, then retry. Keep signature and certificate checks enabled. |
| Fixed packages installed, but old PHP processes remain | Replace the affected processes using their application's shutdown and restart procedure, then rerun `--check`. |
| Supervisor or another application launcher cannot be restarted safely by the script | During maintenance, stop only the affected programs and confirm their PHP children stay stopped. Retry `--fix`, restore the programs even if patching fails, test them and rerun `--check`. |
| A supported hosting panel owns PHP | Use the recognised panel update path. Check panel licences and updater failures. Panel updates can affect more than PHP. |
| A package build has no verified fix rule | Obtain evidence for that exact package revision or update it to a verified fixed build. An old version number alone does not prove a vendor backport is missing. |

Existing Sury/ondrej packages can use a recognised fixed revision from their configured source and PHP branch.

A successful package update still needs an application check. Other PHP copies, isolated environments and workers using old code can keep the overall result unresolved.

## What refreshing and installing mean

A repository is a configured package source. Its **source definition** tells APT
where to look. A **signing key** lets APT authenticate the repository's published
metadata. A **package index** is the downloaded catalogue of available versions.
The package archive contains the software itself.

Refreshing indexes, like `apt-get update`, downloads catalogues and writes APT's
local list/cache files on this server. It does not change the provider's repository,
install PHP or edit the source definitions. Installation is a separate step that
downloads or reuses package archives and runs their setup scripts. See the
[APT manual](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html#update).

A normal `--fix` uses the existing configured sources. Depending on the server,
these can be Debian/Ubuntu mirrors, an existing Sury/PPA source or another supported
provider. APT resolves package URLs from its authenticated metadata. The APT methods here
do not fetch a standalone PHP `.deb` from a hard-coded URL to bypass the configured
repositories. The explicit key operations below are different: they download public
signing keys from named HTTPS endpoints.

Routine APT PHP updates do not directly rewrite source definitions. A supported
hosting-panel update invokes vendor tooling with a broader scope: Plesk can update
non-PHP components, and panel tools can manage their own repositories/configuration.
Check the detected panel's update description as well as the option chosen here.

## Repository repair advice

Checks and fixes report recognised source layouts without changing them:

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
those sources, replace keys or execute repository setup commands. Source layout
alone does not establish a repository failure or change PHP vulnerability state.

## Compare the options

These options add permission to a fix attempt. They do not guarantee that a fix is
available. After a successful repair, the script checks PHP again and can continue
with the ordinary PHP update and service restarts. A command selecting a key or
package repair is therefore **not a repair-only command**.

The table describes the selected action's direct changes. Package installation
scripts and hosting-panel updaters have their own effects, explained below.

| Option | APT source or signing-key files | Selected action | Main benefit and risk |
| --- | --- | --- | --- |
| `--fix` | No direct source/key edits by this script. Panel tools have their own scope. | Refresh indexes, install allowed PHP updates and replace supported workers. | Obtain fixes through existing sources; package scripts and restarts can interrupt sites. |
| `--migrate-php-to-sury` | Unchanged unless repository addition is separately permitted. | Replace eligible distribution PHP packages with Sury/PPA builds of the same PHP branch. | Obtain a verified fix from another provider; future updates use that provider and applications still need testing. |
| `--add-sury-repository` | Can add one source file and a dedicated key. | Make the matching Sury/PPA repository available for the approved migration. | Supply missing candidates; the new source can affect future package-manager choices. |
| `--refresh-sury-signing-key` | Replace the standard Sury keyring; retain a backup. Source definitions stay unchanged. | Repair trust for an existing, verified standard Sury definition. | Restore authenticated repository access; a bad URL, wrong suite or unavailable package remains a separate problem. |
| `--add-os-security-repository` | Add a source file using the installed Debian/Ubuntu archive keyring. | Enable the matching native `main` security repository. | Make native security updates available; the persistent source also affects future updates outside PHP. |
| `--configure-pending-php-packages` | No direct source/key edits. | Finish setup for explicitly identified pending PHP packages. | Complete an interrupted installation; package setup scripts can change configuration and services. |
| `--reinstall-php-same-version` | No direct source/key edits. | Download and reinstall the same PHP package version. | Restore package files/metadata; setup scripts run again and the version may still be vulnerable. |
| `--upgrade-required-php-libraries` | No direct source/key edits. | Upgrade a small approved set of already-installed native libraries needed by PHP. | Unblock a PHP update; other applications may use those shared libraries. |
| `--wait-for-package-lock SECONDS` | Unchanged. | Wait for another package operation before proceeding. | Avoid a temporary lock failure; waiting does not fix a stalled package manager. |

The additional repair, repository and provider methods require
`--enable-extra-fixes` and are otherwise disabled. The lock-wait option is
independent. `--enable-extra-fixes` alone does not grant all these permissions
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
services. Its cached information cannot prove what a missing or repaired source
will supply. The normal logging rules still apply.

## Use Sury packages

Get PHP security updates from a different provider while keeping the PHP version branch your applications use. This also changes where future PHP updates come from.

Use this when an eligible distribution PHP package needs a fix that an appropriate
Sury/PPA build can supply. Try the existing provider first. Selecting migration can
choose Sury even when a distribution update would also have worked.

**Option:** `--migrate-php-to-sury`

**Environment equivalent:** `DP2S_MIGRATE_PHP_TO_SURY=true`

On Debian, the alternative provider is Sury's PHP repository at
`https://packages.sury.org/php`. On Ubuntu, it is Ondřej Surý's PHP PPA, hosted at
`https://ppa.launchpadcontent.net/ondrej/php/ubuntu`. These are third-party PHP
sources, separate from Debian's and Ubuntu's own security repositories.

With this option alone, the repository must already be configured. The script
refreshes APT indexes and asks APT for eligible packages through that source. It
checks the normal selected candidate, provider, OS suite, architecture and exact
package version. It does not fetch a guessed `.deb` URL or search an old archive
for any package that happens to install.

Migration retains the reviewed binary package names, PHP branch, architecture and
extension API. For example, an eligible PHP 8.2 installation remains PHP 8.2; this
is not permission to move its websites to PHP 8.4. Unversioned selectors,
`php-common`, `php-pear` and unreviewed extensions remain at their installed versions. A plan requiring new packages,
removals or unrelated changes is refused. Necessary reviewed library upgrades
require their separate permission.

The supported migration combinations are Debian 11/12/13 and Ubuntu 22.04/24.04,
on amd64. Panel-managed installations and unverified equivalents stay blocked.
Keeping a PHP branch reduces the size of the change; provider patches, packaging
and configuration can still differ. Test the affected sites and scheduled jobs.
The installed provider and available future updates have changed, and there is
no automatic package rollback.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --migrate-php-to-sury
```

## Add the Sury or PPA repository

Add the missing update source so the server can look for a fixed PHP build. The new source can affect future software updates; adding it does not guarantee that a fix is available.

This additionally permits a missing repository to be added. It requires
`--migrate-php-to-sury`, `--enable-extra-fixes` and a supported migration combination.
It is useful when the package identities fit the migration method but the source
is absent. Adding a source does not establish that it has a suitable fixed build.

**Option:** `--add-sury-repository`

**Environment equivalent:** `DP2S_ADD_SURY_REPOSITORY=true`

The script can create exactly these dedicated files:

- `/etc/apt/sources.list.d/dephp2shell-sury-php.list`
- `/etc/apt/keyrings/dephp2shell-sury-php.gpg`

The source uses the matching installed OS suite, `main`, amd64 and a `Signed-By`
reference to that dedicated key. The file names are the same for the Ubuntu PPA.
Existing active definitions and disabled Deb822 stanzas (`Enabled: no`) are
retained, including recognised extrepo-managed sources. The script does not repair
these by creating a duplicate or overwrite a conflicting dedicated file. Commented-out
lines in a classic `.list` file are ignored; those comments do not prevent adding
a new source.

The **public signing key** is downloaded directly: from
`https://packages.sury.org/php/apt.gpg` on Debian, or
`https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6`
on Ubuntu. The script checks the reviewed primary fingerprint before using it.
The key is limited to the dedicated source instead of being added to global APT
trust. Existing `curl` or `wget`, plus `gpg`, are required; the script does not
install those tools.

PHP packages are then obtained by APT from authenticated repository metadata,
not downloaded from a hard-coded PHP package URL. Before any package transaction
is attempted, newly created source/key files are removed on exit. After a
transaction attempt they remain, including after failure, to support recovery and
later updates. Pre-existing files are not removed by that cleanup.

A retained source can affect later APT operations. This is an ongoing package-source
choice, not a temporary one-package download. Review the migration risks above.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes \
  --migrate-php-to-sury --add-sury-repository
```

## Repair the existing Sury signing key

Restore access to an existing Sury update source by replacing the key used to verify its downloads. The script keeps a backup of the old key.

Use this when the recognised standard Sury source has an expired or mismatched
installed key. The benefit is restoring authenticated access to the existing
source, without changing PHP provider or adding another repository.

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

Give the server access to security updates from its operating-system provider. This adds a lasting update source that can also affect software beyond PHP.

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
expects setup scripts to cope with being run again. That expectation is not proof
that a particular failed script will succeed on this server. On a fully configured
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
These checks reduce known risks. They cannot establish why every earlier setup
failed or prove that every website will work. Review the original package error
and saved diagnostics before retrying an unexplained failure.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --configure-pending-php-packages
```

## Reinstall the exact PHP package version

Repair PHP package files and records by installing the same version again. Local edits to package files can be overwritten, and that version may still need a security update.

Use this when the diagnostic identifies missing or unreadable PHP package
checksum (`.md5sums`) or installed-file-list (`.list`) metadata. These are dpkg
records about the package's files. The automatic method selects otherwise-installed
packages with this specific metadata problem. An arbitrary missing or damaged PHP
executable alone does not establish eligibility. Reinstallation also restores
package-supplied files without selecting a new provider or replacement version.

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
A shared library is code that several applications can use. This permission can
unblock the PHP security update, but its effects can extend to other applications
using that library.

**Option:** `--upgrade-required-php-libraries`

**Environment equivalent:** `DP2S_UPGRADE_REQUIRED_PHP_LIBRARIES=true`

The script must prove that the proposed library upgrade is required by the selected
PHP packages or their necessary dependency chain. It permits only already-installed
amd64 native packages from this reviewed list: `libpcre2-8-0`, `libonig5`,
`libargon2-1`, `libxml2`, `libzip4`, `libzip5` and `libsodium23`.

Candidates come from the matching official native distribution sources through
APT, not directly from Sury or a hard-coded package URL. The supported dependency
method covers Debian 11/12/13 and Ubuntu 22.04/24.04/26.04. Other selected methods
still have their own OS limits. The script pins the approved normal candidate
versions, repeats the simulation and checks the actual plan before installation.

This **installs library updates**; it does not merely refresh a package list.
It adds no source definition and permits no new packages, removals, replacements,
downgrades, base-system library upgrades or RPM dependency repairs. A missing
library is not permission to install it. A proposed upgrade outside the list stays
blocked.

Package scripts can run, PHP/web services may be restarted, and other applications
using these libraries need consideration. The tool does not restart every process
on the server or test all those applications. Arrange application checks alongside
the PHP website checks.

```sh
sudo bash dephp2shell.sh --fix --enable-extra-fixes --upgrade-required-php-libraries
```

## Wait for another package operation

Give another software update time to finish before retrying this one. The script waits for a limited time without stopping the other update or deleting its locks.

Use this when an automatic package job or another administrator is already using
APT/dpkg. Give it a bounded opportunity to finish, then let the selected fix proceed.
This option does not require `--enable-extra-fixes`. The range is 0–600 seconds; zero is the
default and disables the extra waiting step.

**Option:** `--wait-for-package-lock SECONDS`

**Environment equivalent:** `DP2S_WAIT_FOR_PACKAGE_LOCK_SECONDS=SECONDS`

With a positive wait on an APT system, an existing `fuser` command checks whether
processes have package lock files open. File existence alone does not establish
that a lock is held. The open-file check is conservative and can wait on a file
that is open without a conflicting lock.

No repositories or packages change during the waiting step. The script does not
install `fuser`, remove lock files or stop processes. An unavailable/inconclusive
probe or an expired wait stops the fix. Waiting cannot repair a stuck package job
or reserve the package manager for later: APT/dpkg still enforce their locks when
the actual operation begins. Review a genuinely stalled job before retrying.

```sh
sudo bash dephp2shell.sh --fix --wait-for-package-lock 120
```

## Shared limits and recovery

A package simulation checks the proposed transaction; it does not execute the
package setup scripts or test the applications. Approval of the package list does
not sandbox those scripts. The script preserves existing trust checks and package
holds, but cannot promise that every package-provided action is harmless.

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
| Containers or other separate application environments | Check and update PHP inside each affected environment. A host update alone cannot establish their patch state. |
| No compatible fixed candidate from the current or explicitly approved alternative source | Review a PHP branch change or server migration. Do not force packages from a different OS release. |

These are limits of the current automation and evidence. They do not establish that every installation in a category lacks a fix.

RimuHosting offers a no-cost, no-obligation investigation and a report on mitigation or server migration options, including for servers hosted elsewhere. Contact RimuHosting to coordinate the server manifest and investigation. Any changes or further work are agreed separately.
