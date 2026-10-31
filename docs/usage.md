# Usage

Run the script as root for complete package and process visibility:

```sh
sudo bash dephp2shell.sh --check
```

No arguments also selects `--check`. `--help` prints usage without inspecting the server.

## Options

PHP package publishers supply PHP builds: the Linux distribution, a third-party
repository such as Sury/ondrej, or a control-panel vendor. Switching PHP package
sources changes installed software and future updates. Server hosting is a
separate choice; a vulnerable PHP package calls for reviewing its update path.

For repair and PHP package source permissions, read the
[option effects and risks](resolution-options.md#compare-the-options) before selecting
one. The guide explains repository/key changes, download locations, package setup,
service interruption and what happens after failure. These permissions add to a
fix attempt; a successful repair can be followed by ordinary PHP updates.

| Option | Behaviour |
| --- | --- |
| `--check` | Inspect PHP and report the result. Does not update packages or restart services. |
| `--fix` | Check prerequisites, attempt supported updates and service restarts, then check again. |
| `--enable-extra-fixes` | Attempt explicitly enabled alternative update methods. Each method is disabled by default. |
| [`--migrate-php-to-sury`](resolution-options.md#use-sury-packages) | With `--enable-extra-fixes`, allow a closely matched native-to-Sury PHP package change. |
| [`--add-sury-repository`](resolution-options.md#add-the-sury-or-ppa-repository) | With both options above, allow the matching official Sury/ondrej source to be added. |
| [`--refresh-sury-signing-key`](resolution-options.md#repair-the-existing-sury-signing-key) | With `--enable-extra-fixes`, replace the standard Debian Sury signing key and save a backup; source definitions stay unchanged. |
| [`--add-os-security-repository`](resolution-options.md#add-a-missing-native-security-source) | With `--enable-extra-fixes`, add a missing matching Debian/Ubuntu `main` security source using the installed archive keyring. |
| [`--configure-pending-php-packages`](resolution-options.md#finish-pending-php-package-configuration) | With `--enable-extra-fixes`, configure a verified set of pending standard PHP packages. |
| [`--reinstall-php-same-version`](resolution-options.md#reinstall-the-exact-php-package-version) | With `--enable-extra-fixes`, reinstall PHP from authenticated exact installed-version candidates to restore package metadata. |
| `--output human` | Show readable progress and results. This is the default. |
| `--output machine` | Emit the structured line protocol for integrations. |
| `--log-dir DIR` | Save this run's detailed diagnostics in a private subdirectory of `DIR`. |
| `--color WHEN` | `auto` (default), `always` or `never`; colour only decorative human-output markers. |
| `--no-color` | Disable colour. Bold is controlled separately. |
| `--bold WHEN` | `auto` (default), `always` or `never`; emphasise warning, error and result labels. |
| `--no-bold` | Disable bold emphasis. |
| `--help` | Print usage. |

`DP2S_OUTPUT`, `DP2S_LOG_DIR`, `DP2S_COLOR` and `DP2S_BOLD` supply the corresponding defaults. An explicit command-line value takes precedence.

```sh
sudo bash dephp2shell.sh --check --log-dir /root/dephp2shell-logs
sudo env DP2S_OUTPUT=human DP2S_LOG_DIR=/root/dephp2shell-logs \
  bash dephp2shell.sh --fix
```

Human output saves diagnostics under `$HOME/dephp2shellinfo/runs` by default. The console prints their location. Each private run directory has a UTC timestamp and random suffix. `output.log` holds detailed output and `exit-status` records the result. Keep the complete run directory when investigating a failure.

Choose a log directory owned by the account running the script, without group or
other write access. Its parent directories must also be trusted: the script checks
the supplied root, not every ancestor. Each run directory is mode 0700 and its
files are mode 0600. Logs are retained until you remove them.

Machine output creates no persistent log directory by default. Supply `--log-dir` if the caller also wants saved diagnostics.

## Terminal readability

Message text uses your terminal's default foreground and background. The tool
sets no background colours and uses no dim, blinking or fixed RGB text. Warning
and error labels remain readable without colour: only an optional `!` marker
uses the terminal's yellow or red palette. Bold emphasises labels and results.
The wording carries the meaning in every mode.

Both colour and bold default to `auto`. Each is enabled only for a terminal that
reports the relevant capabilities through `tput`. Redirected output, a missing or
`dumb` terminal, absent `tput`, or unsupported capabilities leave that feature
unstyled. Monochrome terminals can still support bold.

For no colour, or completely unstyled output:

```sh
sudo bash dephp2shell.sh --check --no-color
sudo bash dephp2shell.sh --check --no-color --no-bold
```

`--color always` and `--bold always` explicitly force standard ANSI styling,
including through a pipe. Use these only when the receiving terminal or viewer
supports it. The `--no-color` and `--no-bold` aliases are equivalent to `never`.

A nonempty [`NO_COLOR`](https://no-color.org/) disables colour by default,
including a `DP2S_COLOR` environment setting. It leaves bold independently
controlled. An explicit `--color` option overrides that default; options on the
command line override environment settings.

Styling is applied after writing the detailed log. Machine output and the saved
report receive no presentation escapes, even when styling is explicitly forced.
The terminal's palette is user-configurable; the tool does not try to guess your
theme or recolour the message text to compensate for it.

## Updating

Review the check first. Ensure backups, console access and a maintenance window are appropriate for the server. Then:

```sh
sudo bash dephp2shell.sh --fix
```

Fix mode uses the supported procedure for the detected setup. APT updates include
proven necessary upgrades of reviewed, already-installed native shared libraries
from matching official OS sources. These need no extra option. Other applications
may use those libraries and need testing. See [library update limits](resolution-options.md#allow-the-native-libraries-php-needs). Package holds, pins, signing requirements and package publisher boundaries remain in effect. A blocked update reports the reason and the next step. Changes can already have occurred if a package operation or restart fails; there is no automatic rollback.

The former `--upgrade-required-php-libraries` flag and
`DP2S_UPGRADE_REQUIRED_PHP_LIBRARIES` setting have been removed. Use `--fix`;
old command lines containing that flag are rejected.

Alternative methods require `--enable-extra-fixes` and a separate opt-in. `DP2S_MIGRATE_PHP_TO_SURY=true` and `DP2S_ADD_SURY_REPOSITORY=true` supply the corresponding method settings; both default to false. They do not enable package publisher changes in normal `--fix` mode. Environment booleans accept `true`/`false`, `yes`/`no` or `1`/`0`.

`--enable-extra-fixes` selects an update attempt unless `--check` is explicit. Use `--check --enable-extra-fixes` with the method options to inspect eligibility without adding sources or running package-manager network operations. A method option without `--enable-extra-fixes`, `--enable-extra-fixes` without a selected method, or repository permission without migration permission is invalid. See [resolution options](resolution-options.md) for requirements and commands, or when a check or update remains unresolved.

`DP2S_CONFIGURE_PENDING_PHP_PACKAGES` and `DP2S_REINSTALL_PHP_SAME_VERSION`
are Boolean defaults, initially false.
`DP2S_REFRESH_SURY_SIGNING_KEY` and `DP2S_ADD_OS_SECURITY_REPOSITORY` are also
Boolean defaults, initially false. Choose only one of these two repository methods
per attempt. All method settings require command-line `--enable-extra-fixes`;
the consent gate has no environment equivalent.
Explicit command-line settings take precedence over the environment.

`--check` now prints suggested options when installed or cached evidence supports
a particular update or repair. Cached simulations do not refresh repositories,
install packages or run repairs. A missing-source migration suggestion explicitly
states that its candidates have not been checked. Suggestions use the installed/cached observations; fix mode refreshes metadata and repeats all applicable safety checks.

An unresolved `--fix` run offers specific additional repairs when fresh checks
identify one. It omits a plain `--fix` retry. If no additional automatic repair is
identified, review the detailed log and remaining PHP findings, address the
reported cause, then run `--check` before deciding on another update attempt.

The complete report retains `fix_recommendation` and cached `option_assessment`
records, including reasons a potential method was refused.

Afterwards, check important website and application functions. Existing scheduled PHP jobs can retain old code until they finish. The tool does not kill those jobs or restart cron to replace them. Arrange an application-aware rerun if needed, then check again.

## Results and exit status

Read the final result even when the command exits successfully. A completed check can still find vulnerable PHP or leave a specific verification gap.

| Exit status | Meaning |
| --- | --- |
| `0` | Normal completion. Inspect the vulnerability result. |
| `1` | A required operation failed, or an update was blocked or incomplete. |
| `64` | Invalid arguments, option combinations or environment option values. |
| `69` | Non-Linux or unidentified runtime platform. |

## Machine output

For a caller that stores and parses the complete report:

```sh
sudo bash dephp2shell.sh --check --output machine
```

Messages use `dss:info:`, `dss:warn:`, `dss:error:` and update-progress records. Detailed evidence uses `dss:manifest:`. Basic host observations also use `RET:` records. These protocol names remain stable for existing integrations.

The aggregate result covers both vulnerabilities under one identifier:

```text
dss:isvulnerable:afterfix: CVE_2026_109618N
```

| Suffix | Meaning |
| --- | --- |
| `Y` | At least one PHP installation was identified as vulnerable. |
| `N` | All detected installations passed the checks, or no PHP was found within the inspected scope. |
| `?` | A specific inventory, package provenance or running-process check remains unresolved. Read the associated messages. |

The script emits `beforefix` and `afterfix` phases in check mode too. Read the update and restart records for the operations attempted; the phase labels are emitted in both check and fix mode. A vulnerable installation takes precedence over unknown findings; an unresolved finding prevents a clear result.

## Diagnostic privacy

Detailed logs can contain hostnames, filesystem paths, process and user IDs, package versions and repository metadata. URL redaction removes some sensitive values; it does not anonymise a report.

For follow-up investigation, keep the complete saved `output.log` or machine
response from the check/update that reported the problem. The human console
summary omits most manifest details. Additional package-audit and candidate-query
evidence is collected automatically when the relevant step is reached; no extra
debug flag is needed. A later check does not repeat fix-only candidate queries.

For suspected cPanel leftovers, a check includes `panel_path`, `runtime_path`
and `package_install_status` diagnostics. Compare missing core/updater files,
broken links and package-only PHP entries before deciding whether panel repair
or removal is appropriate. These observations do not enable automatic cleanup.

For a bug report, describe the script revision, distribution, architecture, action, relevant PHP versions and warning. Review any excerpts before sharing. Keep complete logs private. Nothing is uploaded automatically.
