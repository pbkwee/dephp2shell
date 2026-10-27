# Choosing a resolution

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

## Repository repair advice

Checks and fixes report recognised source layouts without changing them:

- Legacy or custom Sury PHP definitions receive a recommendation to review the
  [Sury instructions](https://packages.sury.org/php/README.txt), the installed OS
  suite and `debsuryorg-archive-keyring`. Correct the existing definition after
  review instead of adding a duplicate. A different Debian suite needs separate
  review before using its packages.
- Extrepo-managed Sury definitions receive a recommendation to review
  `extrepo update sury` when repair is needed. Check enabled state and duplicate
  definitions first. `--repair-repository sury-key` refuses these layouts because
  extrepo manages a different keyring. `extrepo enable sury` can re-enable an
  existing definition without refreshing metadata; see the
  [Debian manual](https://manpages.debian.org/bookworm/extrepo/extrepo.1p.en.html).
- Legacy Virtualmin sources receive a recommendation to review
  `virtualmin configure-repos`, or `virtualmin setup-repos` on older versions.
  The legacy repository can be intentional. Switching to the production source
  can change Webmin module packaging. Review the
  [vendor procedure](https://www.virtualmin.com/docs/installation/troubleshooting-repositories/),
  including its script alternative when the CLI is unavailable.

Disabled definitions remain visible in the manifest. The advice does not enable
those sources, replace keys or execute repository setup commands. Source layout
alone does not establish a repository failure or change PHP vulnerability state.

## Targeted repairs

A check recommends options for a recognized problem. Review that explanation
before selecting a method. Each repair below also requires `--disruptive`:

| Option | What it can do | Important limit |
| --- | --- | --- |
| `--repair-repository native-security-source` | Add a missing native security source using the installed OS suite and packaged archive keyring. | Debian 11/12/13 or Ubuntu 22.04/24.04, main component only. Existing/disabled security definitions and mixed native suites need review. It does not enable subscriptions. |
| `--repair-repository sury-key` | Refresh an expired or mismatched key in the standard package-owned Debian Sury keyring. | Same-release standard source required. Verify the downloaded fingerprint and retain a durable original-key backup. Other key/source layouts stay blocked. |
| `--allow-pending-php-configuration` | Finish configuration of verified unpacked or half-configured PHP packages. | Only known versioned PHP source packages; unrelated package state and triggers stay blocked. Package scripts can affect services. |
| `--allow-exact-php-reinstall` | Restore PHP package files and metadata using the exact installed version. | That version must still be an authenticated same-provider normal candidate. No replacement version or unrelated package repair is substituted. It may restore a vulnerable build; ordinary patch checks follow. |
| `--allow-php-dependency-updates` | Permit proven necessary upgrades of a small reviewed set of already-installed native libraries. | Reviewed APT suites and amd64 only. New packages, removals, base-system libraries, third-party libraries and unsupported dependencies remain blocked. |

For example, only when the check identifies pending PHP configuration:

```sh
sudo bash dephp2shell.sh --fix --disruptive --allow-pending-php-configuration
```

The tool repeats the audit, holds, disk, runtime and restart checks before any
repair. Successful repairs are followed by a fresh PHP inventory and ordinary
patch attempt. A failed repair can already have changed packages or services.
Verified service replacement is still attempted after a package mutation.
Unrelated newly activated triggers stop the procedure instead of being run.

Repository repairs persist even if later patching fails. The standard Sury key
repair reports its retained backup path. This differs from the temporary source
cleanup used by an opted-in provider migration described below.

`--wait-for-package-lock 120` can be added to a fix command without disruptive
permission. It requires an existing `fuser` on an APT system and conservatively
waits while a package lock file is open. It never removes locks or stops jobs.
An unknown probe or an expired wait stops the attempt; the package manager still
enforces its own locks afterwards.

## When a larger change is needed

A different PHP package provider can sometimes supply a fixed build for the same PHP branch and installed components. Keeping those names and versions close reduces the change; it does not establish application compatibility. Repository changes need a separate explicit choice, a maintenance window, backups and a recovery plan.

To allow the bounded migration using an already configured, authenticated Sury/ondrej source:

```sh
sudo bash dephp2shell.sh --disruptive --allow-sury-migration
```

The environment equivalent is `DP2S_ALLOW_SURY_MIGRATION=true` with `--disruptive`. The setting alone does not change normal `--fix` behaviour. The script requires a supported OS release and architecture, matching versioned package names and PHP branches, verified fixed candidates, and an acceptable transaction and restart plan. It stops if those checks fail; a package from another OS release is not a substitute.

If the appropriate source is missing, a further opt-in permits adding it:

```sh
sudo bash dephp2shell.sh --disruptive --allow-sury-migration --allow-sury-repository
```

The additional environment setting is `DP2S_ALLOW_SURY_REPOSITORY=true`. Assess the existing-provider update first: requesting migration can choose Sury even when a normal distribution update is available.

This route is limited to Debian 11, 12 and 13 using Sury, or Ubuntu 22.04 and 24.04 using the ondrej PHP PPA, on amd64. It uses the source matching the installed OS release, with dedicated signing-key verification. Existing `curl` or `wget`, plus `gpg`, are required; the script does not install those tools.

An added source is removed again if no PHP installation was attempted. Once installation is attempted, it remains configured, including after failure, so recovery and later updates can use it. Package changes have no automatic rollback. A PHP fix does not restore operating-system support, including on an older Debian release.

For an observational review, add `--check` to either command. That checks local eligibility without adding a source or refreshing package metadata; it cannot establish which candidates a missing source will supply.

The script does not perform an operating-system upgrade, change individual website PHP selections, rebuild custom PHP, or rewrite application-specific Supervisor configuration.

| Setup without a suitable automatic path | Practical next step |
| --- | --- |
| Retired OS release or architecture with no maintained package route | Plan migration to a maintained OS and test the applications there. An archive preserves old packages; it does not add new security fixes. |
| Several PHP branches, with an older branch lacking a suitable fix | Move its websites, applications and scheduled jobs to a patched branch. Test them before removing unused older packages. |
| Custom, embedded or panel-specific PHP without a verified update path | Use a procedure for that product or build. Replacing the host's PHP packages may leave that runtime unchanged. |
| Containers or other separate application environments | Check and update PHP inside each affected environment. A host update alone cannot establish their patch state. |
| No compatible fixed candidate from the current or explicitly approved alternative source | Review a PHP branch change or server migration. Do not force packages from a different OS release. |

These are limits of the current automation and evidence. They do not establish that every installation in a category lacks a fix.

RimuHosting offers a no-cost, no-obligation investigation and a report on mitigation or server migration options, including for servers hosted elsewhere. Contact RimuHosting to coordinate the server manifest and investigation. Any changes or further work are agreed separately.
