# DePHP2Shell

![DePHP2Shell. Check first. Patch carefully. PHP security checks for mixed Linux fleets.](assets/branding/readme-banner.png)

Check Linux servers for the PHP2Shell vulnerabilities, then update supported PHP installations through their existing package sources.

A single server might need APT, DNF, YUM or a hosting panel's updater. A fleet can have all of them, alongside several PHP branches and custom installations. DePHP2Shell detects those differences, reports what needs attention and attempts a conservative update where a supported procedure exists.

The tool is one Bash script. The server needs no Python, Node.js, PHP library or downloaded helper. Checking is the default action.

## Start with a check

Download the script, inspect it, then run it as root:

```sh
wget -O dephp2shell.sh https://raw.githubusercontent.com/pbkwee/dephp2shell/main/dephp2shell.sh
less dephp2shell.sh
sudo bash dephp2shell.sh --check
```

These examples use `main`, the latest development version. For repeatable deployments, replace `main` in the download URL with a reviewed release tag or commit. Alternatively, clone the repository:

```sh
git clone --branch main https://github.com/pbkwee/dephp2shell.git
cd dephp2shell
less dephp2shell.sh
sudo bash dephp2shell.sh --check
```

A check inventories installed PHP packages, discovered runtimes and relevant running processes. It does not install packages, change service configurations or restart services. Human-readable results appear on screen; detailed diagnostics are saved privately for each run.

Terminal output adapts to reported capabilities. Use `--no-color` to disable colour,
or `--no-color --no-bold` for completely unstyled text.

See [usage and logging](docs/usage.md), [resolution options](docs/resolution-options.md), [coverage](docs/coverage.md) and [download help for old servers](docs/faq.md#downloading-on-an-old-server). Maintainers can read the [implementation reference](docs/maintainer-reference.md) and [security background](docs/security-background.md).

## Attempt an update

After reviewing the check, arrange backups and a maintenance window:

```sh
sudo bash dephp2shell.sh --fix
```

The tool checks prerequisites, attempts supported package or panel updates, restarts supported services where needed, then checks again. Updates and restarts can interrupt applications. Plesk's component updater can also update databases, mail and web servers.

Normal `--fix` preserves existing package providers and PHP branches. Existing Sury/ondrej PHP can use a recognised fixed package from its configured source.

A separate, explicitly enabled `--disruptive` procedure can attempt a closely matched native-to-Sury package change. It requires compatible package names, PHP branches, architecture and transaction checks. It does not change individual website PHP selections. See [resolution options](docs/resolution-options.md) before choosing it.

A clear result covers the installations and processes inspected for CVE-2026-109618 and CVE-2026-109619. It is not a website test, a compromise assessment or a general security audit. Older operating systems can still need migration even after PHP is fixed.

## Development

Run `python3 tests/run.py` for offline fixture tests. See the
[maintainer reference](docs/maintainer-reference.md#offline-tests-and-release-checks)
for syntax checks, older-interpreter tests and evidence requirements.

See the [branding guide](docs/branding.md) for logo files, colours and usage notes,
including the [editable SVG logo](assets/branding/logo.svg).

## Licence and project name

Released under the [MIT licence](LICENSE), with no warranty. Use it at your own
risk and verify the results and application health on your servers.

DePHP2Shell is the project's name. RimuHosting is a trademark of RimuHosting;
see [NOTICE](NOTICE). The software licence does not imply endorsement of forks
or grant trademark rights.

## About RimuHosting

DePHP2Shell was developed by the team at [RimuHosting](https://rimuhosting.com/). We have been hosting Linux virtual machines since 2003. That history brings a wide variety of distributions, hosting panels, PHP versions and local customisations. Our [server patching tools](https://blog.rimuhosting.com/2022/02/06/server-patch-tool/) grew from the practical work of maintaining those different environments.

Keeping a public server secure protects its users and everyone else who could be harmed if that server is taken over. We see that care as part of running a hosting service, and as a responsibility shared by everyone operating public services.

RimuHosting offers a no-cost, no-obligation investigation and a report on mitigation or server migration options, including for servers hosted elsewhere. Contact RimuHosting to coordinate the server manifest and investigation. Any changes or further work are agreed separately.
