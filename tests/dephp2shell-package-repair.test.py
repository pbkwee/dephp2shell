"""Offline package-repair contracts; every administrative command is mocked."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')


class PackageRepairTest(unittest.TestCase):
    def shell(self, body, changes=''):
        with tempfile.TemporaryDirectory(prefix='dephp-package-repair-') as work:
            script = Path(work) / 'fixture.sh'
            source = SCRIPT.read_text()
            script.write_text(source.replace('/var/lib/dpkg/info/', work + '/var/lib/dpkg/info/'))
            setup = r'''
source "$1"
P2S_WORK=$2; P2S_PHASE=beforefix; P2S_BACKEND=deb; P2S_PANEL=''; P2S_DISTRO=debian; P2S_RELEASE=12
P2S_MODE=fix; P2S_DISRUPTIVE=true; P2S_ALLOW_PENDING_PHP_CONFIGURATION=true
P2S_ALLOW_EXACT_PHP_REINSTALL=true; P2S_PACKAGE_REPAIR_SAFETY_VERIFIED=true
P2S_BLOCKED=false; P2S_TRANSACTION_ATTEMPTED=false
version=8.2.29-1~deb12u1; package=php8.2-cli; arch=amd64; source=php8.2
vendor='Debian PHP Maintainers'; status='install ok unpacked'; finish_status='install ok installed'
provider_origin=Debian; suite=bookworm; repo=https://deb.debian.org/debian
candidate=$version; metadata_source=$source; metadata_arch=$arch; metadata_hash=true
foreign_origin=false; added_dependency=false; removal=false; conf_unrelated=false
plan_arch=amd64; purge=false; unknown_action=false
install_fail=false; configure_fail=false; refresh_fail=false; trigger_fail=false; final_audit=false
: > "$P2S_WORK/audit-status.err"
'''
            setup += changes + r'''
fixture_suite=$suite; fixture_vendor=$vendor; fixture_source=$source; fixture_version=$version; fixture_arch=$arch; fixture_package=$package
printf '%s|%s|%s|%s\n' "$package" "$version" "$arch" "$status" > "$P2S_WORK/audit-selected"
cp "$P2S_WORK/audit-selected" "$P2S_WORK/audit-status"
mkdir -p "$P2S_WORK/var/lib/dpkg/info"
printf '%s|%s|%s|%s\n' "$package" "$version" "$arch" "$vendor" > "$P2S_WORK/packages"
p2s_package_deb_sury_trust_preflight() { printf 'TRUST\n' >> "$P2S_WORK/commands"; return 0; }
p2s_command_run() {
    local last
    for last in "$@"; do :; done
    printf '%s\n' "$*" >> "$P2S_WORK/commands"
    case "$2" in
        dpkg-query)
            case "$*" in *Maintainer*) printf '%s|%s|%s|%s|%s\n' "$fixture_package" "$fixture_version" "$fixture_arch" "$fixture_source" "$fixture_vendor" ;;
                *) printf '%s|%s|%s|%s\n' "$fixture_package" "$fixture_version" "$fixture_arch" "$finish_status" ;; esac ;;
        dpkg)
            case "$3" in
                --audit) if $final_audit; then printf 'Package audit still blocked\n'; fi ;;
                *) case "$*" in
                    *--configure*) if $configure_fail; then return 1; fi ;;
                    *--triggers-only*) if $trigger_fail; then return 1; fi ;;
                    *) return 97 ;;
                esac ;;
            esac ;;
        apt-cache)
            case "$*" in
                *' policy '*|*' policy')
                    if [ "$last" = policy ]; then
                        printf ' 500 %s %s/main amd64 Packages\n     release o=%s,n=%s,c=main,b=amd64\n' "$repo" "$fixture_suite" "$provider_origin" "$fixture_suite"
                    else
                        printf '%s:\n Installed: %s\n Candidate: %s\n Version table:\n *** %s 500\n  500 %s %s/main amd64 Packages\n  100 /var/lib/dpkg/status\n' "$fixture_package" "$fixture_version" "$candidate" "$fixture_version" "$repo" "$fixture_suite"
                        if $foreign_origin; then printf '  500 https://foreign.invalid/php bookworm/main amd64 Packages\n'; fi
                    fi ;;
                *' show '*)
                    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSource: %s\nFilename: pool/main/p/php8.2/pkg.deb\n' "$fixture_package" "$fixture_version" "$metadata_arch" "$metadata_source"
                    if $metadata_hash; then printf 'SHA256: %064d\n' 1; fi ;;
                *) return 97 ;;
            esac ;;
        apt-get)
            case "$*" in
                *' update') if $refresh_fail; then printf 'W: Failed to fetch\n'; fi ;;
                *' -s '*)
                    printf 'Inst %s [%s] (%s Debian:12 [%s])\nConf %s (%s Debian:12 [%s])\n' "$fixture_package" "$fixture_version" "$fixture_version" "$plan_arch" "$fixture_package" "$fixture_version" "$plan_arch"
                    if $added_dependency; then printf 'Inst unrelated (1.0 Debian:12 [amd64])\n'; fi
                    if $removal; then printf 'Remv unrelated [1.0]\n'; fi
                    if $conf_unrelated; then printf 'Conf unrelated (1.0 Debian:12 [amd64])\n'; fi
                    if $purge; then printf 'Purg unrelated [1.0]\n'; fi
                    if $unknown_action; then printf 'UnknownAction php8.2-cli\n'; fi ;;
                *' -y '*) if $install_fail; then return 1; fi ;;
                *) return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED administrative command %s\n' "$*" >&2; return 97 ;;
    esac
}
'''
            run = subprocess.run([BASH, '-c', setup + body, 'fixture', str(script), work],
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertNotIn('UNEXPECTED administrative command', run.stderr)
            return run.stdout

    def test_pending_configuration_finishes_without_blanket_configuration(self):
        self.shell(r'''
p2s_disruptive_package_configure_pending_php || exit 1
$P2S_TRANSACTION_ATTEMPTED && $P2S_PACKAGE_CONFIGURATION_ATTEMPTED || exit 2
grep -F -- '--no-triggers --configure php8.2-cli:amd64' "$P2S_WORK/commands" || exit 3
if grep -E -- '--configure -a|--pending|apt-get' "$P2S_WORK/commands"; then exit 4; fi
''')

    def test_assessment_is_read_only_and_specific(self):
        self.shell(r'''
p2s_package_deb_repair_assess
$P2S_PENDING_PHP_REPAIR_ELIGIBLE && ! $P2S_EXACT_PHP_REPAIR_ELIGIBLE || exit 1
if grep -E -- 'apt-get| --configure | --triggers-only ' "$P2S_WORK/commands"; then exit 2; fi
''')

    def test_unrelated_pending_or_unknown_sources_are_not_eligible(self):
        for change in ["package=unrelated", "source=customphp", "vendor=PrivateBuild", "status='install ok half-installed'", "P2S_PANEL=plesk"]:
            with self.subTest(change=change):
                self.shell(r'''
p2s_package_deb_repair_assess
! $P2S_PENDING_PHP_REPAIR_ELIGIBLE && ! $P2S_EXACT_PHP_REPAIR_ELIGIBLE || exit 1
''', change + '\n')

    def test_mutation_requires_every_permission(self):
        for method in ['configure_pending_php', 'reinstall_exact_php']:
            for change in ['P2S_MODE=check', 'P2S_DISRUPTIVE=false', 'P2S_PACKAGE_REPAIR_SAFETY_VERIFIED=false',
                           'P2S_ALLOW_PENDING_PHP_CONFIGURATION=false; P2S_ALLOW_EXACT_PHP_REINSTALL=false']:
                with self.subTest(method=method, change=change):
                    self.shell(f'''
if p2s_disruptive_package_{method}; then exit 1; fi
! $P2S_TRANSACTION_ATTEMPTED || exit 2
[ ! -s "$P2S_WORK/commands" ] || exit 3
''', change + '\n')

    def test_explicit_php_triggers_complete(self):
        self.shell(r'''
p2s_disruptive_package_configure_pending_php || exit 1
grep -F -- '--no-triggers --triggers-only php8.2-cli:amd64' "$P2S_WORK/commands" || exit 2
''', "finish_status='install ok triggers-pending'\n")

    def test_unrelated_trigger_not_processed(self):
        self.shell(r'''
p2s_command_run_original=$(declare -f p2s_command_run)
eval "${p2s_command_run_original/p2s_command_run/p2s_command_run_fixture}"
p2s_command_run() {
    if [ "$2" = dpkg-query ] && case "$*" in *Maintainer*) false;; *) true;; esac; then
        printf 'unrelated|1.0|amd64|install ok triggers-pending\n'; return 0
    fi
    p2s_command_run_fixture "$@"
}
if p2s_disruptive_package_configure_pending_php; then exit 1; fi
if grep -- '--triggers-only' "$P2S_WORK/commands"; then exit 2; fi
''')

    def test_configuration_failure_is_recorded_after_attempt(self):
        self.shell(r'''
if p2s_disruptive_package_configure_pending_php; then exit 1; fi
$P2S_TRANSACTION_ATTEMPTED && $P2S_BLOCKED || exit 2
''', 'configure_fail=true\n')

    def test_exact_reinstall_completes_preserving_version_and_config(self):
        self.shell(r'''
p2s_disruptive_package_reinstall_exact_php || exit 1
$P2S_PACKAGE_REINSTALL_ATTEMPTED || exit 2
grep -F -- "--reinstall" "$P2S_WORK/commands" || exit 3
grep -F -- "php8.2-cli:amd64=$version" "$P2S_WORK/commands" || exit 4
grep -F -- '--force-confold' "$P2S_WORK/commands" || exit 5
''', "status='install ok installed'\n")

    def test_exact_sury_reinstall_preserves_existing_provider(self):
        self.shell(r'''
p2s_disruptive_package_reinstall_exact_php || exit 1
$P2S_PACKAGE_REINSTALL_ATTEMPTED || exit 2
''', "status='install ok installed'\nversion=8.2.29-1+0~20261021.94+debian12~1.gbp8bff78; candidate=$version\n"
             "provider_origin=deb.sury.org; repo=https://packages.sury.org/php\n")

    def test_assessment_rejects_mixed_or_incomplete_audit_scope(self):
        for extra in [
            r'''printf 'unrelated|1|amd64|install ok unpacked\n' >> "$P2S_WORK/audit-status"''',
            r'''printf 'unparseable pending row\n' >> "$P2S_WORK/audit-status"''',
            r'''printf 'query warning\n' > "$P2S_WORK/audit-status.err"''',
            r'''printf 'php8.2-cli|%s|amd64|install ok installed\n' "$version" >> "$P2S_WORK/audit-selected"''',
        ]:
            with self.subTest(extra=extra):
                self.shell(extra + r'''
p2s_package_deb_repair_assess
! $P2S_PENDING_PHP_REPAIR_ELIGIBLE && ! $P2S_EXACT_PHP_REPAIR_ELIGIBLE || exit 1
''')

    def test_candidate_must_be_exact_authenticated_equivalent(self):
        for change in ['candidate=8.2.35-1', 'foreign_origin=true', 'provider_origin=Foreign', 'suite=bullseye',
                       'repo=https://foreign.invalid/debian', 'metadata_source=php8.3', 'metadata_arch=arm64', 'metadata_hash=false', 'P2S_RELEASE=10']:
            with self.subTest(change=change):
                self.shell(r'''
if p2s_disruptive_package_reinstall_exact_php; then exit 1; fi
! $P2S_TRANSACTION_ATTEMPTED || exit 2
''', "status='install ok installed'\n" + change + '\n')

    def test_omitted_source_is_not_invented_for_versioned_php_binary(self):
        self.shell(r'''
p2s_package_deb_repair_assess
! $P2S_PENDING_PHP_REPAIR_ELIGIBLE || exit 1
[ "$P2S_PACKAGE_REPAIR_REASON" = source_identity_mismatch ] || exit 2
''', "source=''\n")

    def test_reinstall_rejects_expanded_transaction(self):
        for change in ['added_dependency=true', 'removal=true', 'conf_unrelated=true',
                       'plan_arch=arm64', 'purge=true', 'unknown_action=true']:
            with self.subTest(change=change):
                self.shell(r'''
if p2s_disruptive_package_reinstall_exact_php; then exit 1; fi
! $P2S_TRANSACTION_ATTEMPTED || exit 2
''', "status='install ok installed'\n" + change + '\n')

    def test_reinstall_refresh_and_install_failures(self):
        for failure in ['refresh_fail', 'install_fail']:
            with self.subTest(failure=failure):
                self.shell(f'''
if p2s_disruptive_package_reinstall_exact_php; then exit 1; fi
$P2S_BLOCKED || exit 2
''', f"status='install ok installed'\n{failure}=true\n")

    def test_audit_must_clear_before_reporting_recovery(self):
        self.shell(r'''
if p2s_disruptive_package_configure_pending_php; then exit 1; fi
$P2S_TRANSACTION_ATTEMPTED && $P2S_BLOCKED || exit 2
''', 'final_audit=true\n')


if __name__ == '__main__':
    unittest.main()
