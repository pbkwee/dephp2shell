"""Option permissions, read-only recommendations and repair orchestration."""
from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))
DISRUPTIVE = runpy.run_path(str(Path(__file__).with_name('dephp2shell-disruptive.test.py')))


class RepairOptionsTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def cli(self, args, settings='', expected=0):
        return self.shell(r'''
unset DP2S_ALLOW_SURY_MIGRATION DP2S_ALLOW_SURY_REPOSITORY DP2S_ALLOW_PENDING_PHP_CONFIGURATION
unset DP2S_ALLOW_EXACT_PHP_REINSTALL DP2S_ALLOW_PHP_DEPENDENCY_UPDATES DP2S_REPOSITORY_REPAIR DP2S_PACKAGE_LOCK_WAIT_SECONDS
p2s_main() { printf 'ENGINE:%s|pending=%s|reinstall=%s|deps=%s|repo=%s|wait=%s\n' "$*" "$P2S_ALLOW_PENDING_PHP_CONFIGURATION" "$P2S_ALLOW_EXACT_PHP_REINSTALL" "$P2S_ALLOW_PHP_DEPENDENCY_UPDATES" "$P2S_REPOSITORY_REPAIR" "$P2S_PACKAGE_LOCK_WAIT_SECONDS"; }
''' + settings + '\np2s_cli --output machine ' + args, status=expected)

    def test_new_permissions_and_environment_require_disruptive(self):
        flags = [('pending-php-configuration', 'pending'), ('exact-php-reinstall', 'reinstall'),
                 ('php-dependency-updates', 'deps')]
        for flag, field in flags:
            with self.subTest(flag=flag):
                self.cli('--fix --allow-' + flag, expected=64)
                out = self.cli('--disruptive --allow-' + flag)
                self.assertIn('ENGINE:--fix|', out)
                self.assertIn(field + '=true', out)
                out = self.cli('--check --disruptive --allow-' + flag)
                self.assertIn('ENGINE:--check|', out)
                env = 'DP2S_ALLOW_' + flag.upper().replace('-', '_') + '=true'
                self.cli('--fix', env, expected=64)
                self.assertIn(field + '=true', self.cli('--disruptive', env))
                self.cli('--disruptive --allow-' + flag + '=invalid', expected=64)
        self.assertIn('repo=sury-key', self.cli('--disruptive --repair-repository sury-key'))
        self.assertIn('repo=native-security-source', self.cli('--disruptive --repair-repository=native-security-source'))
        self.cli('--fix --repair-repository sury-key', expected=64)
        self.cli('--disruptive --repair-repository unknown', expected=64)
        self.cli('--disruptive', 'DP2S_REPOSITORY_REPAIR=unknown', expected=64)

    def test_wait_range_and_check_mode(self):
        self.assertIn('wait=120', self.cli('--check --wait-for-package-lock 120'))
        self.assertIn('wait=60', self.cli('--fix --wait-for-package-lock=060'))
        self.assertIn('wait=0', self.cli('--check'))
        for value in ('-1', '601', '10000000000000000', 'no', ''):
            with self.subTest(value=value):
                self.cli('--fix --wait-for-package-lock=' + value, expected=64)

    def test_cached_candidate_plan_never_refreshes_or_installs(self):
        fixture = DISRUPTIVE['DisruptiveTest']().fixture(
            'P2S_MODE=check; P2S_ALLOW_SURY_REPOSITORY=true\n'
            "p2s_disruptive_sury_add_repository() { printf 'UNEXPECTED_SOURCE_WRITE\\n'; return 97; }")
        out = self.shell(fixture, isolated_sources=True)
        self.assertIn('cached_update_plan:beforefix|approved_with_cached_metadata_only', out)
        self.assertIn('RC=0|ATTEMPTED=false', out)
        self.assertNotIn('REFRESH', out)
        self.assertNotIn('INSTALL:', out)
        self.assertNotIn('UNEXPECTED_SOURCE_WRITE', out)

    def test_wait_releases_or_times_out_without_removing_lock(self):
        for scenario in ('release', 'busy', 'unknown', 'slow'):
            with self.subTest(scenario=scenario):
                out = self.shell('scenario=' + scenario + r'''
P2S_PACKAGE_LOCK_WAIT_SECONDS=2; probes=0; SECONDS=0
touch "$P2S_WORK/lock-must-remain"
p2s_package_lock_probe() {
    probes=$((probes + 1))
    [ "$scenario" != slow ] || SECONDS=$((SECONDS + 2))
    [ "$scenario" != unknown ] || return 2
    [ "$scenario" = release ] && [ "$probes" -gt 1 ] && return 0
    return 1
}
p2s_command_run() { [ "$2" = sleep ] && [ "$3" = 1 ] || return 1; SECONDS=$((SECONDS + 1)); }
p2s_package_lock_wait
printf 'RC=%s|PROBES=%s\n' "$?" "$probes"
[ -f "$P2S_WORK/lock-must-remain" ] && printf 'LOCK_RETAINED\n'
''')
                self.assertIn('LOCK_RETAINED', out)
                self.assertIn({'release': 'RC=0|PROBES=2', 'busy': 'RC=1|PROBES=3',
                               'unknown': 'RC=1|PROBES=1', 'slow': 'RC=1|PROBES=1'}[scenario], out)

    def test_check_recommends_matching_package_repair_only(self):
        for eligible, expected in [('pending', '--allow-pending-php-configuration'),
                                   ('exact', '--allow-exact-php-reinstall'), ('unrelated', None)]:
            with self.subTest(eligible=eligible):
                out = self.shell('eligible=' + eligible + r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'package_state\n' > "$P2S_WORK/blocker-keys"
p2s_package_lock_probe() { return 0; }
p2s_package_deb_repair_audit_collect() {
    P2S_REPAIR_AUDIT_NEEDED=true
    P2S_PENDING_PHP_REPAIR_ELIGIBLE=false; P2S_EXACT_PHP_REPAIR_ELIGIBLE=false
    case "$eligible" in pending) P2S_PENDING_PHP_REPAIR_ELIGIBLE=true;; exact) P2S_EXACT_PHP_REPAIR_ELIGIBLE=true;; esac
    printf 'php8.2-cli|8.2.35-1|amd64\n' > "$P2S_WORK/repair-reinstall"
}
p2s_package_deb_repair_exact_candidate_validate() { return 0; }
p2s_fix_recommend_options
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
''')
                self.assertIn('BLOCKED=true', out)
                if expected:
                    self.assertIn('--fix --disruptive ' + expected, out)
                    self.assertIn('fix_recommendation:', out)
                else:
                    self.assertNotIn('Suggested options:', out)

    def test_check_does_not_recommend_migration_past_other_blockers(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'custom_runtime\n' > "$P2S_WORK/blocker-keys"
p2s_package_lock_probe() { return 0; }
p2s_disruptive_sury_validate_equivalents() { printf 'UNEXPECTED_ALTERNATIVE\n'; return 0; }
p2s_fix_recommend_options
''')
        self.assertNotIn('Suggested options:', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_recommendation_prefers_existing_native_source_and_refresh(self):
        for provider in ('Debian PHP Maintainers', 'Sury PHP Maintainers'):
            with self.subTest(provider=provider):
                out = self.shell("vendor='" + provider + "'" + r'''
P2S_STATE=Y; P2S_BACKEND=deb
printf 'php8.2-cli|8.2.29-1|amd64|%s\n' "$vendor" > "$P2S_WORK/packages"
p2s_package_lock_probe() { return 0; }
p2s_package_deb_repair_audit_collect() { P2S_REPAIR_AUDIT_NEEDED=false; }
p2s_repository_repair_assess() {
    [ "$1" = native-security-source ] || return 1
    P2S_REPOSITORY_REPAIR_STATE=needed
}
p2s_package_deb_update() { return 1; }
p2s_disruptive_sury_validate_equivalents() { printf 'ALTERNATIVE_ASSESSED\n'; return 1; }
p2s_fix_recommend_options
cat "$P2S_WORK/recommend-migration.log" 2>/dev/null || :
''')
                if provider.startswith('Debian'):
                    self.assertIn('--repair-repository native-security-source', out)
                    self.assertNotIn('ALTERNATIVE_ASSESSED', out)
                else:
                    self.assertNotIn('--repair-repository native-security-source', out)
                    self.assertIn('Suggested options: --fix.', out)
                    self.assertIn('refresh and try existing sources', out)

    def test_check_recommends_migration_only_after_cached_equivalence_checks(self):
        out = self.shell(DISRUPTIVE['DisruptiveTest']().fixture('P2S_MODE=check') + r'''
P2S_STATE=Y
p2s_package_lock_probe() { return 0; }
p2s_fix_recommend_options
''', isolated_sources=True)
        self.assertIn('Suggested options: --fix --disruptive --allow-sury-migration.', out)
        self.assertNotIn('REFRESH', out)
        self.assertNotIn('INSTALL:', out)

    def test_missing_source_recommendation_is_explicitly_conditional(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'unsupported_os\n' > "$P2S_WORK/blocker-keys"
: > "$P2S_WORK/apt-origins"
p2s_package_lock_probe() { return 0; }
p2s_repository_repair_assess() { return 1; }
p2s_disruptive_sury_validate_equivalents() { return 0; }
p2s_package_deb_update() { return 1; }
p2s_fix_recommend_options
''', isolated_sources=True)
        self.assertIn('--allow-sury-migration --allow-sury-repository', out)
        self.assertIn('candidates from the missing source have not been checked', out)

    def test_failed_audit_cannot_authorize_package_repair(self):
        out = self.shell(r'''
P2S_BACKEND=deb; P2S_PANEL=''
p2s_command_run() { printf 'partial audit\n'; printf 'database read failed\n' >&2; return 1; }
p2s_package_deb_audit_context_collect() {
    printf 'php8.2-cli|8.2.29-1|amd64|install ok unpacked\n' > "$P2S_WORK/audit-status"
    cp "$P2S_WORK/audit-status" "$P2S_WORK/audit-selected"
}
p2s_package_deb_repair_audit_collect
printf 'ELIGIBLE=%s|REASON=%s\n' "$P2S_PENDING_PHP_REPAIR_ELIGIBLE" "$P2S_PACKAGE_REPAIR_REASON"
''')
        self.assertIn('ELIGIBLE=false|REASON=audit_query_failed', out)

    def test_key_recommendation_requires_expiry_or_key_mismatch(self):
        for expiry, wanted in [('0', 1), ('1', 0)]:
            with self.subTest(expiry=expiry):
                out = self.shell('expiry=' + expiry + r'''
p2s_command_exists() { [ "$1" = gpg ]; }
p2s_command_run() { printf 'pub:u:4096:1:KEY:1:%s:::\nfpr:::::::::15058500A0235D97F5D10063B188E2B695BD4743:\n' "$expiry"; }
p2s_repository_sury_key_needs_refresh
printf 'RC=%s\n' "$?"
''')
                self.assertIn('RC=' + str(wanted), out)

    def test_dependency_permission_pins_both_simulation_and_install(self):
        fixture = DISRUPTIVE['DisruptiveTest']().fixture(
            'P2S_MODE=fix; P2S_ALLOW_PHP_DEPENDENCY_UPDATES=true')
        fixture = fixture.split('\np2s_package_deb_update\n', 1)[0]
        for scenario in ('valid', 'check', 'purge', 'changed_conf', 'addition', 'invalid_mode'):
            with self.subTest(scenario=scenario):
                out = self.shell(fixture + '\nscenario=' + scenario + r'''
eval "$(declare -f p2s_command_run | sed '1s/p2s_command_run/p2s_fixture_command_run/')"
p2s_command_run() {
    local last sims=0
    for last in "$@"; do :; done
    case "$2:$last" in
        dpkg-query:libxml2|dpkg-query:libxml2:amd64)
            printf 'install ok installed|libxml2:amd64|2.9.14-1|amd64|libxml2|Debian XML Team\n'; return 0 ;;
        apt-cache:libxml2:amd64)
            printf 'libxml2:\n Installed: 2.9.14-1\n Candidate: 2.9.15-1\n Version table:\n  2.9.15-1 500\n   500 https://deb.debian.org/debian bookworm/main amd64 Packages\n'; return 0 ;;
        apt-cache:libxml2:amd64=2.9.15-1)
            printf 'Package: libxml2\nVersion: 2.9.15-1\nArchitecture: amd64\nSource: libxml2\n'; return 0 ;;
    esac
    p2s_fixture_command_run "$@" || return $?
    case " $* " in
        *' apt-cache '*' policy '*)
            if [ "$last" = policy ]; then
                printf '500 https://deb.debian.org/debian bookworm/main amd64 Packages\n release o=Debian,n=bookworm,c=main,b=amd64\n'
            fi ;;
        *' apt-cache '*' show '*) printf 'Pre-Depends: libc6 (>= 2.31)\nDepends: libxml2 (>= 2.9.15)\n' ;;
        *' apt-get -s '*)
            if [ -f "$P2S_WORK/simulation-count" ]; then read -r sims < "$P2S_WORK/simulation-count"; fi
            sims=$((sims + 1)); printf '%s\n' "$sims" > "$P2S_WORK/simulation-count"
            if [ "$sims" -eq 2 ] && [ "$scenario" = addition ]; then
                printf 'Inst libxml2 (2.9.15-1 Debian:12 [amd64])\n'
            else printf 'Inst libxml2 [2.9.14-1] (2.9.15-1 Debian:12 [amd64])\n'; fi
            if [ "$sims" -eq 2 ]; then
                case "$scenario" in
                    purge) printf 'Purg libxml2\n' ;;
                    changed_conf) printf 'Conf php8.2-cli (99.0 Debian:12 [amd64])\n' ;;
                esac
            fi ;;
    esac
}
[ "$scenario" != invalid_mode ] || P2S_MODE=invalid
[ "$scenario" != check ] || P2S_MODE=check
p2s_package_deb_update
printf 'RC=%s|ATTEMPTED=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
cat "$P2S_WORK/calls"
''', isolated_sources=True)
                if scenario == 'valid':
                    self.assertIn('RC=0|ATTEMPTED=true', out)
                    install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
                    simulations = [line for line in out.splitlines() if line.startswith('SIMULATE:')]
                    self.assertEqual(len(simulations), 2)
                    self.assertIn('libxml2:amd64=2.9.15-1', install)
                    self.assertEqual(simulations[-1].split('install --only-upgrade ', 1)[1],
                                     install.split('install --only-upgrade ', 1)[1])
                elif scenario == 'check':
                    self.assertIn('RC=0|ATTEMPTED=false', out)
                    self.assertNotIn('REFRESH', out)
                    self.assertNotIn('INSTALL:', out)
                else:
                    self.assertIn('RC=1|ATTEMPTED=false', out)
                    self.assertNotIn('INSTALL:', out)

    def test_repair_preflight_preserves_unknown_and_unrelated_blockers(self):
        for key in ('custom_runtime', 'service_mapping', ''):
            with self.subTest(key=key):
                out = self.shell("key='" + key + "'" + r'''
P2S_BLOCKED=true; P2S_BACKEND=deb; P2S_ALLOW_PENDING_PHP_CONFIGURATION=true
[ -z "$key" ] || printf '%s\n' "$key" > "$P2S_WORK/blocker-keys"
p2s_fix_preflight() { printf 'UNEXPECTED_PREFLIGHT\n'; return 0; }
p2s_fix_selected_repair_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
''')
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_partial_package_repair_uses_existing_restart_path(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_MODE=fix; P2S_DISRUPTIVE=true
P2S_ALLOW_PENDING_PHP_CONFIGURATION=true
: > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
p2s_fix_selected_repair_preflight() { return 0; }
p2s_fix_prepare_selected_methods() { P2S_TRANSACTION_ATTEMPTED=true; P2S_PACKAGE_CONFIGURATION_ATTEMPTED=true; return 1; }
p2s_service_restart_and_verify() { P2S_RESTART_ATTEMPTED=true; printf 'RESTART_VERIFIED\n'; return 0; }
p2s_package_deb_update() { printf 'UNEXPECTED_UPDATE\n'; return 97; }
p2s_fix_run
printf 'RC=%s|INSTALL=%s|RESTART=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED" "$P2S_RESTART_ATTEMPTED"
''')
        self.assertIn('RESTART_VERIFIED', out)
        self.assertIn('RC=1|INSTALL=true|RESTART=true', out)
        self.assertIn('pending_php_configuration_attempted=true', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_fix_orchestration_refuses_explicit_check_mode(self):
        out = self.shell(r'''
P2S_MODE=check
p2s_package_lock_wait() { printf 'UNEXPECTED_WAIT\n'; return 97; }
p2s_fix_run
printf 'RC=%s\n' "$?"
''')
        self.assertIn('RC=1', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_failed_status_query_clears_stale_repair_targets(self):
        out = self.shell(r'''
: > "$P2S_WORK/audit"
printf 'php8.2-cli|8.2.29-1|amd64|install ok unpacked\n' > "$P2S_WORK/audit-selected"
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() { printf 'php8.2-cli|8.2.29-1|amd64|install ok unpacked\n'; return 124; }
p2s_package_deb_audit_context_collect
[ ! -s "$P2S_WORK/audit-selected" ] && printf 'STALE_TARGETS_CLEARED\n'
''')
        self.assertIn('status_query_exit=124', out)
        self.assertIn('STALE_TARGETS_CLEARED', out)


if __name__ == '__main__':
    unittest.main()
