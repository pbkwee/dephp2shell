"""Option permissions, read-only recommendations and repair orchestration."""
from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))
DISRUPTIVE = runpy.run_path(str(Path(__file__).with_name('dephp2shell-disruptive.test.py')))


class RepairOptionsTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def test_negative_pin_does_not_offer_repository_or_migration_retries(self):
        for phase in ('beforefix', 'afterfix'):
            with self.subTest(phase=phase):
                out = self.shell(HELPERS['PHP2ShellTest'].apt_pin_policy(self) + '\nP2S_PHASE=' + phase + r'''
p2s_package_deb_policy_collect php8.2-common libapache2-mod-php8.2
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'no_candidate\n' > "$P2S_WORK/blocker-keys"
p2s_repository_repair_assess() { printf 'UNEXPECTED_REPOSITORY_REPAIR\n'; return 97; }
p2s_disruptive_sury_validate_equivalents() { printf 'UNEXPECTED_MIGRATION\n'; return 97; }
p2s_fix_recommend_options
printf 'STATE=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_BLOCKED"
''', isolated_sources=True)
                self.assertIn('Resolve the reported negative APT priorities', out)
                self.assertIn('STATE=Y|BLOCKED=true', out)
                self.assertNotIn('fix_recommendation:', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_fix_method_records_effective_options_before_failed_preflight(self):
        setup = r'''
p2s_command_exists() { return 1; }
unset DP2S_MIGRATE_PHP_TO_SURY DP2S_ADD_SURY_REPOSITORY DP2S_CONFIGURE_PENDING_PHP_PACKAGES
unset DP2S_REINSTALL_PHP_SAME_VERSION DP2S_REFRESH_SURY_SIGNING_KEY DP2S_ADD_OS_SECURITY_REPOSITORY
'''
        for options in [
            '--fix',
            '--fix --enable-extra-fixes --migrate-php-to-sury --add-sury-repository --configure-pending-php-packages --reinstall-php-same-version',
            '--fix --enable-extra-fixes --refresh-sury-signing-key',
            '--fix --enable-extra-fixes --add-os-security-repository',
        ]:
            with self.subTest(options=options):
                out = self.shell(setup + '\np2s_cli --output machine ' + options, status=1)
                methods = [line for line in out.splitlines() if line.startswith('dss:fixmethod:')]
                self.assertEqual(methods, ['dss:fixmethod: Attempted ' + options])
        env = 'DP2S_CONFIGURE_PENDING_PHP_PACKAGES=yes\n'
        out = self.shell(setup + env + 'p2s_cli --output machine --enable-extra-fixes', status=1)
        self.assertIn('dss:fixmethod: Attempted --fix --enable-extra-fixes --configure-pending-php-packages', out)
        out = self.shell(setup + env + 'p2s_cli --output machine --fix --configure-pending-php-packages=false', status=1)
        self.assertIn('dss:fixmethod: Attempted --fix\n', out)
        out = self.shell(setup + env + 'p2s_cli --output machine --check --enable-extra-fixes', status=1)
        self.assertNotIn('dss:fixmethod:', out)

    def cli(self, args, settings='', expected=0):
        return self.shell(r'''
unset DP2S_MIGRATE_PHP_TO_SURY DP2S_ADD_SURY_REPOSITORY DP2S_CONFIGURE_PENDING_PHP_PACKAGES
unset DP2S_REINSTALL_PHP_SAME_VERSION
unset DP2S_REFRESH_SURY_SIGNING_KEY DP2S_ADD_OS_SECURITY_REPOSITORY
p2s_main() { printf 'ENGINE:%s|pending=%s|reinstall=%s|repo=%s\n' "$*" "$P2S_ALLOW_PENDING_PHP_CONFIGURATION" "$P2S_ALLOW_EXACT_PHP_REINSTALL" "$P2S_REPOSITORY_REPAIR"; }
''' + settings + '\np2s_cli --output machine ' + args + ' 2>&1', status=expected)

    def test_new_permissions_and_environment_require_disruptive(self):
        flags = [('configure-pending-php-packages', 'pending', 'true'),
                 ('reinstall-php-same-version', 'reinstall', 'true'),
                 ('refresh-sury-signing-key', 'repo', 'sury-key'),
                 ('add-os-security-repository', 'repo', 'native-security-source')]
        for flag, field, value in flags:
            with self.subTest(flag=flag):
                self.cli('--fix --' + flag, expected=64)
                out = self.cli('--enable-extra-fixes --' + flag)
                self.assertIn('ENGINE:--fix|', out)
                self.assertIn(field + '=' + value, out)
                out = self.cli('--check --enable-extra-fixes --' + flag)
                self.assertIn('ENGINE:--check|', out)
                env = 'DP2S_' + flag.upper().replace('-', '_') + '=true'
                self.cli('--fix', env, expected=64)
                self.assertIn(field + '=' + value, self.cli('--enable-extra-fixes', env))
                self.cli('--enable-extra-fixes --' + flag + '=invalid', expected=64)
                self.cli('--enable-extra-fixes', env.replace('=true', '=invalid'), expected=64)
                out = self.cli('--check --' + flag + '=false', env)
                self.assertIn(field + ('=none' if field == 'repo' else '=false'), out)

    def test_repository_repairs_cannot_be_combined(self):
        gate = '--enable-extra-fixes '
        for args, env in [('--refresh-sury-signing-key --add-os-security-repository', ''),
                          ('--add-os-security-repository --refresh-sury-signing-key', ''),
                          ('', 'DP2S_REFRESH_SURY_SIGNING_KEY=true; DP2S_ADD_OS_SECURITY_REPOSITORY=true'),
                          ('--refresh-sury-signing-key', 'DP2S_ADD_OS_SECURITY_REPOSITORY=true'),
                          ('--add-os-security-repository', 'DP2S_REFRESH_SURY_SIGNING_KEY=true')]:
            with self.subTest(args=args, env=env):
                out = self.cli(gate + args, env, expected=64)
                self.assertIn('Choose only one', out)
                self.assertNotIn('ENGINE:', out)
        env = 'DP2S_REFRESH_SURY_SIGNING_KEY=true; DP2S_ADD_OS_SECURITY_REPOSITORY=true'
        out = self.cli(gate + '--add-os-security-repository=false', env)
        self.assertIn('repo=sury-key', out)
        out = self.cli('--check ' + gate + '--refresh-sury-signing-key=false', env)
        self.assertIn('ENGINE:--check|', out)
        self.assertIn('repo=native-security-source', out)

    def test_old_method_flags_have_no_compatibility_aliases(self):
        for flag in ('--allow-disruptive-fixes', '--disruptive', '--allow-sury-migration', '--allow-sury-repository',
                     '--allow-pending-php-configuration', '--allow-exact-php-reinstall',
                     '--allow-php-dependency-updates', '--upgrade-required-php-libraries',
                     '--upgrade-required-php-libraries=false', '--repair-repository sury-key'):
            with self.subTest(flag=flag):
                self.assertNotIn('ENGINE:', self.cli('--check ' + flag, expected=64))
        out = self.cli('--check', 'DP2S_REPOSITORY_REPAIR=sury-key; DP2S_ALLOW_PENDING_PHP_CONFIGURATION=true')
        self.assertIn('pending=false', out)
        self.assertIn('repo=none', out)

    def test_removed_dependency_environment_is_not_a_permission_setting(self):
        for value in ('true', 'false', 'invalid'):
            with self.subTest(value=value):
                out = self.cli('--fix', 'DP2S_UPGRADE_REQUIRED_PHP_LIBRARIES=' + value)
                self.assertIn('ENGINE:--fix|', out)

    def test_retired_wait_option_is_rejected_before_the_engine_runs(self):
        for args in ('--fix --wait-for-package-lock 120', '--fix --wait-for-package-lock=120'):
            with self.subTest(args=args):
                out = self.cli(args, expected=64)
                self.assertIn('Unrecognised argument', out)
                self.assertNotIn('ENGINE:', out)

    def test_package_lock_blocker_requires_investigation_without_retry_options(self):
        for phase in ('beforefix', 'afterfix'):
            out = self.shell('P2S_PHASE=' + phase + r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'package_manager_busy\n' > "$P2S_WORK/blocker-keys"
p2s_fix_recommend_options
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
''')
            self.assertIn('BLOCKED=true', out)
            self.assertNotIn('Suggested options:', out)
            self.assertNotIn('fix_recommendation:', out)

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

    def test_panel_recommendations_use_vendor_updater_and_do_not_offer_sury_repairs(self):
        for panel in ('cpanel', 'plesk'):
            for blocked in ('false', 'true'):
                with self.subTest(panel=panel, blocked=blocked):
                    out = self.shell('P2S_PANEL=' + panel + '; P2S_BLOCKED=' + blocked + r'''
P2S_BACKEND=deb; P2S_STATE=Y
p2s_repository_repair_assess() { printf 'UNEXPECTED_REPOSITORY_REPAIR\n'; return 0; }
p2s_disruptive_sury_validate_equivalents() { printf 'UNEXPECTED_MIGRATION\n'; return 0; }
p2s_fix_recommend_options
''')
                    self.assertNotIn('UNEXPECTED_', out)
                    self.assertNotIn('--migrate-php-to-sury', out)
                    self.assertNotIn('--add-sury-repository', out)
                    self.assertNotIn('--refresh-sury-signing-key', out)
                    self.assertEqual('Suggested options: --fix.' in out, blocked == 'false')

    def test_panel_cannot_add_sury_source_or_refresh_its_key_even_with_explicit_options(self):
        for panel in ('cpanel', 'plesk'):
            with self.subTest(panel=panel):
                out = self.shell('P2S_PANEL=' + panel + r'''
P2S_DISTRO=debian; P2S_RELEASE=12; P2S_BACKEND=deb; P2S_MODE=fix
P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=true
p2s_command_run() { printf 'UNEXPECTED_COMMAND\n'; return 97; }
p2s_disruptive_sury_add_repository
printf 'ADD_STATUS=%s\n' "$?"
p2s_repository_repair_assess sury-key
printf 'KEY_STATUS=%s|REASON=%s\n' "$?" "$P2S_REPOSITORY_REPAIR_REASON"
p2s_disruptive_sury_validate_equivalents
printf 'MIGRATE_STATUS=%s\n' "$?"
''')
                self.assertIn('ADD_STATUS=1', out)
                self.assertIn('KEY_STATUS=1', out)
                self.assertIn('MIGRATE_STATUS=1', out)
                self.assertIn('Sury key repair is disabled', out)
                self.assertNotIn('UNEXPECTED_COMMAND', out)

    def test_check_recommends_matching_package_repair_only(self):
        for eligible, expected in [('pending', '--configure-pending-php-packages'),
                                   ('exact', '--reinstall-php-same-version'), ('unrelated', None)]:
            with self.subTest(eligible=eligible):
                out = self.shell('eligible=' + eligible + r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'package_state\n' > "$P2S_WORK/blocker-keys"
p2s_package_deb_repair_audit_collect() {
    P2S_REPAIR_AUDIT_NEEDED=true
    P2S_PENDING_PHP_REPAIR_ELIGIBLE=false; P2S_EXACT_PHP_REPAIR_ELIGIBLE=false
    case "$eligible" in pending) P2S_PENDING_PHP_REPAIR_ELIGIBLE=true;; exact) P2S_EXACT_PHP_REPAIR_ELIGIBLE=true;; esac
    printf 'php8.2-cli|8.2.35-1|amd64\n' > "$P2S_WORK/repair-reinstall"
}
p2s_package_deb_exact_candidate_validate() { return 0; }
p2s_fix_recommend_options
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
''')
                self.assertIn('BLOCKED=true', out)
                if expected:
                    self.assertIn('--fix --enable-extra-fixes ' + expected, out)
                    self.assertIn('fix_recommendation:', out)
                else:
                    self.assertNotIn('Suggested options:', out)

    def test_incomplete_pending_configuration_is_not_recommended_again_in_same_run(self):
        for phase, attempted, offered in [('afterfix', 'true', False), ('afterfix', 'false', True), ('beforefix', 'true', True)]:
            with self.subTest(phase=phase, attempted=attempted):
                out = self.shell(f'P2S_PHASE={phase}; P2S_PACKAGE_CONFIGURATION_ATTEMPTED={attempted}\n' + r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'package_state\n' > "$P2S_WORK/blocker-keys"
p2s_package_deb_repair_audit_collect() {
    P2S_REPAIR_AUDIT_NEEDED=true; P2S_PENDING_PHP_REPAIR_ELIGIBLE=true
}
p2s_fix_recommend_options
''')
                self.assertEqual('fix_recommendation:' in out, offered)
                if not offered:
                    self.assertIn('attempted PHP package configuration is still incomplete', out)
                    self.assertIn('run --check before trying the repair again', out)

    def test_incomplete_fix_recommends_from_fresh_afterfix_preflight_only(self):
        for outcome in ('pending', 'unrelated', 'fixed', 'generic', 'legacy_yum'):
            with self.subTest(outcome=outcome):
                out = self.shell('outcome=' + outcome + r'''
P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true
P2S_ALLOW_SURY_REPOSITORY=true; P2S_ALLOW_PENDING_PHP_CONFIGURATION=true
P2S_ALLOW_EXACT_PHP_REINSTALL=true
P2S_REPOSITORY_REPAIR=sury-key
p2s_distro_detect() {
    P2S_BACKEND=deb
    if [ "$outcome" = legacy_yum ]; then P2S_BACKEND=rpm; fi
}
p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() {
    P2S_STATE=Y
    if [ "$P2S_PHASE" = afterfix ] && [ "$outcome" = fixed ]; then P2S_STATE=N; fi
    if [ "$P2S_PHASE" = afterfix ] && [ "$outcome" = unrelated ]; then p2s_fix_block custom_runtime 'Current blocker'; fi
}
p2s_fix_check_distro_recipe() {
    printf 'RECIPE:%s\n' "$P2S_PHASE"
    if [ "$outcome" = legacy_yum ]; then p2s_fix_block unsupported_os 'No automatic update recipe'; return 1; fi
    if [ "$P2S_PHASE" = beforefix ]; then p2s_fix_block stale 'Old blocker'; fi
}
p2s_fix_run() {
    [ "$outcome" != legacy_yum ] || return 1
    P2S_TRANSACTION_ATTEMPTED=true
}
p2s_fix_preflight() {
    printf 'PREFLIGHT:%s|%s|%s|%s|%s|%s|%s|%s\n' "$P2S_PHASE" "$P2S_MODE" "$P2S_DISRUPTIVE" "$P2S_ALLOW_SURY_MIGRATION" "$P2S_ALLOW_SURY_REPOSITORY" "$P2S_ALLOW_PENDING_PHP_CONFIGURATION" "$P2S_ALLOW_EXACT_PHP_REINSTALL" "$P2S_REPOSITORY_REPAIR"
    if grep -q stale "$P2S_WORK/blocker-keys"; then return 97; fi
    $P2S_BLOCKED && return 1
    return 0
}
p2s_package_deb_preflight() {
    [ "$outcome" != generic ] || return 0
    p2s_fix_block package_state 'Pending PHP configuration'; return 1
}
p2s_package_deb_repair_audit_collect() {
    P2S_REPAIR_AUDIT_NEEDED=false
    if [ "$outcome" = pending ]; then P2S_REPAIR_AUDIT_NEEDED=true; P2S_PENDING_PHP_REPAIR_ELIGIBLE=true; fi
}
p2s_repository_repair_assess() { return 1; }
p2s_package_deb_update() { return 1; }
p2s_disruptive_sury_validate_equivalents() { return 1; }
p2s_check_refresh_packages() { printf 'CHECK_REFRESH:%s|%s|%s\n' "$P2S_PHASE" "$P2S_MODE" "$P2S_BACKEND"; }
p2s_command_run() { return 0; }
# Never create or remove the production patch lock.
mkdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
rmdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
(p2s_main --fix)
''', status=0 if outcome == 'fixed' else 1)
                self.assertNotIn('fix_recommendation:beforefix|', out)
                self.assertEqual('CHECK_REFRESH:afterfix|check|rpm' in out, outcome == 'legacy_yum')
                if outcome == 'pending':
                    self.assertIn('RECIPE:afterfix', out)
                    self.assertIn('PREFLIGHT:afterfix|check|false|false|false|false|false|none', out)
                    self.assertIn('fix_recommendation:afterfix|pending_php|options=--fix --enable-extra-fixes --configure-pending-php-packages|', out)
                else:
                    self.assertNotIn('fix_recommendation:', out)
                if outcome in ('pending', 'fixed'):
                    self.assertNotIn('This script could not finish the PHP fix', out)
                else:
                    self.assertIn('This script could not finish the PHP fix', out)
                    self.assertIn('then run --check again to reassess the server', out)
                if outcome == 'fixed':
                    self.assertNotIn('RECIPE:afterfix', out)
                    self.assertNotIn('PREFLIGHT:', out)

    def test_plain_fix_recommendation_is_only_for_checks(self):
        for phase in ('beforefix', 'afterfix'):
            for backend, plan_status in (('rpm', 0), ('deb', 0), ('deb', 1)):
                with self.subTest(phase=phase, backend=backend, plan_status=plan_status):
                    out = self.shell('P2S_PHASE=' + phase + '; P2S_BACKEND=' + backend + '; plan_status=' + str(plan_status) + r'''
P2S_STATE=Y; P2S_BLOCKED=false; P2S_FIX_RECOMMENDATION_EMITTED=false
p2s_package_deb_repair_audit_collect() { P2S_REPAIR_AUDIT_NEEDED=false; }
p2s_repository_repair_assess() { return 1; }
p2s_package_deb_update() { return "$plan_status"; }
p2s_disruptive_sury_validate_equivalents() { return 1; }
p2s_fix_recommend_options
printf 'EMITTED=%s\n' "$P2S_FIX_RECOMMENDATION_EMITTED"
''')
                    if phase == 'beforefix':
                        self.assertIn('Suggested options: --fix.', out)
                        self.assertIn('fix_recommendation:beforefix|existing_provider|options=--fix|', out)
                        self.assertIn('EMITTED=true', out)
                    else:
                        self.assertNotIn('Suggested options:', out)
                        self.assertNotIn('fix_recommendation:', out)
                        self.assertIn('EMITTED=false', out)

    def test_check_does_not_recommend_migration_past_other_blockers(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true
printf 'custom_runtime\n' > "$P2S_WORK/blocker-keys"
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
                    self.assertIn('--add-os-security-repository', out)
                    self.assertNotIn('ALTERNATIVE_ASSESSED', out)
                else:
                    self.assertNotIn('--add-os-security-repository', out)
                    self.assertIn('Suggested options: --fix.', out)
                    self.assertIn('refresh and try the configured PHP package repositories', out)

    def test_required_libraries_recommend_plain_fix_without_extra_consent(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=false
p2s_package_deb_repair_audit_collect() { P2S_REPAIR_AUDIT_NEEDED=false; }
p2s_repository_repair_assess() { return 1; }
p2s_package_deb_update() {
    [ "$P2S_MODE" = check ] && ! $P2S_DISRUPTIVE || return 97
    printf 'libpcre2-8-0|10.42-2|amd64|libpcre2-8-0\n' > "$P2S_WORK/dependency-approved"
}
p2s_fix_recommend_options
''')
        self.assertIn('fix_recommendation:beforefix|existing_provider|options=--fix|', out)
        self.assertNotIn('--enable-extra-fixes', out)
        self.assertNotIn('--upgrade-required-php-libraries', out)

    def test_check_recommends_migration_only_after_successful_refresh(self):
        for freshness in ('not_refreshed', 'failed', 'refreshed'):
            with self.subTest(freshness=freshness):
                out = self.shell(DISRUPTIVE['DisruptiveTest']().fixture('P2S_MODE=check') + r'''
P2S_STATE=Y
P2S_REPOSITORY_REFRESH=''' + freshness + '''
p2s_fix_recommend_options
''', isolated_sources=True)
                self.assertEqual('Suggested options: --fix --enable-extra-fixes --migrate-php-to-sury.' in out,
                                 freshness == 'refreshed')
                self.assertNotIn('REFRESH', out)
                self.assertNotIn('INSTALL:', out)

    def test_missing_source_recommendation_is_explicitly_conditional(self):
        out = self.shell(r'''
P2S_STATE=Y; P2S_BACKEND=deb; P2S_BLOCKED=true; P2S_REPOSITORY_REFRESH=refreshed
printf 'unsupported_os\n' > "$P2S_WORK/blocker-keys"
: > "$P2S_WORK/apt-origins"
p2s_repository_repair_assess() { return 1; }
p2s_disruptive_sury_validate_equivalents() { return 0; }
p2s_package_deb_update() { p2s_fix_block no_candidate "No PHP update found."; return 1; }
p2s_fix_recommend_options
''', isolated_sources=True)
        self.assertIn('--migrate-php-to-sury --add-sury-repository', out)
        self.assertIn('candidates from the missing repository have not been checked', out)

    def test_default_check_refreshes_apt_before_assessing_current_publisher(self):
        for scenario, fresh, blocker in [('no_php', 'not_refreshed', ''),
                                         ('fixed', 'refreshed', ''),
                                         ('fixed_fix', 'refreshed', ''),
                                         ('native', 'refreshed', ''),
                                         ('plan_failure', 'refreshed', 'The PHP simulation failed.'),
                                         ('partial', 'failed', 'apt-get update left some package lists incomplete.'),
                                         ('failure', 'failed', 'apt-get update failed (exit 100).'),
                                         ('timeout', 'failed', 'apt-get update timed out after 300 seconds.')]:
            with self.subTest(scenario=scenario):
                out = self.shell('scenario=' + scenario + r'''
p2s_work_directory_init() { :; }
p2s_distro_detect() { P2S_DISTRO=debian; P2S_RELEASE=12; P2S_MAJOR=12; }
p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() {
    P2S_BACKEND=deb; P2S_STATE=Y; P2S_COUNT=1
    case "$scenario" in
        fixed|fixed_fix) P2S_STATE=N ;;
        no_php) P2S_STATE=N; P2S_COUNT=0; : > "$P2S_WORK/packages"; return ;;
    esac
    printf 'php8.2-cli|8.2.35-1~deb12u1|amd64|Debian\n' > "$P2S_WORK/packages"
    printf 'php8.2-cli|8.2.35-1~deb12u1|amd64|php8.2|8.2.35-1~deb12u1\n' > "$P2S_WORK/deb-source-records"
}
id() { printf '0\n'; }
p2s_package_lock_warn() { :; }
p2s_fix_preflight() { :; }
p2s_package_deb_preflight() { :; }
p2s_package_deb_repair_audit_collect() { P2S_REPAIR_AUDIT_NEEDED=false; }
p2s_package_deb_sury_trust_preflight() { :; }
p2s_repository_repair_assess() { return 1; }
p2s_command_run() {
    case "$2:$3" in
        df:-Pk) return 0 ;;
        apt-get:-c)
            grep -Fx '#clear APT::Update::Post-Invoke-Success;' "$4" >/dev/null || return 97
            grep -Fx '#clear Binary::apt-get::APT::Update::Pre-Invoke;' "$4" >/dev/null || return 97
            case " $* " in *' Acquire::Retries=1 '*' update '*) ;; *) return 97 ;; esac
            case "$scenario" in
                fixed|fixed_fix|native|plan_failure) : > "$P2S_WORK/refreshed" ;;
                partial) printf 'W: Some index files failed to download\n' ;;
                failure) return 100 ;;
                timeout) return 124 ;;
                *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_package_deb_update() {
    if [ -f "$P2S_WORK/refreshed" ] && $P2S_APT_CURRENT_PROVIDER_ONLY && ! $P2S_ALLOW_SURY_MIGRATION; then
        if [ "$scenario" = native ]; then
            p2s_manifest_record cached_update_plan 'approved_after_refresh|fresh_fix_preflight_and_refresh_required'
            return 0
        fi
        p2s_fix_block transaction_plan 'The PHP simulation failed.'
    else
        p2s_fix_block no_candidate 'Cached APT has no newer package.'
    fi
    return 1
}
p2s_disruptive_sury_validate_equivalents() { printf 'UNEXPECTED_MIGRATION\n'; return 97; }
mode=--check
[ "$scenario" != fixed_fix ] || mode=--fix
p2s_cli "$mode" --november-2026 --output machine
''')
                if scenario != 'fixed_fix':
                    self.assertIn('repositories=' + fresh, out)
                self.assertEqual('repository_refresh:' in out, scenario != 'no_php')
                if blocker:
                    self.assertIn(blocker, out)
                self.assertIn('dss:isvulnerable:afterfix: CVE_2026_126714' +
                              ('N' if scenario in ('fixed', 'fixed_fix', 'no_php') else 'Y'), out)
                self.assertEqual('APT refreshed the package lists and found an update plan' in out, scenario == 'native')
                self.assertEqual('Next action: Run the PHP update.' in out, scenario == 'native')
                self.assertEqual('Next action: Resolve the reported APT plan problem' in out,
                                 scenario == 'plan_failure')
                self.assertNotIn('sury_migration_identity', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_rpm_check_uses_appropriate_metadata_and_candidate_commands(self):
        cases = [('dnf', '4.4.2', 'check-update', 100, 0, ''),
                 ('dnf', 'dnf5 version 5.2.17.0', 'check-upgrade', 0, 0, ''),
                 ('yum', '3.4.3', 'check-update', 1, 0, ''),
                 ('yum', '3.4.3', 'check-update', 0, 124, ''),
                 ('yum', '3.4.3', 'check-update', 0, 0, 'There are no enabled repos.')]
        for manager, version, query, query_status, refresh_status, refresh_output in cases:
            with self.subTest(manager=manager, version=version, refresh_status=refresh_status,
                              refresh_output=refresh_output):
                out = self.shell(f'fixture_manager={manager}; fixture_version=\'{version}\'; '
                                 f'fixture_query={query}; query_status={query_status}; '
                                 f'refresh_status={refresh_status}; refresh_output=\'{refresh_output}\'\n' + r'''
P2S_BACKEND=rpm; P2S_MODE=check; P2S_STATE=Y
id() { printf '0\n'; }
printf 'php-cli|0:8.3.6-1|x86_64|Example\n' > "$P2S_WORK/packages"
p2s_command_exists() { [ "$1" = "$fixture_manager" ]; }
p2s_command_run() {
    [ "$2" = "$fixture_manager" ] || return 97
    case " $* " in
        *' --version '*) printf '%s\n' "$fixture_version" ;;
        *' --assumeno '*' makecache '*) printf '%s\n' "$refresh_output"; return "$refresh_status" ;;
        *" --cacheonly --assumeno $fixture_query php-cli.x86_64 "*) return "$query_status" ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_check_refresh_packages
printf 'state=%s\n' "$P2S_REPOSITORY_REFRESH"
''')
                self.assertIn(f'{manager} makecache|exit={refresh_status}', out)
                if refresh_status or refresh_output:
                    diagnosis = 'timed out after 300 seconds' if refresh_status else 'found no enabled repositories'
                    self.assertIn(f'{manager} makecache {diagnosis}', out)
                    self.assertIn('state=failed', out)
                    self.assertNotIn('rpm_candidate_query:', out)
                else:
                    self.assertIn(f'{manager} {query}|exit={query_status}', out)
                    self.assertIn({0: 'found no update', 100: 'found newer PHP package builds',
                                   1: 'failed (exit 1)'}[query_status], out)

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

    def test_default_dependency_upgrades_pin_both_simulation_and_install(self):
        fixture = DISRUPTIVE['DisruptiveTest']().fixture(
            'P2S_MODE=fix; P2S_DISRUPTIVE=false; P2S_ALLOW_SURY_MIGRATION=false; '
            'old=8.2.29-1+0~20261021.94+debian12~1.gbp8bff78')
        fixture = fixture.split('\np2s_package_deb_update\n', 1)[0]
        for scenario in ('valid', 'check', 'purge', 'changed_conf', 'addition', 'invalid_mode'):
            with self.subTest(scenario=scenario):
                out = self.shell(fixture + '\nscenario=' + scenario + r'''
sed -i '/^php8.2-redis|/d' "$P2S_WORK/packages"
eval "$(declare -f p2s_command_run | sed '1s/p2s_command_run/p2s_fixture_command_run/')"
p2s_command_run() {
    local last sims=0
    for last in "$@"; do :; done
    case "$2:$last" in
        dpkg-query:libxml2|dpkg-query:libxml2:amd64)
            printf 'install ok installed|libxml2:amd64|2.9.14-1|amd64|libxml2|Debian XML Team\n'; return 0 ;;
        apt-cache:libxml2:amd64)
            printf 'libxml2:\n Installed: 2.9.14-1\n Candidate: 2.9.15-1\n Version table:\n  2.9.15-1 500\n   500 https://deb.debian.org/debian bookworm/main amd64 Packages\n *** 2.9.14-1 500\n   500 https://deb.debian.org/debian bookworm/main amd64 Packages\n   100 %s/var/lib/dpkg/status\n' "$P2S_WORK"; return 0 ;;
        apt-cache:libxml2:amd64=2.9.14-1|apt-cache:libxml2:amd64=2.9.15-1)
            printf 'Package: libxml2\nVersion: %s\nArchitecture: amd64\nSource: libxml2\n' "${last##*=}"; return 0 ;;
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
