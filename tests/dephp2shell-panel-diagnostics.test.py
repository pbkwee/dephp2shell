"""Offline panel diagnostics; updater and PHP probes use synthetic output only."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')


class PanelDiagnosticsTest(unittest.TestCase):
    def shell(self, body):
        with tempfile.TemporaryDirectory(prefix='dephp2shell-panel-test-') as work:
            source = re.sub(r'(?<![A-Za-z0-9_*/.-])/(?:usr|opt|proc|etc|www|var)/',
                            lambda match: work + match[0], SCRIPT.read_text())
            script = Path(work) / 'fixture.sh'
            script.write_text(source)
            setup = '''
source "$1"
P2S_WORK="$2"; P2S_PHASE=beforefix; P2S_BLOCKED=false; P2S_UNKNOWN=false
P2S_COUNT=0; P2S_BACKEND=rpm; P2S_PANEL=cpanel; P2S_PANEL_TOOL=/fixture/upcp
P2S_PANEL_UPDATE_COMPLETED=false
p2s_command_run() { printf 'UNEXPECTED administrative command: %s\\n' "$*" >&2; return 97; }
'''
            run = subprocess.run([BASH, '-c', setup + body, 'fixture', str(script), work],
                                 text=True, capture_output=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(run.stderr, '')
            return run.stdout

    def test_cpanel_directory_without_core_files_retains_block_and_explains_evidence(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel" "$P2S_WORK/etc/cl.selector"
p2s_panel_inventory_collect
printf 'BLOCKED=%s|TOOL=%s\n' "$P2S_BLOCKED" "$P2S_PANEL_TOOL"
''')
        self.assertRegex(out, r'panel_path:beforefix\|.*/cpanel\|type=directory')
        for name in ('version', 'cpsrvd', '3rdparty/bin/perl', 'scripts/upcp',
                     'scripts/update-packages', 'scripts/rpmup'):
            self.assertIn('/cpanel/' + name + '|type=missing_or_inaccessible', out)
        self.assertIn('/etc/cl.selector|type=directory', out)
        self.assertIn('incomplete installation or leftover files', out)
        self.assertIn('BLOCKED=true|TOOL=', out)
        self.assertNotIn('panel_update_recipe:', out)

    def test_cpanel_broken_updater_link_has_target_and_cannot_enable_updates(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts"
printf '11.110.0.0\n' > "$P2S_WORK/usr/local/cpanel/version"
ln -s ./missing-updater "$P2S_WORK/usr/local/cpanel/scripts/upcp"
p2s_panel_inventory_collect
printf 'BLOCKED=%s|TOOL=%s\n' "$P2S_BLOCKED" "$P2S_PANEL_TOOL"
''')
        self.assertIn('/scripts/upcp|type=dangling_or_inaccessible_symlink', out)
        self.assertIn('link_target=./missing-updater', out)
        self.assertIn('BLOCKED=true|TOOL=', out)
        self.assertNotIn('panel_update_recipe:', out)

    def test_supported_cpanel_recipe_is_unchanged_and_updater_is_not_executed(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts"
printf '11.110.0.0\n' > "$P2S_WORK/usr/local/cpanel/version"
printf '#!/bin/sh\necho UNEXPECTED_UPDATER_EXECUTION\n' > "$P2S_WORK/usr/local/cpanel/scripts/upcp"
chmod 700 "$P2S_WORK/usr/local/cpanel/scripts/upcp"
p2s_panel_inventory_collect
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
''')
        self.assertRegex(out, r'/scripts/upcp\|type=regular_file\|readable=true\|executable=true')
        self.assertIn('panel_update_recipe:beforefix|cpanel|upcp --security|', out)
        self.assertIn('BLOCKED=false', out)
        self.assertNotIn('UNEXPECTED_UPDATER_EXECUTION', out)
        self.assertNotIn('incomplete installation or leftover files', out)

    def test_package_install_status_preserves_installed_and_incomplete_evidence(self):
        out = self.shell(r'''
P2S_DISTRO=debian
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() {
    [ "$2" = dpkg-query ] && [ "$3" = -W ] || return 97
    printf '%s\n' 'ea-php81-php-cli|8.1.32-1|amd64|install ok installed|cPanel' \
        'ea-php82-php-cli|8.2.28-1|amd64|install ok half-configured|cPanel' \
        'ea-php83-php-cli|8.3.31-1|amd64|deinstall ok config-files|cPanel'
}
p2s_package_inventory_collect
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
''')
        self.assertIn('package_install_status:beforefix|deb|ea-php81-php-cli|amd64|install ok installed', out)
        self.assertIn('package_install_status:beforefix|deb|ea-php82-php-cli|amd64|install ok half-configured', out)
        self.assertIn('package_install_status:beforefix|deb|ea-php83-php-cli|amd64|deinstall ok config-files', out)
        self.assertNotIn('package:beforefix|deb|ea-php83-php-cli|', out)
        self.assertIn('BLOCKED=true|UNKNOWN=true', out)

    def test_zero_exit_cpanel_nested_failures_are_not_success(self):
        failures = [
            'E The install encountered a fatal error: An attempt to upgrade was blocked.',
            '[/fixture/update-packages] The update-packages command reported error number 1 when it ended.',
            '(XID fixture) yum reported error code “1” when it ended:',
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                out = self.shell('fixture_output=' + repr(failure) + r'''
p2s_command_run() { printf '%s\n' "$fixture_output"; return 0; }
p2s_panel_update
printf 'STATUS=%s|COMPLETED=%s|BLOCKED=%s\n' "$?" "$P2S_PANEL_UPDATE_COMPLETED" "$P2S_BLOCKED"
''')
                self.assertIn('panel_update_exit:beforefix|cpanel|0', out)
                self.assertIn('nested_update_failed', out)
                self.assertIn('STATUS=1|COMPLETED=false|BLOCKED=true', out)
                self.assertNotIn('vendor update command completed', out)

    def test_successful_certificate_housekeeping_is_not_a_tls_failure(self):
        out = self.shell(r'''
p2s_command_run() {
    printf '%s\n' 'Processing: Scheduling task to check service default SSL/TLS certificates' \
        'Processing: Purging invalid or soon-to-expire Domain TLS entries for service domains' \
        'Found and expunged 0 expired certificates.' 'No problems found' \
        'Child command reported error number 0 when it ended.'
}
p2s_panel_update
printf 'STATUS=%s|COMPLETED=%s\n' "$?" "$P2S_PANEL_UPDATE_COMPLETED"
''')
        self.assertIn('STATUS=0|COMPLETED=true', out)
        self.assertNotIn('repository_failure:', out)
        self.assertNotIn('nested_update_failed', out)

    def test_cpanel_missing_license_explains_why_update_could_not_finish(self):
        for status in (0, 1):
            with self.subTest(status=status):
                out = self.shell('fixture_status=' + str(status) + r'''
p2s_command_run() {
    printf '%s\n' 'E Blocker found: No license file found. Your cPanel software will not function properly.' \
        'E The install encountered a fatal error: An attempt to upgrade was blocked.'
    return "$fixture_status"
}
p2s_panel_update
printf 'STATUS=%s|COMPLETED=%s|BLOCKED=%s\n' "$?" "$P2S_PANEL_UPDATE_COMPLETED" "$P2S_BLOCKED"
''')
                self.assertIn('panel_update_exit:beforefix|cpanel|' + str(status), out)
                self.assertIn('cpanel|panel_license|', out)
                self.assertIn('blocker:beforefix|panel_license|', out)
                self.assertIn('A valid cPanel license is required for this update path', out)
                self.assertIn('Some changes may already have been made', out)
                self.assertIn('STATUS=1|COMPLETED=false|BLOCKED=true', out)
                self.assertNotIn('vendor update command completed', out)

    def test_current_update_reports_license_and_conflicts_together_even_on_zero_exit(self):
        for license_error in ('Blocker found: No license file found.',
                              'The license is invalid.', 'The license has expired.'):
            with self.subTest(license_error=license_error):
                out = self.shell('license_error=' + repr(license_error) + r'''
p2s_command_run() {
    printf '%s\n' "$license_error" \
        'package ea-apache24-2.4.69-1.cpanel from EA4 conflicts with httpd-mmn provided by httpd-core-2.4.63 from appstream' \
        'package other-web-2 conflicts with other-web-1 https://user:password@private.invalid/path' \
        'Completed all updates'
    return 0
}
p2s_panel_update
printf 'STATUS=%s|COMPLETED=%s|BLOCKED=%s\n' "$?" "$P2S_PANEL_UPDATE_COMPLETED" "$P2S_BLOCKED"
''')
                self.assertIn('panel_license|', out)
                self.assertIn('panel_package_conflict|', out)
                self.assertIn('ea-apache24-2.4.69-1.cpanel', out)
                self.assertIn("operating system's Apache package (httpd-core)", out)
                self.assertIn('other-web-2 conflicts with other-web-1', out)
                self.assertIn('STATUS=1|COMPLETED=false|BLOCKED=true', out)
                self.assertNotIn('password', out)
                self.assertNotIn('returned success. Checking', out)

    def test_read_only_panel_inventory_reports_previous_blocker_without_asserting_current_license(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts" "$P2S_WORK/var/cpanel/updatelogs"
printf '11.136.0.29\n' > "$P2S_WORK/usr/local/cpanel/version"
touch "$P2S_WORK/usr/local/cpanel/scripts/upcp"; chmod 700 "$P2S_WORK/usr/local/cpanel/scripts/upcp"
printf '%s\n' 'Blocker found: No license file found.' 'Blocker found: Required disk space is unavailable.' \
    'package first-apache conflicts with second-apache' > "$P2S_WORK/var/cpanel/updatelogs/last"
P2S_MODE=check; P2S_INVENTORY_MESSAGES=true
p2s_panel_inventory_collect
p2s_panel_inventory_collect
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
''')
        self.assertIn('last recorded update log: cPanel reported a license problem', out)
        self.assertIn('Required disk space is unavailable', out)
        self.assertIn('first-apache conflicts with second-apache', out)
        self.assertEqual(out.count('panel_previous_update_log:'), 1)
        self.assertIn('BLOCKED=false', out)
        self.assertNotIn('UNEXPECTED administrative command', out)

    def test_real_tls_failure_still_has_a_specific_diagnostic(self):
        for failure in ('SSL certificate problem: unable to get local issuer certificate',
                        'Could not handshake: TLS connection failed',
                        'server certificate verification failed'):
            with self.subTest(failure=failure):
                out = self.shell('fixture_output=' + repr(failure) + r'''
printf '%s\n' "$fixture_output" > "$P2S_WORK/package.log"
p2s_package_log_report "$P2S_WORK/package.log"
''')
                self.assertIn('repository_failure:beforefix|tls', out)
                self.assertIn('Certificate verification was not disabled', out)
                self.assertNotIn('needs no HTTPS download', out)

    def test_unconfigured_cpanel_selector_explains_the_actual_failure(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/php"; : > "$runtime"; chmod 700 "$runtime"
: > "$P2S_WORK/paths.raw"
printf 'ea-php-cli|0:1.0.0-1.cpanel|x86_64|cPanel\n' > "$P2S_WORK/packages"
p2s_package_owner_for_path() { printf 'ea-php-cli\n'; }
p2s_runtime_probe_version() { printf 'Default PHP is not configured!\n'; return 2; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('has no default PHP version configured', out)
        self.assertIn('UNKNOWN=true', out)
        self.assertIn('runtime_error:beforefix|', out)
        self.assertNotIn('missing libraries', out)
        self.assertNotIn('This check did not', out)

    def test_exact_cpanel_internal_php_rules_preserve_unknown_custom_builds(self):
        cases = []
        for release in (7, 8, 9):
            cases.extend([('cpanel-php81', f'0:8.1.34-1.cp110~el{release}', 'x86_64', 'Y'),
                          ('cpanel-php81', f'8.1.34-2.cp110~el{release}', 'x86_64', 'N')])
        for release in (8, 9, 10):
            cases.append(('cpanel-php84', f'0:8.4.22-1.cp130~el{release}', 'x86_64', 'Y'))
        cases.extend([('cpanel-php84', '0:8.4.27-1.cp130~el10', 'x86_64', 'N'),
                      ('cpanel-php81', '8.1.34-2.cp110~el9.local', 'x86_64', '?'),
                      ('cpanel-php81', '8.1.34-3.cp110~el9', 'x86_64', '?'),
                      ('cpanel-php81', '1:8.1.34-2.cp110~el9', 'x86_64', '?'),
                      ('cpanel-php84', '0:8.4.22-1.cp130~el10.local', 'x86_64', '?'),
                      ('cpanel-php84', '0:8.4.22-1.cp130~el10', 'aarch64', '?'),
                      ('ea-php84-php-cli', '0:8.4.22-1.cp130~el10', 'x86_64', '?')])
        for name, version, arch, expected in cases:
            with self.subTest(name=name, version=version, arch=arch):
                out = self.shell(f'P2S_DISTRO=almalinux\np2s_version_package_state {name} {version} "(none)" {arch}\n')
                self.assertEqual(out.strip(), expected)

    def test_successful_noop_cpanel_update_names_unfixed_build_and_command(self):
        out = self.shell(r'''
P2S_MODE=fix; P2S_INVENTORY_MESSAGES=true
printf 'cpanel-php84|0:8.4.22-1.cp130~el10|x86_64|(none)\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_command_run() { return 0; }
p2s_package_inventory_assess
p2s_summary_print_versions
p2s_panel_update
P2S_PHASE=afterfix
p2s_package_inventory_assess
p2s_summary_print_versions
P2S_RETRY_ASSESSMENT=true
p2s_package_inventory_assess
p2s_summary_print_versions
''')
        self.assertIn('Initial check: PHP 8.4.22 (cpanel-php84): vulnerable;', out)
        self.assertIn('After update attempt (/fixture/upcp --security): PHP 8.4.22 (cpanel-php84): vulnerable;', out)
        self.assertIn('cPanel\'s security updater returned success, but cpanel-php84 still lacks a verified fix', out)
        self.assertIn('installed package: 0:8.4.22-1.cp130~el10; required: 8.4.27', out)
        self.assertIn('panel_update_verification:afterfix|cpanel-php84|0:8.4.22-1.cp130~el10|Y|required=', out)
        self.assertEqual(out.count('The security updater can skip updates without an error or log'), 1)
        self.assertEqual(out.count('cPanel includes its own PHP software'), 1)
        self.assertNotIn('patch status not verified', out)
        self.assertNotIn('dss:warn: PHP 8.4.22', out)

    def test_update_preferences_identify_skip_settings_without_exposing_other_config(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts" "$P2S_WORK/etc"
printf '11.136.0.29\n' > "$P2S_WORK/usr/local/cpanel/version"
: > "$P2S_WORK/usr/local/cpanel/scripts/upcp"; chmod 700 "$P2S_WORK/usr/local/cpanel/scripts/upcp"
printf '%s\n' 'CPANEL=11.136.0.29' 'SECURITY_UPDATES=never' 'RPMUP=manual' 'UPDATES=manual' \
    'OTHER=private-config' 'CPANEL=https://private.invalid/secret' > "$P2S_WORK/etc/cpupdate.conf"
P2S_INVENTORY_MESSAGES=true
p2s_panel_inventory_collect
P2S_PHASE=afterfix; P2S_TRANSACTION_ATTEMPTED=true
p2s_panel_inventory_collect
''')
        self.assertIn('panel_update_setting:beforefix|cpanel|RPMUP=manual', out)
        self.assertIn('panel_update_setting:afterfix|cpanel|SECURITY_UPDATES=never', out)
        self.assertEqual(out.count('critical security updater is disabled by SECURITY_UPDATES=never'), 1)
        self.assertEqual(out.count('cPanel is pinned to release 11.136.0.29'), 1)
        self.assertNotIn('private', out)

    def test_unfixed_php_reports_dated_previous_log_without_claiming_current_failure(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/var/cpanel/updatelogs"
previous="$P2S_WORK/var/cpanel/updatelogs/update.20261028.log"
printf '%s\n' '=> Log opened Wed Oct 28 05:23:00 2026' \
    'E Blocker found: No license file found. Your cPanel software will not function properly.' \
    'package ea-apache24-2.4.69-1.cpanel.x86_64 from EA4 conflicts with httpd-mmn provided by httpd-core-2.4.63-13.el10.x86_64 from appstream' \
    'ea-apache24 requires ea-apache24-mmn20120211x8664 https://user:password@private.invalid/secret?token=private' \
    'cannot install the best update candidate for package httpd-core' \
    'The update-packages command reported error number 1 when it ended.' \
    'unrelated private operational text' '=> Log closed Wed Oct 28 05:23:32 2026' > "$previous"
touch -t 202610280523.32 "$previous"
ln -s update.20261028.log "$P2S_WORK/var/cpanel/updatelogs/last"
P2S_MODE=fix; P2S_INVENTORY_MESSAGES=true
printf 'cpanel-php84|0:8.4.22-1.cp130~el10|x86_64|(none)\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_command_run() { return 0; }
p2s_panel_update
P2S_PHASE=afterfix
p2s_package_inventory_assess
p2s_package_inventory_assess
printf 'COMPLETED=%s|BLOCKED=%s\n' "$P2S_PANEL_UPDATE_COMPLETED" "$P2S_BLOCKED"
''')
        self.assertIn('modified_UTC=2026-10-28 05:23:32', out)
        self.assertIn('not_current_attempt_output', out)
        self.assertIn('the reported problems may have been resolved since then', out)
        self.assertIn('last recorded update log: cPanel reported a license problem', out)
        self.assertIn('Check the current license status in WHM', out)
        self.assertIn("operating system's Apache package (httpd-core)", out)
        self.assertIn('These historical errors may explain why PHP remains unfixed', out)
        self.assertIn('COMPLETED=true|BLOCKED=false', out)
        self.assertEqual(out.count('panel_previous_update_log:'), 1)
        self.assertIn('repository host=private.invalid; path redacted', out)
        self.assertNotIn('password', out)
        self.assertNotIn('token=private', out)
        self.assertNotIn('unrelated private operational text', out)
        self.assertNotIn('blocker:afterfix|panel_license', out)

    def test_previous_log_is_ignored_for_fixed_php_or_unsafe_log_paths(self):
        for version, target in [('0:8.4.27-1.cp130~el10', 'previous'),
                                ('0:8.4.22-1.cp130~el10', 'missing'),
                                ('0:8.4.22-1.cp130~el10', 'outside'),
                                ('0:8.4.22-1.cp130~el10', 'fifo')]:
            with self.subTest(version=version, target=target):
                out = self.shell('version=' + version + '\ntarget=' + target + r'''
mkdir -p "$P2S_WORK/var/cpanel/updatelogs"
printf '%s\n' 'E Blocker found: No license file found.' > "$P2S_WORK/var/cpanel/updatelogs/previous"
printf '%s\n' 'E Blocker found: No license file found.' > "$P2S_WORK/outside"
case "$target" in
    previous) ln -s previous "$P2S_WORK/var/cpanel/updatelogs/last" ;;
    outside) ln -s "$P2S_WORK/outside" "$P2S_WORK/var/cpanel/updatelogs/last" ;;
    fifo) mkfifo "$P2S_WORK/var/cpanel/updatelogs/last" ;;
esac
printf 'cpanel-php84|%s|x86_64|(none)\n' "$version" > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
P2S_PHASE=afterfix; P2S_PANEL_UPDATE_COMPLETED=true
p2s_package_inventory_assess
''')
                self.assertNotIn('panel_previous_update_', out)
                self.assertNotIn('no license file was found', out)

    def test_previous_log_read_is_bounded_and_unrelated_lines_are_not_reported(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/var/cpanel/updatelogs"
{
    printf '%s\n' 'E Blocker found: No license file found.'
    head -c 300000 /dev/zero | tr '\000' x
    printf '\nCompleted all updates\n'
} > "$P2S_WORK/var/cpanel/updatelogs/last"
p2s_cpanel_last_update_report
printf 'READ_BYTES=%s\n' "$(wc -c < "$P2S_WORK/cpanel-last-update.log" | tr -d ' ')"
''')
        self.assertIn('READ_BYTES=262144', out)
        self.assertNotIn('no license file was found', out)
        self.assertNotIn('panel_previous_update_error:', out)

    def test_cpanel_branch_selection_is_not_an_exact_release_pin(self):
        for release, pinned in [('136', False), ('11.136', False), ('11.136.0', False),
                                ('136.0.29', True), ('11.136.0.29', True)]:
            with self.subTest(release=release):
                out = self.shell('release=' + release + r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts" "$P2S_WORK/etc"
printf '11.136.0.29\n' > "$P2S_WORK/usr/local/cpanel/version"
: > "$P2S_WORK/usr/local/cpanel/scripts/upcp"; chmod 700 "$P2S_WORK/usr/local/cpanel/scripts/upcp"
printf 'CPANEL=%s\n' "$release" > "$P2S_WORK/etc/cpupdate.conf"
p2s_panel_inventory_collect
''')
                self.assertEqual('cPanel is pinned to release' in out, pinned)
                self.assertIn('panel_update_setting:beforefix|cpanel|CPANEL=' + release, out)


if __name__ == '__main__':
    unittest.main()
