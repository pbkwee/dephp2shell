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
            source = re.sub(r'(?<![A-Za-z0-9_*/.-])/(?:usr|opt|proc|etc|www)/',
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
                self.assertIn('cpanel|license_unavailable|', out)
                self.assertIn('blocker:beforefix|panel_license|', out)
                self.assertIn('A valid cPanel license is required for this update path', out)
                self.assertIn('Some changes may already have been made', out)
                self.assertIn('STATUS=1|COMPLETED=false|BLOCKED=true', out)
                self.assertNotIn('vendor update command completed', out)

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


if __name__ == '__main__':
    unittest.main()
