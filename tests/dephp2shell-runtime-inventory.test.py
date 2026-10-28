"""Offline PHP runtime inventory regressions; administrative commands are denied.

Run with Python 3, optionally setting DP2S_TEST_BASH to an older Bash.
Hardcoded system paths are redirected only in a temporary script copy.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')


class RuntimeInventoryTest(unittest.TestCase):
    def test_missing_packaged_runtime_and_broken_link_keep_owner_and_file_evidence(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/opt/cpanel/ea-php81/root/usr/bin" "$P2S_WORK/usr/bin"
missing="$P2S_WORK/opt/cpanel/ea-php81/root/usr/bin/php"
link="$P2S_WORK/usr/bin/php"
ln -s "$missing" "$link"
printf '%s\n' "$missing" "$link" > "$P2S_WORK/paths.raw"
p2s_package_owner_for_path() { printf 'ea-php81-php-cli\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertRegex(out, r'runtime_path:beforefix\|.*/root/usr/bin/php\|type=missing_or_inaccessible.*package_owner=ea-php81-php-cli')
        self.assertRegex(out, r'runtime_path:beforefix\|.*/usr/bin/php\|type=dangling_or_inaccessible_symlink.*link_target=.*/root/usr/bin/php')
        self.assertIn('inventory_gap:beforefix|runtime_file|', out)
        self.assertIn('UNKNOWN=true', out)

    def test_existing_launcher_with_exit_127_is_recorded_as_present(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/php"
printf '#!/missing/perl\n' > "$runtime"; chmod 700 "$runtime"
printf 'ea-php-cli|1.0.0-1|amd64|cPanel\n' > "$P2S_WORK/packages"
p2s_package_owner_for_path() { printf 'ea-php-cli\n'; }
p2s_runtime_probe_version() { printf 'No such file or directory\n'; return 127; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertRegex(out, r'runtime_path:beforefix\|.*/usr/bin/php\|type=regular_file\|readable=true\|executable=true.*package_owner=ea-php-cli')
        self.assertIn('exit=127', out)
        self.assertIn('UNKNOWN=true', out)
        self.assertNotIn('missing_or_not_regular', out)

    def shell(self, body):
        with tempfile.TemporaryDirectory(prefix='dephp2shell-runtime-test-') as work:
            source = SCRIPT.read_text()
            # Match path starts, not embedded /usr in /opt/.../root/usr paths.
            source = re.sub(r'(?<![A-Za-z0-9_*/.-])/(?:usr|opt|proc|etc|www)/',
                            lambda match: work + match[0], source)
            script = Path(work) / 'fixture.sh'
            script.write_text(source)
            setup = r'''
source "$1"
P2S_WORK="$2"; P2S_PHASE=beforefix; P2S_BLOCKED=false
P2S_UNKNOWN=false; P2S_COUNT=0; P2S_VULNERABLE=false; P2S_RESTART_PENDING=false
P2S_BACKEND=deb
: > "$P2S_WORK/paths.raw"; : > "$P2S_WORK/packages"
p2s_command_run() { printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97; }
apt-get() { return 97; }; yum() { return 97; }; dnf() { return 97; }
systemctl() { return 97; }; service() { return 97; }; rpm() { return 97; }
dpkg() { return 97; }; dpkg-query() { return 97; }
'''
            run = subprocess.run([BASH, '-c', setup + body, 'fixture', str(script), work],
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertNotIn('UNEXPECTED administrative command:', run.stderr)
            return run.stdout

    def test_deleted_web_executable_only_requires_php_restart_when_php_is_mapped(self):
        cases = [('nginx', 'none', 'N', False, False),
                 ('httpd', 'none', 'N', False, False),
                 ('nginx', 'php', '?', True, True),
                 ('httpd', 'php', '?', True, False),
                 ('httpd', 'deleted_php', '?', True, False),
                 ('php-fpm8.3', 'none', '?', True, False),
                 ('nginx', 'unreadable', '?', False, False),
                 ('nginx', 'read_failed', '?', False, False)]
        for name, maps, state, pending, blocked in cases:
            with self.subTest(name=name, maps=maps):
                out = self.shell(f'name={name}; mapping={maps}\n' + r'''
mkdir -p "$P2S_WORK/proc/1"
printf '1 (systemd) S 0\n' > "$P2S_WORK/proc/1/stat"
ln -s /fixture/init "$P2S_WORK/proc/1/exe"
module="$P2S_WORK/libphp.so"; : > "$module"
for pid in 4242 4243; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (%s) S 1\n' "$pid" "$name" > "$P2S_WORK/proc/$pid/stat"
    ln -s "/fixture/$name (deleted)" "$P2S_WORK/proc/$pid/exe"
    ln -s / "$P2S_WORK/proc/$pid/root"
    unit=$name.service
    [ "$name" != php-fpm8.3 ] || unit=php8.3-fpm.service
    printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/$pid/cgroup"
    case "$mapping" in
        php) printf '1234 r-xp 0 0 0 %s\n' "$module" > "$P2S_WORK/proc/$pid/maps" ;;
        deleted_php) printf '1234 r-xp 0 0 0 %s (deleted)\n' "$module" > "$P2S_WORK/proc/$pid/maps" ;;
        unreadable) : ;;
        *) printf '1234 rw-s 0 0 0 /dev/zero (deleted)\n1235 r-xp 0 0 0 /fixture/libssl.so (deleted)\n' > "$P2S_WORK/proc/$pid/maps" ;;
    esac
done
if [ "$mapping" = read_failed ]; then
    awk() { case "$*" in *libphp*) return 1 ;; *) command awk "$@" ;; esac; }
fi
p2s_process_check_host_scope() { return 0; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
id() { printf '0\n'; }
p2s_package_inventory_collect() { :; }
p2s_package_inventory_assess() {
    p2s_state_include N
    printf '8.3.36|N|PHP-FPM||Debian|8.3.36-1|N|executable\n' > "$P2S_WORK/summary-versions"
}
p2s_panel_inventory_collect() { :; }
p2s_runtime_inventory_collect() { :; }
p2s_web_listener_inventory_collect() { :; }
p2s_inventory_collect_and_assess
printf 'STATE=%s|PENDING=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_RESTART_PENDING" "$P2S_BLOCKED"
if [ "$P2S_STATE" = N ]; then
    # Exercise the real fix-mode dispatch while denying package/service operations and lock writes.
    p2s_work_directory_init() { :; }
    p2s_distro_detect() { :; }; p2s_repository_inventory_collect() { :; }; p2s_fix_check_distro_recipe() { :; }
    p2s_command_run() { [ "$2" = df ] && return 0; printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97; }
    p2s_fix_run() { printf 'UNEXPECTED_FIX\n'; return 97; }
    mkdir() { [ "$1" != /var/run/rh-php2shell.lock ] || { printf 'UNEXPECTED_LOCK\n'; return 97; }; command mkdir "$@"; }
    (p2s_main --fix)
fi
''')
                self.assertIn(f'STATE={state}|PENDING={str(pending).lower()}|BLOCKED={str(blocked).lower()}', out)
                advice = [line for line in out.splitlines() if 'Separate maintenance:' in line]
                if state == 'N':
                    # One warning in each inventory; never one per worker.
                    self.assertEqual(len(advice), 2)
                    self.assertIn('Review a restart of this web server', advice[0])
                    self.assertEqual(out.count('dss:manifest:web_restart_advisory:'), 4)
                    self.assertNotIn('php_restart_pending:', out)
                    self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618N', out)
                    self.assertNotIn('UNEXPECTED_', out)
                else:
                    self.assertEqual(advice, [])
                if maps == 'read_failed':
                    self.assertIn('process_maps|4242|nginx|read_failed', out)

    def test_web_listener_observations_are_informational_and_scoped(self):
        cases = [('none', 'No TCP listener on port 80 or 443'),
                 ('ipv4', 'Listening TCP ports: 80 '), ('ipv6', 'Listening TCP ports: 443 '),
                 ('both', 'Listening TCP ports: 80 and 443 '),
                 ('unavailable', 'could not be fully inspected'),
                 ('failed', 'could not be fully inspected')]
        for scenario, message in cases:
            with self.subTest(scenario=scenario):
                out = self.shell('scenario=' + scenario + '\n' + r'''
mkdir -p "$P2S_WORK/proc/net"
if [ "$scenario" != unavailable ]; then
    printf 'sl local_address rem_address st\n' > "$P2S_WORK/proc/net/tcp"
    # Non-LISTEN connections and unrelated ports must not count as web listeners.
    printf '0: 00000000:0050 00000000:0000 01\n1: 00000000:1F90 00000000:0000 0A\n' >> "$P2S_WORK/proc/net/tcp"
fi
case "$scenario" in ipv4|both)
    printf '2: 00000000:0050 00000000:0000 0A\n' >> "$P2S_WORK/proc/net/tcp";; esac
case "$scenario" in ipv6|both)
    printf 'sl local_address rem_address st\n0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A\n' > "$P2S_WORK/proc/net/tcp6";; esac
p2s_command_run() {
    [ "$scenario" != failed ] || return 124
    shift
    [ "$1" = awk ] || return 97
    "$@"
}
p2s_web_listener_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s|VULNERABLE=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED" "$P2S_VULNERABLE"
''')
                self.assertIn(message, out)
                self.assertIn('UNKNOWN=false|BLOCKED=false|VULNERABLE=false', out)
                self.assertIn('network_namespace=current|transport=TCP|ports=80,443', out)
                self.assertNotIn('dss:warn:', out)
                if scenario == 'failed':
                    self.assertIn('tcp|read_failed', out)
                    self.assertNotIn('No TCP listener', out)
                if scenario in ('ipv4', 'both'):
                    self.assertIn('web_listener:beforefix|tcp|80|00000000:0050', out)
                if scenario in ('ipv6', 'both'):
                    self.assertIn('web_listener:beforefix|tcp6|443|', out)

    def test_caddy_recognition_does_not_change_php_restart_or_vulnerability_state(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (caddy) S 1\n' > "$P2S_WORK/proc/4242/stat"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s|VULNERABLE=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED" "$P2S_VULNERABLE"
''')
        self.assertIn('web_process:beforefix|4242|caddy', out)
        self.assertIn('web_process_summary:beforefix|recognised_server=true', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false|VULNERABLE=false', out)
        self.assertNotIn('No recognised web-server process', out)
        self.assertNotIn('No running PHP or related web-server', out)

    def test_web_server_disappearance_after_updates(self):
        cases = [
            # A surviving different server must not conceal a disappearance.
            ('caddy lighttpd', 'lighttpd', 'update', ['Caddy']),
            ('apache2 httpd', '', 'update', ['Apache']),
            ('nginx caddy lighttpd lshttpd frankenphp', '', 'update',
             ['nginx', 'Caddy', 'lighttpd', 'LiteSpeed', 'FrankenPHP']),
            ('apache2', 'httpd', 'update', []),
            ('caddy', 'caddy', 'update', []),
            ('', '', 'update', []),
            ('', 'caddy', 'update', []),
            ('caddy', '', 'blocked', []),
            ('caddy', '', 'restart', ['Caddy']),
            ('caddy', '', 'no_before_inventory', []),
            ('caddy', '', 'no_after_inventory', []),
            ('caddy', '', 'comparison_failed', []),
        ]
        for before, after, mode, missing in cases:
            with self.subTest(before=before, after=after, mode=mode):
                out = self.shell(f'before="{before}"; after="{after}"; mode={mode}\n' + r'''
mkdir -p "$P2S_WORK/proc/1"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
# Detailed PHP process inspection is irrelevant to the before/after name comparison.
readlink() { return 1; }
pid=100
for name in $before; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (%s) S 1\n' "$pid" "$name" > "$P2S_WORK/proc/$pid/stat"
    pid=$((pid + 1))
done
if [ "$mode" = no_before_inventory ]; then rm "$P2S_WORK/proc/1/stat"; fi
p2s_process_inventory_collect
printf 'BEFORE_SCAN_COMPLETE\n'
rm -rf "$P2S_WORK/proc"
mkdir -p "$P2S_WORK/proc/1"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
# Replacement workers have new PIDs even when the web server remains available.
pid=200
for name in $after; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (%s) S 1\n' "$pid" "$name" > "$P2S_WORK/proc/$pid/stat"
    pid=$((pid + 1))
done
if [ "$mode" = no_after_inventory ]; then rm "$P2S_WORK/proc/1/stat"; fi
if [ "$mode" = comparison_failed ]; then grep() { return 2; }; fi
P2S_PHASE=afterfix
P2S_TRANSACTION_ATTEMPTED=true; P2S_RESTART_ATTEMPTED=false
if [ "$mode" = blocked ]; then P2S_TRANSACTION_ATTEMPTED=false; fi
if [ "$mode" = restart ]; then P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=true; fi
P2S_UNKNOWN=false; P2S_BLOCKED=false; P2S_VULNERABLE=false; P2S_STATE=N
p2s_process_inventory_collect
printf 'STATE=%s|VULNERABLE=%s\n' "$P2S_STATE" "$P2S_VULNERABLE"
''')
                before_output, after_output = out.split('BEFORE_SCAN_COMPLETE\n')
                self.assertNotIn('web_server_missing:', before_output)
                self.assertNotIn('not expected to leave the web server stopped', before_output)
                records = re.findall(r'^dss:manifest:web_server_missing:afterfix\|([^|]+)\|',
                                     after_output, re.M)
                self.assertCountEqual(records, missing)
                warnings = re.findall(r'^dss:warn: (\S+) was running before the update attempt',
                                      after_output, re.M)
                self.assertCountEqual(warnings, missing)
                self.assertIn('STATE=N|VULNERABLE=false', after_output)
                if missing:
                    self.assertIn('not expected to leave the web server stopped', after_output)
                    self.assertIn('website availability immediately', after_output)
                if mode == 'comparison_failed':
                    self.assertIn('Could not compare web-server processes', after_output)

    def test_sw_engine_product_revision_is_not_a_php_version(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/sw-engine"
: > "$runtime"; chmod 700 "$runtime"
printf 'sw-engine|6.61.1-ubuntu.22.04.240426.1113|amd64|WebPros\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() {
    if [ "$2" = dpkg-query ]; then printf '%s\n' "$runtime"
    else printf 'PHP 8.3.6 (cli) (built: Apr 26 2024 10:39:49)\n'; fi
}
p2s_package_owner_for_path() { printf 'sw-engine\n'; }
p2s_package_inventory_assess
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
        self.assertIn('embedded_runtime_package:beforefix|sw-engine|6.61.1', out)
        self.assertIn('embedded_engine_independent_version', out)
        self.assertIn('WebPros sw-engine (Plesk/WP Toolkit)', out)
        customer = '\n'.join(row for row in out.splitlines() if row.startswith(('dss:warn:', 'dss:info:')))
        self.assertIn('PHP 8.3.6', customer)
        self.assertNotIn('PHP 6.61.1', customer)
        self.assertNotIn('its package is', customer)
        self.assertNotIn('Package revision: 6.61.1', customer)

    def test_repeated_container_workers_keep_pid_evidence_but_share_one_warning(self):
        out = self.shell(r'''
readlink() { case "$1" in */root) printf '/container-root\n';; *) return 1;; esac; }
for pid in 4242 4243 4244; do
    entry="$P2S_WORK/proc/$pid"; mkdir -p "$entry"
    printf '0::/system.slice/docker-fixture.scope\n' > "$entry/cgroup"
    p2s_process_check_host_scope "$entry" "$pid" /usr/sbin/php-fpm
 done
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertEqual(len([r for r in out.splitlines() if r.startswith('dss:warn:')]), 1)
        for pid in (4242, 4243, 4244):
            self.assertIn(f'process_scope_review:beforefix|{pid}|', out)
        self.assertIn('UNKNOWN=true|BLOCKED=false', out)
        self.assertNotIn('check whether it uses PHP', out)

    def test_container_gap_allows_host_fix_without_becoming_a_host_restart_target(self):
        out = self.shell(r'''
entry="$P2S_WORK/proc/4242"; mkdir -p "$entry"
printf '0::/system.slice/docker-fixture.scope\n' > "$entry/cgroup"
readlink() { case "$1" in */root) printf '/container-root\n';; *) return 1;; esac; }
p2s_process_check_host_scope "$entry" 4242 /usr/sbin/php-fpm
P2S_BACKEND=deb
printf '8.4.26|Y|command line||Debian|8.4.26-1|Y|package\n' > "$P2S_WORK/summary-versions"
: > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
p2s_fix_preflight() { ! $P2S_BLOCKED; }
p2s_package_deb_update() { P2S_TRANSACTION_ATTEMPTED=true; printf 'HOST_UPDATE_REQUESTED\n'; }
p2s_service_restart_and_verify() {
    [ ! -s "$P2S_WORK/services" ] && [ ! -s "$P2S_WORK/processes" ] || return 96
    printf 'NO_FOREIGN_RESTART_TARGETS\n'
}
p2s_fix_run
printf 'RC=%s|UNKNOWN=%s|BLOCKED=%s\n' "$?" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('HOST_UPDATE_REQUESTED', out)
        self.assertIn('NO_FOREIGN_RESTART_TARGETS', out)
        self.assertIn('RC=0|UNKNOWN=true|BLOCKED=false', out)

    def test_panel_version_files_and_tools_are_recorded_without_running_updaters(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/cpanel/scripts" "$P2S_WORK/usr/local/psa/admin/sbin"
printf 'exit 97\n' > "$P2S_WORK/usr/local/psa/admin/sbin/autoinstaller"
chmod 700 "$P2S_WORK/usr/local/psa/admin/sbin/autoinstaller"
printf '11.138.0.18\n' > "$P2S_WORK/usr/local/cpanel/version"
printf '18.0.81 Ubuntu 22.04 180081\n' > "$P2S_WORK/usr/local/psa/version"
printf 'exit 97\n' > "$P2S_WORK/usr/local/cpanel/scripts/upcp"
chmod 700 "$P2S_WORK/usr/local/cpanel/scripts/upcp"
p2s_command_exists() { return 1; }
p2s_panel_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('|11.138.0.18', out)
        self.assertIn('|18.0.81 Ubuntu 22.04', out)
        self.assertIn('/scripts/upcp|not_executed', out)
        tool_rows = [r for r in out.splitlines() if 'panel_update_tool:' in r]
        self.assertEqual(len(tool_rows), 2)
        self.assertTrue(any('|plesk|' in r and '/psa/admin/sbin/autoinstaller|' in r for r in tool_rows))
        self.assertFalse(any('|cpanel|' in r and '/psa/' in r for r in tool_rows))
        self.assertIn('broad_vendor_updates_can_change_non_PHP_components', out)
        self.assertIn('UNKNOWN=false|BLOCKED=true', out)


    def test_supported_panel_recipes_do_not_force_unknown_or_run_updaters_in_check(self):
        for panel, version, supported in [('cpanel', '11.138.0.18', True),
                                           ('cpanel', '11.98.0.1', False),
                                           ('plesk', '18.0.81 Ubuntu', True),
                                           ('plesk', '17.8.11', False),
                                           ('virtualmin', '', True)]:
            with self.subTest(panel=panel, version=version):
                directory = {'cpanel': '/usr/local/cpanel', 'plesk': '/usr/local/psa',
                             'virtualmin': '/etc/webmin/virtual-server'}[panel]
                tool = {'cpanel': '/usr/local/cpanel/scripts/upcp',
                        'plesk': '/usr/sbin/plesk', 'virtualmin': '/fixture/not-used'}[panel]
                out = self.shell('directory=' + directory + '; tool=' + tool +
                                 '; version=' + repr(version) + r"""
mkdir -p "$P2S_WORK$directory" "$(dirname "$P2S_WORK$tool")"
printf '%s\n' "$version" > "$P2S_WORK$directory/version"
printf '#!/bin/sh\nexit 97\n' > "$P2S_WORK$tool"; chmod 700 "$P2S_WORK$tool"
p2s_command_exists() { return 1; }
p2s_package_inventory_collect() { :; }; p2s_package_sources_collect() { :; }
p2s_package_inventory_assess() { p2s_state_include N; }
p2s_process_inventory_collect() { :; }; p2s_web_listener_inventory_collect() { :; }; p2s_runtime_inventory_collect() { :; }
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
printf 'STATE=%s|UNKNOWN=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_UNKNOWN" "$P2S_BLOCKED"
""")
                self.assertIn('STATE=N|UNKNOWN=false|BLOCKED=false' if supported
                              else 'STATE=N|UNKNOWN=false|BLOCKED=true', out)
                if panel == 'virtualmin':
                    self.assertIn('existing repositories and supported service restarts', out)
                if panel == 'plesk' and supported:
                    self.assertIn('databases, mail and web-server components', out)

    def test_panel_service_mappings_are_scoped_and_keep_unknown_units_blocked(self):
        cases = [('cpanel', 'ea-php84-php-fpm.service', 'php-fpm', True),
                 ('cpanel', 'cpanel_php_fpm.service', 'php-fpm', True),
                 ('plesk', 'plesk-php84-fpm.service', 'php-fpm', True),
                 ('plesk', 'sw-engine.service', 'sw-engine-fpm', True),
                 ('cpanel', 'sw-engine.service', 'sw-engine-fpm', True),
                 ('plesk', 'plesk-web-socket.service', 'sw-engine', True),
                 ('plesk', 'plesk-web-socket.service', 'sw-engine', False),
                 ('', 'ea-php84-php-fpm.service', 'php-fpm', False),
                 ('plesk', 'custom-launcher.service', 'php-cgi', False)]
        for panel, unit, comm, supported in cases:
            with self.subTest(panel=panel, unit=unit):
                out = self.shell('P2S_PANEL=' + repr(panel) + '; unit=' + unit + '; comm=' + comm
                                 + '; verified=' + str(supported).lower() + r"""
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (systemd) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (%s) S 1\n' "$comm" > "$P2S_WORK/proc/4242/stat"
ln -s /fixture/init "$P2S_WORK/proc/1/exe"
ln -s "/fixture/$comm" "$P2S_WORK/proc/4242/exe"
printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/4242/cgroup"
: > "$P2S_WORK/proc/4242/maps"
p2s_process_check_host_scope() { return 0; }
p2s_service_plesk_web_socket_verified() { $verified; }
p2s_process_inventory_collect
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
cat "$P2S_WORK/services"; cat "$P2S_WORK/fpm-masters"
""")
                self.assertIn('BLOCKED=' + str(not supported).lower(), out)
                self.assertEqual('\n' + unit + '\n' in out, supported)
                if supported and 'fpm' in comm:
                    self.assertIn('4242|/fixture/' + comm, out)
                if unit == 'plesk-web-socket.service' and not supported:
                    self.assertIn('This script has no verified restart procedure for this service', out)
                    self.assertIn('safe restart method for sw-engine', out)

    def test_plesk_web_socket_requires_reviewed_owned_unit_without_overrides(self):
        vendor_unit = '''# Copyright 1999-2026. WebPros International GmbH. All rights reserved.

[Unit]
Description=Plesk Web Socket Service
Wants=mariadb.service mysql.service
After=network.target mariadb.service mysql.service

[Service]
Type=simple
ExecStart=/opt/psa/bin/sw-engine-pleskrun /opt/psa/admin/plib/WebSocket/bin/ws-server.php
User=psaadm
Group=psaadm
RuntimeDirectory=plesk-web-socket
RuntimeDirectoryMode=0770

[Install]
WantedBy=multi-user.target
'''
        for change, allowed in [('', True), ('changed=true', False), ('fixture_overrides=/etc/custom.conf', False),
                                ('fixture_owner=customer-package', False), ('P2S_PANEL=cpanel', False),
                                ('P2S_BACKEND=rpm', False), ('missing_property=true', False)]:
            with self.subTest(change=change):
                out = self.shell('vendor_unit=' + shlex.quote(vendor_unit) + r'''
P2S_PANEL=plesk; P2S_BACKEND=deb; fixture_owner=plesk-web-socket; fixture_overrides=; changed=false; missing_property=false
''' + change + r'''
mkdir -p "$P2S_WORK/usr/lib/systemd/system"
fixture_fragment="$P2S_WORK/usr/lib/systemd/system/plesk-web-socket.service"
printf '%s' "$vendor_unit" > "$fixture_fragment"
if $changed; then printf '\nExecStart=/custom/app\n' >> "$fixture_fragment"; fi
p2s_command_exists() { return 0; }
p2s_command_run() {
    case " $* " in
        *' systemctl show '*)
            printf 'FragmentPath=%s\n' "$fixture_fragment"
            if ! $missing_property; then printf 'DropInPaths=%s\n' "$fixture_overrides"; fi ;;
        *' systemctl restart plesk-web-socket.service '*) printf 'RESTARTED\n' ;;
        *) return 97 ;;
    esac
}
p2s_package_owner_for_path() { printf '%s\n' "$fixture_owner"; }
p2s_service_plesk_web_socket_verified; printf 'VERIFIED_RC=%s\n' "$?"
p2s_service_run plesk-web-socket.service restart; printf 'RESTART_RC=%s\n' "$?"
''')
                self.assertIn('VERIFIED_RC=' + ('0' if allowed else '1'), out)
                self.assertIn('RESTART_RC=' + ('0' if allowed else '1'), out)
                self.assertEqual('RESTARTED' in out, allowed)

    def test_cagefs_directory_requires_review_without_claiming_it_is_active(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/cagefs"
p2s_command_exists() { return 1; }
p2s_panel_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('CageFS configuration was found', out)
        self.assertIn('This script cannot verify whether applications use separate PHP copies', out)
        self.assertIn('UNKNOWN=true|BLOCKED=true', out)
        self.assertNotIn('CageFS was detected', out)

    def test_inventory_includes_vendor_runtime_package_families(self):
        out = self.shell(r'''
for name in lsphp84 lsphp84-common cpanel-php84 sw-engine frankenphp; do
    p2s_package_is_php "$name" && printf 'PHP_PACKAGE=%s\n' "$name"
done
:
''')
        self.assertEqual(out.splitlines(), ['PHP_PACKAGE=' + name for name in
                         ('lsphp84', 'lsphp84-common', 'cpanel-php84', 'sw-engine', 'frankenphp')])

    def test_bare_lsphp_and_panel_engine_are_runtime_paths(self):
        out = self.shell(r'''
p2s_runtime_path_add /fixture/bin/lsphp
p2s_runtime_path_add /fixture/bin/sw-engine
p2s_runtime_path_add /fixture/bin/php-config
p2s_runtime_path_add /fixture/bin/phpize
cat "$P2S_WORK/paths.raw"
''')
        self.assertEqual(out.splitlines(), ['/fixture/bin/lsphp', '/fixture/bin/sw-engine'])

    def test_rocky9_fixed_backport_clears_without_installing_or_restarting(self):
        out = self.shell(r'''
P2S_DISTRO=rocky; P2S_RELEASE=9.5; P2S_MAJOR=9
p2s_package_inventory_collect() {
    P2S_BACKEND=rpm
    printf '%s\n' 'php-common|0:8.0.30-8.el9_8.1|x86_64|Rocky Enterprise Software Foundation' \
        'php-cli|0:8.0.30-8.el9_8.1|x86_64|Rocky Enterprise Software Foundation' \
        'php|0:8.0.30-8.el9_8.1|x86_64|Rocky Enterprise Software Foundation' > "$P2S_WORK/packages"
}
mkdir -p "$P2S_WORK/usr/bin"
for name in php php-cgi; do : > "$P2S_WORK/usr/bin/$name"; chmod 700 "$P2S_WORK/usr/bin/$name"; done
p2s_package_backport_evidence_collect() { :; }
p2s_process_inventory_collect() { :; }
p2s_web_listener_inventory_collect() { :; }
p2s_package_owner_for_path() { printf 'php-cli\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.0.30 (cli) (built: Oct 21 2026)\n'; }
p2s_command_run() { [ "$2:$3" = rpm:-ql ] || return 97; }
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
p2s_summary_print_result
printf 'STATE=%s|UNKNOWN=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('STATE=N|UNKNOWN=false|BLOCKED=false', out)
        self.assertIn('fixes verified for both PHP2Shell vulnerabilities', out)
        self.assertIn('The PHP package publisher added the security fixes without changing the PHP version', out)
        self.assertNotIn('dss:warn:', out)
        self.assertNotIn('No recognised web-server', out)

    def test_package_directories_named_php_do_not_make_fixed_runtime_unknown(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/share/php" "$P2S_WORK/usr/lib/php" "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/php8.3"
: > "$runtime"; chmod 700 "$runtime"
printf 'php8.3-cli|8.3.36-1|amd64|Debian PHP Maintainers\n' > "$P2S_WORK/packages"
printf 'php8.3-cli|N\n' > "$P2S_WORK/package-states"
: > "$P2S_WORK/summary-versions"
for directory in "$P2S_WORK/usr/share/php" "$P2S_WORK/usr/lib/php"; do p2s_runtime_path_add "$directory"; done
p2s_runtime_path_add "$runtime"
p2s_package_owner_for_path() { printf 'php8.3-cli\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.3.36 (cli) (built: Oct 21 2026)\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=false', out)
        self.assertRegex(out, r'runtime_assessment:beforefix\|.*\|8[.]3[.]36\|.*\|N\|')

    def test_missing_or_unparseable_runtime_explains_unknown(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                out = self.shell('missing=' + str(missing).lower() + '\n' + r'''
mkdir -p "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/php8.3"
if ! $missing; then : > "$runtime"; chmod 700 "$runtime"; fi
printf '%s\n' "$runtime" > "$P2S_WORK/paths.raw"
printf 'php8.3-cli|8.3.36-1|amd64|Debian PHP Maintainers\n' > "$P2S_WORK/packages"
printf 'php8.3-cli|N\n' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'php8.3-cli\n'; }
p2s_runtime_probe_version() { printf 'unexpected wrapper output\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
                self.assertIn('UNKNOWN=true', out)
                self.assertIn('dss:warn:', out)
                self.assertIn('missing_or_not_regular' if missing else 'unrecognised_output', out)

    def test_failed_package_file_inventory_explains_unknown(self):
        out = self.shell(r'''
printf 'php8.3-cli|8.3.36-1|amd64|Debian PHP Maintainers\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_version_package_state() { printf 'N\n'; }
p2s_command_run() { return 1; }
p2s_package_inventory_assess
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=true', out)
        self.assertIn('package_files|php8.3-cli|file_list_failed', out)
        self.assertIn('Could not list runtime files for PHP package php8.3-cli', out)

    def test_vendor_locations_are_inventoried_without_running_host_commands(self):
        locations = (
            '/usr/local/php84/bin/php',
            '/usr/local/php84/sbin/php-fpm',
            '/usr/local/lsws/lsphp84/bin/lsphp',
            '/www/server/php/84/bin/php',
            '/www/server/php/84/sbin/php-fpm',
            '/opt/php84/bin/php',
            '/usr/lib/cgi-bin/php8.4',
            '/usr/local/bin/lsphp',
            '/usr/local/bin/frankenphp',
            '/opt/plesk/php/8.4/sbin/php-fpm',
            '/opt/cpanel/ea-php84/root/usr/sbin/php-fpm',
        )
        for location in locations:
            with self.subTest(location=location):
                out = self.shell('runtime="$P2S_WORK' + location + '"\n' + r'''
mkdir -p "${runtime%/*}"
: > "$runtime"; chmod 700 "$runtime"
p2s_package_owner_for_path() { return 1; }
p2s_command_run() { printf 'PHP 8.4.26 (cli) (built: Oct 20 2026)\n'; }
p2s_runtime_inventory_collect
''')
                self.assertIn(location + '|unowned', out)

    def test_frankenphp_version_is_the_embedded_php_version(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/local/bin"
: > "$P2S_WORK/usr/local/bin/frankenphp"; chmod 700 "$P2S_WORK/usr/local/bin/frankenphp"
p2s_package_owner_for_path() { return 1; }
p2s_command_run() {
    if [ "$3" != version ]; then printf 'WRONG_FRANKENPHP_COMMAND\n'; return 1; fi
    printf 'FrankenPHP v1.11.1 PHP 8.4.26 Caddy v2.10.2\n'
}
p2s_runtime_inventory_collect
printf 'VULNERABLE=%s\n' "$P2S_VULNERABLE"
''')
        self.assertNotIn('WRONG_FRANKENPHP_COMMAND', out)
        self.assertIn('PHP 8.4.26', out)
        self.assertIn('VULNERABLE=true', out)

    def test_one_vulnerable_custom_runtime_wins_over_other_fixed_versions(self):
        for first, second in [('8.2.34', '8.4.27'), ('8.4.27', '8.2.34')]:
            with self.subTest(first=first, second=second):
                out = self.shell('first=' + first + '\nsecond=' + second + '\n' + r'''
mkdir -p "$P2S_WORK/usr/bin"
for name in php8.2 php8.4; do
    : > "$P2S_WORK/usr/bin/$name"; chmod 700 "$P2S_WORK/usr/bin/$name"
done
p2s_package_inventory_collect() { :; }; p2s_panel_inventory_collect() { :; }; p2s_process_inventory_collect() { :; }
p2s_package_owner_for_path() { return 1; }
p2s_command_run() {
    case "${2##*/}" in
        php8.2) printf 'PHP %s (cli)\n' "$first" ;;
        php8.4) printf 'PHP %s (cli)\n' "$second" ;;
        *) return 97 ;;
    esac
}
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
printf 'STATE=%s\n' "$P2S_STATE"
''')
                self.assertIn('STATE=Y', out)
                self.assertIn('PHP 8.2.34 (cli)', out)
                self.assertIn('PHP 8.4.27 (cli)', out)

    def test_fixed_runtime_does_not_require_a_known_package_owner(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
p2s_package_owner_for_path() { printf 'vendor-bundle\n'; }
p2s_command_run() { printf 'PHP 8.4.27 (cli) (built: Oct 21 2026)\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s|COUNT=%s\n' "$P2S_UNKNOWN" "$P2S_COUNT"
''')
        self.assertIn('UNKNOWN=false|COUNT=1', out)

    def test_foreign_process_cannot_supply_host_paths_or_restart_targets(self):
        for root, namespace in (('/customer-jail', 'mnt:[1]'), ('/', 'mnt:[2]'),
                                ('', 'mnt:[1]'), ('/', '')):
            with self.subTest(root=root, namespace=namespace):
                out = self.shell("fixture_root=" + repr(root) + "\nfixture_ns=" + repr(namespace) + "\n" + r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (php-fpm8.4) S 1\n' > "$P2S_WORK/proc/4242/stat"
: > "$P2S_WORK/proc/4242/maps"
printf '0::/system.slice/php8.4-fpm.service\n' > "$P2S_WORK/proc/4242/cgroup"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() {
    case "$1" in
        */4242/root) printf '%s\n' "$fixture_root" ;;
        */4242/ns/mnt) printf '%s\n' "$fixture_ns" ;;
        */self/ns/mnt) printf 'mnt:[1]\n' ;;
        */4242/exe) printf '/fixture/usr/sbin/php-fpm8.4\n' ;;
        */1/exe) printf '/fixture/sbin/init\n' ;;
        *) return 1 ;;
    esac
}
ps() { printf 'Oct 22 2026\n'; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
printf 'PATHS=%s|SERVICES=%s|PROCESSES=%s\n' "$(cat "$P2S_WORK/paths.raw")" "$(cat "$P2S_WORK/services")" "$(cat "$P2S_WORK/processes")"
''')
                self.assertIn('UNKNOWN=true|BLOCKED=false', out)
                self.assertIn('PATHS=|SERVICES=|PROCESSES=', out)
                self.assertIn('verification_gap:beforefix|isolated_runtime', out)

    def test_installed_container_commands_are_named_without_claiming_running_containers(self):
        for tools in ('docker', 'podman lxc-ls', ''):
            with self.subTest(tools=tools):
                out = self.shell('tools="' + tools + '"\n' + r'''
p2s_command_exists() { case " $tools " in *" $1 "*) return 0;; *) return 1;; esac; }
p2s_panel_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
                if tools:
                    self.assertIn('UNKNOWN=false|BLOCKED=false', out)
                    self.assertIn('dss:info: Container software installed:', out)
                    self.assertNotIn('verification_gap:', out)
                    for tool in tools.split():
                        label = {'docker': 'Docker', 'podman': 'Podman', 'lxc-ls': 'LXC'}[tool]
                        self.assertIn(f'container_tool:beforefix|{label}|{tool}|installed_only', out)
                    self.assertNotIn('appears to be inside', out)
                else:
                    self.assertIn('UNKNOWN=false|BLOCKED=false', out)
                    self.assertNotIn('containers is installed', out)
                    self.assertNotIn('container_tool:', out)

    def test_isolated_process_names_container_only_from_its_own_cgroup(self):
        cases = [('/docker/abc', 'Docker'),
                 ('/system.slice/docker-abc.scope', 'Docker'),
                 ('/user.slice/libpod-abc.scope', 'Podman'),
                 ('/lxc/customer', 'LXC'), ('/lxc.payload.customer', 'LXC'),
                 ('/system.slice/php8.4-fpm.service', None), ('', None)]
        for cgroup, label in cases:
            with self.subTest(cgroup=cgroup):
                out = self.shell('cgroup="' + cgroup + '"\n' + r'''
entry="$P2S_WORK/proc/4242"
mkdir -p "$entry"
if [ -n "$cgroup" ]; then printf '0::%s\n' "$cgroup" > "$entry/cgroup"; fi
readlink() { case "$1" in */root) printf '/application-jail\n';; *) return 1;; esac; }
p2s_process_check_host_scope "$entry" 4242 /fixture/php
printf 'HOST=%s|UNKNOWN=%s|BLOCKED=%s\n' "$?" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
                self.assertIn('HOST=1|UNKNOWN=true|BLOCKED=false', out)
                self.assertIn('process_scope:beforefix|4242|/application-jail|unavailable', out)
                if label:
                    self.assertIn(f'is inside a {label} container', out)
                    self.assertIn(f'process_container_evidence:beforefix|4242|{label}|0::{cgroup}', out)
                    self.assertIn('Check and update PHP inside that environment separately', out)
                else:
                    self.assertIn('uses a separate or unidentified application environment', out)
                    self.assertNotIn('appears to be inside', out)

    def test_only_fpm_master_is_saved_for_service_validation(self):
        out = self.shell(r"""
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242" "$P2S_WORK/proc/4243"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (php-fpm8.4) S 1\n' > "$P2S_WORK/proc/4242/stat"
printf '4243 (php-fpm8.4) S 4242\n' > "$P2S_WORK/proc/4243/stat"
for pid in 4242 4243; do
    : > "$P2S_WORK/proc/$pid/maps"
    printf '0::/system.slice/php8.4-fpm.service\n' > "$P2S_WORK/proc/$pid/cgroup"
done
readlink() {
    case "$1" in
        */4242/exe|*/4243/exe) printf '/fixture/php-fpm8.4\n' ;;
        */1/exe) printf '/fixture/init\n' ;;
        *) return 1 ;;
    esac
}
p2s_process_check_host_scope() { return 0; }
ps() { printf 'Oct 22 2026\n'; }
p2s_process_inventory_collect
printf 'MASTERS=%s\n' "$(cat "$P2S_WORK/fpm-masters")"
printf 'SERVICES=%s\n' "$(cat "$P2S_WORK/services")"
""")
        self.assertIn('MASTERS=4242|/fixture/php-fpm8.4', out)
        self.assertNotIn('MASTERS=4243', out)
        self.assertIn('SERVICES=php8.4-fpm.service', out)
        self.assertEqual(out.count('PHP-FPM 8.4 main process started:'), 1)

    def test_isolated_web_server_only_requires_php_review_for_a_concrete_gap(self):
        for mappings, unknown in [('empty', False), ('php', True), ('missing', True), ('failed', True)]:
            with self.subTest(mappings=mappings):
                out = self.shell('mapping=' + mappings + r'''
entry="$P2S_WORK/proc/4242"; mkdir -p "$entry"
printf '0::/docker/fixture\n' > "$entry/cgroup"
case "$mapping" in
    empty|failed) : > "$entry/maps" ;;
    php) printf '1234 r-xp 0 0 0 /application/libphp.so\n' > "$entry/maps" ;;
esac
if [ "$mapping" = failed ]; then awk() { return 1; }; fi
readlink() { case "$1" in */root) printf '/application-root\n';; *) return 1;; esac; }
p2s_process_check_host_scope "$entry" 4242 /usr/sbin/apache2
printf 'HOST=%s|UNKNOWN=%s|BLOCKED=%s\n' "$?" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
                self.assertIn('HOST=1|UNKNOWN=' + str(unknown).lower() + '|BLOCKED=false', out)
                self.assertEqual('dss:manifest:verification_gap:' in out, unknown)
                self.assertEqual('dss:warn:' in out, unknown)
                if mappings == 'empty':
                    self.assertIn('dss:info: A running apache2 web-server process is inside a Docker container.', out)
                if mappings == 'php':
                    self.assertIn('PHP module loaded', out)
                if mappings in ('missing', 'failed'):
                    self.assertIn('PHP module inspection failed', out)

    def test_embedded_php_uses_engine_version_not_product_revision_or_update_recipe(self):
        cases = [('sw-engine', '8.4.27', 'N'), ('sw-engine', '8.3.6', '?'),
                 ('sw-engine', '', '?'), ('frankenphp', '8.4.27', 'N'),
                 ('frankenphp', '8.4.26', 'Y'), ('frankenphp', '', '?')]
        for product, version, expected in cases:
            with self.subTest(product=product, version=version):
                out = self.shell('product=' + product + '; fixture_php_version=' + repr(version) + r'''
P2S_BACKEND=deb
mkdir -p "$P2S_WORK/usr/local/bin"
runtime="$P2S_WORK/usr/local/bin/$product"
: > "$runtime"; chmod 700 "$runtime"
printf '%s|1.2.3-1|amd64|Custom publisher\n' "$product" > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() { printf '%s\n' "$runtime"; }
p2s_package_owner_for_path() { printf '%s\n' "$product"; }
p2s_runtime_probe_version() { [ -n "$fixture_php_version" ] || return 1; printf 'PHP %s (cli)\n' "$fixture_php_version"; }
p2s_package_inventory_collect() { :; }; p2s_package_sources_collect() { :; }
p2s_panel_inventory_collect() { :; }; p2s_process_inventory_collect() { :; }; p2s_web_listener_inventory_collect() { :; }
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
p2s_summary_print_result
printf 'STATE=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_BLOCKED"
''')
                self.assertIn('STATE=' + expected + '|BLOCKED=true', out)
                self.assertNotIn('PHP 1.2.3', out)
                if expected == 'N':
                    self.assertIn('All detected PHP installations include both PHP2Shell fixes', out)
                if not version:
                    self.assertIn('embedded_PHP_version|', out)

    def test_restart_capability_is_separate_from_current_php_status(self):
        for version, deleted, expected in [('8.4.27', False, 'N'), ('8.4.27', True, '?'),
                                           ('8.4.26', False, 'Y')]:
            with self.subTest(version=version, deleted=deleted):
                out = self.shell('fixture_php_version=' + version + '; deleted=' + str(deleted).lower() + r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242" "$P2S_WORK/usr/sbin"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (php-fpm8.4) S 1\n' > "$P2S_WORK/proc/4242/stat"
: > "$P2S_WORK/proc/4242/maps"
printf '0::/system.slice/custom-php.service\n' > "$P2S_WORK/proc/4242/cgroup"
runtime="$P2S_WORK/usr/sbin/php-fpm8.4"; : > "$runtime"; chmod 700 "$runtime"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() {
    case "$1" in
        */4242/exe) printf '%s' "$runtime"; $deleted && printf ' (deleted)'; printf '\n' ;;
        */1/exe) printf '/fixture/init\n' ;; *) return 1 ;;
    esac
}
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_check_host_scope() { return 0; }
p2s_package_inventory_collect() { printf 'php8.4-fpm|%s-1|amd64|Debian\n' "$fixture_php_version" > "$P2S_WORK/packages"; }
p2s_package_sources_collect() { :; }; p2s_panel_inventory_collect() { :; }; p2s_web_listener_inventory_collect() { :; }
p2s_package_inventory_assess() {
    state=$(p2s_version_upstream_state "$fixture_php_version"); p2s_state_include "$state"
    printf 'php8.4-fpm|%s\n' "$state" > "$P2S_WORK/package-states"
    : > "$P2S_WORK/summary-versions"
}
p2s_package_owner_for_path() { printf 'php8.4-fpm\n'; }
p2s_runtime_probe_version() { printf 'PHP %s (fpm-fcgi)\n' "$fixture_php_version"; }
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
printf 'STATE=%s|PENDING=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_RESTART_PENDING" "$P2S_BLOCKED"
''')
                self.assertIn('STATE=' + expected + '|PENDING=' + str(deleted).lower() + '|BLOCKED=true', out)
                self.assertIn('restart_target_unverified', out)
                self.assertEqual('deleted_executable' in out, deleted)

    def test_isolated_nginx_does_not_claim_php_is_running_inside_its_container(self):
        out = self.shell(r'''
entry="$P2S_WORK/proc/4242"
mkdir -p "$entry"
printf '0::/system.slice/docker-fixture.scope\n' > "$entry/cgroup"
readlink() { case "$1" in */root) printf '/container-root\n';; *) return 1;; esac; }
p2s_process_check_host_scope "$entry" 4242 /usr/sbin/nginx
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('nginx web-server process', out)
        self.assertIn('is inside a Docker container', out)
        self.assertIn('PHP module inspection failed', out)
        self.assertIn('process_scope_review:beforefix|4242|nginx web-server process|', out)
        self.assertIn('UNKNOWN=true|BLOCKED=false', out)
        self.assertNotIn('PHP is running inside', out)

    def test_same_root_without_namespace_support_remains_supported(self):
        out = self.shell(r'''
readlink() { case "$1" in */root) printf '/\n';; *) return 1;; esac; }
p2s_process_check_host_scope /fixture/proc/4242 4242
printf 'HOST=%s|UNKNOWN=%s\n' "$?" "$P2S_UNKNOWN"
''')
        self.assertIn('HOST=0|UNKNOWN=false', out)

    def test_private_mount_namespace_requires_shared_runtime_file_identity(self):
        for shared in (True, False):
            with self.subTest(shared=shared):
                out = self.shell('shared=' + str(shared).lower() + '\n' + r'''
entry="$P2S_WORK/proc/4242"
mkdir -p "$entry"
ln -s / "$entry/root"
: > "$P2S_WORK/runtime"
readlink() {
    case "$1" in
        */4242/ns/mnt) printf 'mnt:[2]\n' ;;
        */self/ns/mnt) printf 'mnt:[1]\n' ;;
        *) command readlink "$1" ;;
    esac
}
path="$P2S_WORK/runtime"
$shared || path="$P2S_WORK/missing-runtime"
p2s_process_check_host_scope "$entry" 4242 "$path"
printf 'HOST=%s|UNKNOWN=%s\n' "$?" "$P2S_UNKNOWN"
''')
                self.assertIn('HOST=0|UNKNOWN=false' if shared else 'HOST=1|UNKNOWN=true', out)

    def test_mapped_php_module_requires_host_path_identity(self):
        for available in (True, False):
            with self.subTest(available=available):
                out = self.shell('available=' + str(available).lower() + '\n' + r'''
entry="$P2S_WORK/proc/4242"
mkdir -p "$entry" "$P2S_WORK/proc/1"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (apache2) S 1\n' > "$entry/stat"
ln -s / "$entry/root"
module="$P2S_WORK/libphp8.4.so"
if $available; then : > "$module"; fi
printf '1234 r-xp 0 0 0 %s\n' "$module" > "$entry/maps"
printf '0::/system.slice/apache2.service\n' > "$entry/cgroup"
readlink() {
    case "$1" in
        */4242/exe) printf '/fixture/apache2\n' ;;
        */1/exe) printf '/fixture/init\n' ;;
        */ns/mnt) printf 'mnt:[1]\n' ;;
        *) command readlink "$1" ;;
    esac
}
ps() { printf 'Oct 22 2026\n'; }
p2s_process_inventory_collect
printf 'BLOCKED=%s\n' "$P2S_BLOCKED"
cat "$P2S_WORK/paths.raw"
''')
                self.assertIn('BLOCKED=' + str(not available).lower(), out)
                self.assertEqual('isolated_module' in out, not available)
                self.assertEqual(any(line.endswith('/libphp8.4.so') for line in out.splitlines()), available)
    def test_changelog_mentions_are_evidence_not_clearance(self):
        out = self.shell(r'''
P2S_BACKEND=rpm; P2S_DISTRO=rocky; P2S_MAJOR=9
p2s_command_run() { printf 'Mention CVE-2026-109618 and CVE-2026-109619\n'; }
p2s_package_backport_evidence_collect php-common
state=$(p2s_version_package_state php-common 8.1.34-1.el9 'Unknown Vendor')
printf 'STATE=%s\n' "$state"
''')
        self.assertIn('dss:manifest:backport_mention:beforefix|php-common|Mention CVE-', out)
        self.assertIn('STATE=?', out)
        self.assertNotIn('dss:isvulnerable:', out)


    def test_runtime_aliases_share_one_customer_build_summary(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin" "$P2S_WORK/usr/sbin"
: > "$P2S_WORK/usr/bin/php8.4"; chmod 700 "$P2S_WORK/usr/bin/php8.4"
ln -s php8.4 "$P2S_WORK/usr/bin/php"
: > "$P2S_WORK/usr/sbin/php-fpm8.4"; chmod 700 "$P2S_WORK/usr/sbin/php-fpm8.4"
printf '%s\n' 'php8.4-cli|8.4.27-1|amd64|Debian PHP Maintainers' 'php8.4-fpm|8.4.27-1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
printf '%s\n' 'php8.4-cli|N' 'php8.4-fpm|N' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { case "$1" in *fpm*) printf 'php8.4-fpm\n';; *) printf 'php8.4-cli\n';; esac; }
p2s_runtime_probe_version() {
    case "$1" in *fpm*) printf 'PHP 8.4.27 (fpm-fcgi) (built: Oct 21 2026 08:21:27) (NTS)\n' ;;
        *) printf 'PHP 8.4.27 (cli) (built: Oct 21 2026 08:21:27) (NTS)\n' ;; esac
}
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
        self.assertEqual(out.count('dss:manifest:php_version:beforefix|'), 3)
        info = [row for row in out.splitlines() if row.startswith('dss:info:')]
        self.assertEqual(len(info), 1)
        self.assertIn('PHP-FPM, command line', info[0])
        self.assertNotIn('Oct 21 2026 08:21:27', info[0])
        self.assertRegex(out, r'dss:manifest:php_version:beforefix\|.*Oct 21 2026 08:21:27')
        self.assertNotIn('/usr/', info[0])

    def test_mismatched_executable_is_not_summarised_as_verified(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php8.4"; chmod 700 "$P2S_WORK/usr/bin/php8.4"
printf '%s\n' 'php8.4-cli|8.4.27-1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
printf '%s\n' 'php8.4-cli|N' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'php8.4-cli\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.4.26 (cli) (built: Oct 20 2026)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
        self.assertIn('runtime_mismatch', out)
        self.assertIn('PHP 8.4.26 (command line): patch status not verified', out)
        self.assertNotIn('fixes verified', out)

    def test_fixed_executable_supplies_evidence_missing_from_selector_package(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php8.4"; chmod 700 "$P2S_WORK/usr/bin/php8.4"
# A selector or unrecognised package cannot supply an engine patch assessment.
printf '%s\n' 'php8.4|8.4.27-1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
: > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'php8.4\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.4.27 (cli) (built: Oct 21 2026)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=false', out)
        self.assertIn('PHP 8.4.27 (command line): fixes verified', out)
        self.assertNotIn('runtime_mismatch', out)

    def test_control_panels_report_found_and_bounded_absence(self):
        for names in [(), ('cpanel',), ('plesk', 'virtualmin')]:
            with self.subTest(names=names):
                locations = {'cpanel': '/usr/local/cpanel', 'plesk': '/usr/local/psa',
                             'virtualmin': '/etc/webmin/virtual-server'}
                body = 'p2s_command_exists() { return 1; }\n'
                for name in names:
                    body += 'mkdir -p "$P2S_WORK' + locations[name] + '"\n'
                body += 'p2s_panel_inventory_collect\nprintf "BLOCKED=%s\\n" "$P2S_BLOCKED"\n'
                out = self.shell(body)
                self.assertEqual(out.count('dss:manifest:panel:beforefix|'), len(names))
                self.assertEqual('No recognised hosting control panel detected in the checked locations.' in out, not names)
                self.assertIn('BLOCKED=' + str(bool(names)).lower(), out)
                if 'cpanel' in names:
                    self.assertIn('Control panel detected: cPanel.', out)
                if 'plesk' in names:
                    self.assertIn('Control panel detected: Plesk.', out)
                if 'virtualmin' in names:
                    self.assertIn("Check each virtual server's selected PHP version and application compatibility", out)

    def test_repository_failure_categories_have_no_download_dependency(self):
        for text, category in [('SSL certificate verify failed', 'tls'),
                               ('404 Not Found', 'http_404'),
                               ('Temporary failure resolving repository', 'dns'),
                               ('NO_PUBKEY missing vendor key', 'authentication')]:
            with self.subTest(category=category):
                out = self.shell("printf '%s\\n' " + repr(text) + r''' > "$P2S_WORK/error"
p2s_package_failure_report "$P2S_WORK/error"
''')
                self.assertIn('dss:manifest:repository_failure:beforefix|' + category, out)

    def test_software_collection_module_package_is_an_engine(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
p2s_package_is_engine php83-php && printf 'ENGINE\n'
''')
        self.assertEqual(out, 'ENGINE\n')

    def test_panel_libraries_and_selectors_are_not_engine_versions(self):
        engines = ['cpanel-php84', 'cpanel-php84-common', 'lsphp84',
                   'lsphp84-common', 'ea-php84-php-cli', 'php83-php',
                   'ea-php56-php-litespeed', 'ea-php83-php-litespeed']
        libraries = ['cpanel-php84-xml-serializer', 'cpanel-php84-pear',
                     'cpanel-php84-xml-common', 'lsphp84-xml',
                     'lsphp84-xml-common', 'ea-php-cli', 'ea-php84',
                     'ea-php83-php-litespeed-devel', 'ea-php83-litespeed',
                     'ea-php83-php-litespeed-common-extra']
        out = self.shell('P2S_BACKEND=rpm\nfor name in ' + ' '.join(engines + libraries) + r''' ; do
    p2s_package_is_php "$name" && printf 'INVENTORY=%s\n' "$name"
    if p2s_package_is_engine "$name"; then printf 'ENGINE=%s\n' "$name"; fi
done
''')
        self.assertEqual([row[7:] for row in out.splitlines() if row.startswith('ENGINE=')], engines)
        self.assertEqual([row[10:] for row in out.splitlines() if row.startswith('INVENTORY=')],
                         engines + libraries)

    def test_easyapache_litespeed_runtime_uses_its_engine_package_assessment(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/opt/cpanel/ea-php83/root/usr/bin"
runtime="$P2S_WORK/opt/cpanel/ea-php83/root/usr/bin/lsphp"
: > "$runtime"; chmod 700 "$runtime"
printf 'ea-php83-php-litespeed|8.3.36-1.cpanel|x86_64|cPanel\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_version_package_state() { printf 'N\n'; }
p2s_command_run() { [ "$2" = rpm ] && [ "$3" = -ql ] && printf '%s\n' "$runtime"; }
p2s_package_owner_for_path() { printf 'ea-php83-php-litespeed\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.3.36 (litespeed)\n'; }
p2s_package_inventory_assess
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('package_assessment:beforefix|ea-php83-php-litespeed|', out)
        self.assertIn('|N|engine_package_assessment|', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)
        self.assertNotIn('owner_is_not_an_assessed_engine', out)

    def test_selector_owner_keeps_independent_version_in_manifest(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
printf 'ea-php-cli|0:1.0.0-12.20.31.cpanel|x86_64|cPanel\n' > "$P2S_WORK/packages"
: > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'ea-php-cli\n'; }
p2s_runtime_probe_version() { printf 'PHP 8.4.27 (cli) (built: Oct 21 2026 12:00:00)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
printf 'UNKNOWN=%s|BLOCKED=%s|VULNERABLE=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED" "$P2S_VULNERABLE"
''')
        self.assertIn('UNKNOWN=false|BLOCKED=true|VULNERABLE=false', out)
        self.assertNotIn('runtime_mismatch', out)
        self.assertIn('Automatic updates require a separate procedure', out)
        self.assertRegex(out, r'dss:manifest:runtime_identity:beforefix\|.*ea-php-cli\|0:1[.]0[.]0-12[.]20[.]31[.]cpanel\|cPanel EasyApache\|')
        self.assertRegex(out, r'dss:manifest:runtime_assessment:beforefix\|.*ea-php-cli\|8[.]4[.]27\|0:1[.]0[.]0-12[.]20[.]31[.]cpanel\|cPanel EasyApache\|N\|owner_is_not_an_assessed_engine')
        self.assertNotIn('Package revision: 0:1.0.0', out)

    def test_equal_versions_keep_provider_specific_conclusions_and_evidence(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/usr/bin"
for name in php8.4 php-cgi; do : > "$P2S_WORK/usr/bin/$name"; chmod 700 "$P2S_WORK/usr/bin/$name"; done
printf '%s\n' 'ea-php84-php-cli|8.4.27-1|x86_64|cPanel' 'cpanel-php84|8.4.27-2|x86_64|cPanel' > "$P2S_WORK/packages"
printf '%s\n' 'ea-php84-php-cli|N' 'cpanel-php84|?' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { case "$1" in *php-cgi) printf 'cpanel-php84\n';; *) printf 'ea-php84-php-cli\n';; esac; }
p2s_runtime_probe_version() { printf 'PHP 8.4.27 (cli) (built: Oct 21 2026 12:00:00)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        rows = [row for row in out.splitlines() if row.startswith(('dss:info: PHP ', 'dss:warn: PHP '))]
        self.assertEqual(len(rows), 2)
        self.assertTrue(any('fixes verified' in row and 'Package label: cPanel EasyApache.' in row for row in rows))
        self.assertTrue(any('patch status not verified' in row and 'Package label: cPanel internal.' in row for row in rows))
        self.assertEqual(out.count('dss:manifest:runtime_identity:beforefix|'), 2)
        self.assertEqual(out.count('dss:manifest:runtime_assessment:beforefix|'), 2)
        self.assertIn('UNKNOWN=true', out)

    def test_unknown_arch_backend_does_not_assume_unpacked_upstream_build(self):
        out = self.shell(r'''
P2S_BACKEND=unknown; P2S_DISTRO=arch
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
p2s_package_owner_for_path() { return 1; }
p2s_runtime_probe_version() { printf 'PHP 8.5.7 (cli) (built: Jun 3 2026 14:41:23)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
printf 'UNKNOWN=%s|BLOCKED=%s|VULNERABLE=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED" "$P2S_VULNERABLE"
''')
        self.assertIn('UNKNOWN=true|BLOCKED=true|VULNERABLE=false', out)
        self.assertIn('package_inventory_unavailable', out)
        self.assertIn('dss:manifest:php_version:beforefix|', out)
        self.assertIn('Jun 3 2026 14:41:23', out)
        self.assertRegex(out, r'dss:manifest:runtime_assessment:beforefix\|.*\|8[.]5[.]7\|.*\|[?]\|.*\|upstream=Y')
        self.assertIn('The upstream version is in the affected range', out)
        self.assertNotIn('bundled or custom build', out)

    def test_process_read_failure_explains_unknown_without_claiming_update_failed(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (php-fpm) S 1\n' > "$P2S_WORK/proc/4242/stat"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { return 1; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=true', out)
        self.assertIn('inventory_gap:beforefix|process_executable|4242|php-fpm|unreadable_or_exited', out)
        self.assertIn('We could not fully check some running PHP or web-server processes', out)
        self.assertIn('Rerun the check', out)
        self.assertIn('No recognised web-server process was detected', out)

    def test_process_that_exits_during_probe_does_not_make_verification_unknown(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (apache2) S 1\n' > "$P2S_WORK/proc/4242/stat"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { rm -rf "$P2S_WORK/proc/4242"; return 1; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=false', out)
        self.assertIn('process_exit:beforefix|4242|apache2|exited_before_executable_check', out)
        self.assertNotIn('inventory_gap:', out)
        self.assertNotIn('We could not fully check', out)


    def scheduled_php_fixture(self):
        return r"""
P2S_BACKEND=deb
printf 'php8.2-cli|8.2.35-1~deb12u1|amd64|Debian\n' > "$P2S_WORK/packages"
mkdir -p "$P2S_WORK/proc/1"
printf '1 (systemd) S 0\n' > "$P2S_WORK/proc/1/stat"
make_job_stat() {
    awk -v pid="$1" -v ticks="$2" 'BEGIN {
        printf "%s (php scheduled (job)) S 1", pid
        for(i=5;i<=21;i++) printf " 0"
        printf " %s\n", ticks
    }' > "$P2S_WORK/proc/$1/stat"
}
for pid in 4242 4243; do
    mkdir -p "$P2S_WORK/proc/$pid"
    make_job_stat "$pid" 12345
    ln -s /fixture/php8.2 "$P2S_WORK/proc/$pid/exe"
    printf 'Uid:\t1001\t1001\t1001\t1001\n' > "$P2S_WORK/proc/$pid/status"
    printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/$pid/cgroup"
    : > "$P2S_WORK/proc/$pid/maps"
done
p2s_process_check_host_scope() { return 0; }
p2s_package_owner_for_path() { printf '%s\n' "$fixture_owner"; }
"""

    def test_packaged_cron_cli_jobs_do_not_block_updates_or_become_restart_targets(self):
        for unit, owner, allowed in [('cron.service', 'php8.2-cli', True),
                                     ('crond.service', 'php8.2-cli', True),
                                     ('custom.service', 'php8.2-cli', False),
                                     ('cron.service', 'php8.2-cgi', False),
                                     ('cron.service', 'php-cli', False),
                                     ('cron.service', '', False)]:
            with self.subTest(unit=unit, owner=owner):
                out = self.shell('unit=' + unit + '; fixture_owner=' + repr(owner) + '\n' +
                                 self.scheduled_php_fixture() + r"""
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
printf 'SERVICES=%s|RESTART_PROCESSES=%s\n' "$(cat "$P2S_WORK/services")" "$(cat "$P2S_WORK/processes")"
""")
                self.assertIn('UNKNOWN=false|BLOCKED=' + str(not allowed).lower(), out)
                if allowed:
                    self.assertIn('SERVICES=|RESTART_PROCESSES=', out)
                    self.assertEqual(out.count('dss:manifest:scheduled_php:'), 2)
                    self.assertIn('uid=1001', out)
                    self.assertIn('start_ticks=12345', out)
                    self.assertIn('tasks do not block PHP package updates', out)
                elif unit == 'cron.service':
                    self.assertIn('Restarting cron does not reliably replace existing tasks', out)

    def test_original_scheduled_jobs_keep_post_update_result_unknown_until_they_exit(self):
        for status, expected in [('same', '?'), ('one', '?'), ('reused', 'N'), ('gone', 'N'), ('unreadable', '?')]:
            with self.subTest(status=status):
                out = self.shell('unit=cron.service; fixture_owner=php8.2-cli; status=' + status + '\n' +
                                 self.scheduled_php_fixture() + r"""
p2s_process_inventory_collect
cp "$P2S_WORK/scheduled-php" "$P2S_WORK/scheduled-php.before"
case "$status" in
    reused) for pid in 4242 4243; do make_job_stat "$pid" 23456; done ;;
    gone) rm -rf "$P2S_WORK/proc/4242" "$P2S_WORK/proc/4243" ;;
    one) rm -rf "$P2S_WORK/proc/4243" ;;
    unreadable) rm "$P2S_WORK/proc/4242/stat" "$P2S_WORK/proc/4243/stat" ;;
esac
p2s_package_inventory_collect() { :; }; p2s_package_sources_collect() { :; }; p2s_panel_inventory_collect() { :; }
p2s_package_inventory_assess() {
    p2s_state_include N
    printf '8.2.35|N|command line||Debian|8.2.35-1~deb12u1|N|package\n' > "$P2S_WORK/summary-versions"
}
p2s_runtime_inventory_collect() { :; }; p2s_web_listener_inventory_collect() { :; }
id() { printf '0\n'; }
P2S_PHASE=afterfix; P2S_TRANSACTION_ATTEMPTED=true
p2s_inventory_collect_and_assess
printf 'STATE=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_BLOCKED"
""")
                self.assertIn('STATE=' + expected + '|BLOCKED=false', out)
                if expected == '?':
                    if status == 'one':
                        self.assertIn('1 PHP scheduled-task process from before the update is still running', out)
                    else:
                        self.assertIn('PHP scheduled-task processes from before the update', out)
                        self.assertIn('PIDs: 4242, 4243', out)
                    self.assertIn('then run this check again', out)
                    self.assertIn('dss:manifest:aggregate:afterfix|?', out)
                else:
                    self.assertNotIn('dss:warn: 2 PHP scheduled-task', out)

    def test_unattempted_update_does_not_claim_scheduled_tasks_kept_old_php(self):
        out = self.shell('unit=cron.service; fixture_owner=php8.2-cli\n' + self.scheduled_php_fixture() + r"""
p2s_process_inventory_collect
cp "$P2S_WORK/scheduled-php" "$P2S_WORK/scheduled-php.before"
P2S_PHASE=afterfix; P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=false
p2s_process_scheduled_php_verify
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
""")
        self.assertIn('UNKNOWN=false', out)
        self.assertNotIn('from before the update are still running', out)

    def test_packaged_cron_definition_is_not_a_php_runtime(self):
        out = self.shell(r"""
p2s_runtime_path_add "$P2S_WORK/etc/cron.d/php"
p2s_runtime_path_add /usr/bin/php8.2
cat "$P2S_WORK/paths.raw"
""")
        self.assertNotIn('/cron.d/', out)
        self.assertIn('/usr/bin/php8.2', out)

    def test_packaged_service_and_logrotate_definitions_are_not_php_runtimes(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/logrotate.d" "$P2S_WORK/etc/init.d"
for file in "$P2S_WORK/etc/logrotate.d/sw-engine" "$P2S_WORK/etc/init.d/php-fpm"; do
    : > "$file"; chmod 700 "$file"
    p2s_runtime_path_add "$file"
done
p2s_runtime_path_add /usr/bin/sw-engine
cat "$P2S_WORK/paths.raw"
''')
        self.assertEqual(out.strip(), '/usr/bin/sw-engine')

    def test_sysconfig_files_do_not_become_runtimes_or_verification_gaps(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/sysconfig" "$P2S_WORK/opt/cpanel/ea-php83/root/etc/sysconfig" \
    "$P2S_WORK/opt/cpanel/ea-php83/root/usr/sbin" "$P2S_WORK/usr/lib64/httpd/modules"
standard_config="$P2S_WORK/etc/sysconfig/php-fpm"
panel_config="$P2S_WORK/opt/cpanel/ea-php83/root/etc/sysconfig/php-fpm"
runtime="$P2S_WORK/opt/cpanel/ea-php83/root/usr/sbin/php-fpm"
module="$P2S_WORK/usr/lib64/httpd/modules/libphp.so"
for file in "$standard_config" "$panel_config" "$runtime" "$module"; do
    : > "$file"; chmod 700 "$file"
done
printf 'ea-php83-php-fpm|8.3.36-1.cpanel|x86_64|cPanel\n' > "$P2S_WORK/packages"
P2S_BACKEND=rpm
p2s_package_backport_evidence_collect() { :; }
p2s_version_package_state() { printf 'N\n'; }
p2s_command_run() {
    [ "$2" = rpm ] && [ "$3" = -ql ] || return 97
    printf '%s\n' "$standard_config" "$panel_config" "$runtime" "$module"
}
p2s_package_owner_for_path() { printf 'ea-php83-php-fpm\n'; }
p2s_runtime_probe_version() {
    [ "$1" = "$runtime" ] || { printf 'UNEXPECTED_CONFIG_PROBE\n'; return 97; }
    printf 'PHP 8.3.36 (fpm-fcgi)\n'
}
p2s_package_inventory_assess
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)
        self.assertNotIn('/etc/sysconfig/', out)
        self.assertNotIn('UNEXPECTED_CONFIG_PROBE', out)
        self.assertNotIn('inventory_gap:', out)
        self.assertRegex(out, r'runtime_probe:beforefix\|.*/root/usr/sbin/php-fpm\|exit=0')
        self.assertRegex(out, r'runtime_observation:beforefix\|.*/libphp[.]so\|module')

    def test_nonexecutable_engine_is_still_reported_as_a_verification_gap(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
runtime="$P2S_WORK/usr/bin/php8.3"; : > "$runtime"
printf 'php8.3-cli|8.3.36-1|amd64|Debian\n' > "$P2S_WORK/packages"
p2s_runtime_path_add "$runtime"
p2s_package_owner_for_path() { printf 'php8.3-cli\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertIn('UNKNOWN=true', out)
        self.assertRegex(out, r'inventory_gap:beforefix\|runtime_version\|.*php8[.]3\|not_executable')

    def test_unmapped_workers_share_warning_but_keep_each_mapping_record(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/proc/1"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
for pid in 4242 4243; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (php-fpm) S 1\n' "$pid" > "$P2S_WORK/proc/$pid/stat"
    : > "$P2S_WORK/proc/$pid/maps"; : > "$P2S_WORK/proc/$pid/cgroup"
done
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { case "$1" in */4242/exe|*/4243/exe) printf '/fixture/php-fpm\n';; *) return 1;; esac; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_check_host_scope() { return 0; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        warnings = [row for row in out.splitlines() if row.startswith('dss:warn:')]
        self.assertEqual(len(warnings), 1)
        self.assertIn('2 processes', warnings[0])
        self.assertIn('we could not verify a safe restart method', warnings[0])
        self.assertEqual(out.count('dss:manifest:service_mapping:beforefix|'), 2)
        self.assertIn('|4242|php-fpm|/fixture/php-fpm|unknown|restart_target_unverified', out)
        self.assertIn('|4243|php-fpm|/fixture/php-fpm|unknown|restart_target_unverified', out)
        self.assertIn('UNKNOWN=false|BLOCKED=true', out)
        self.assertIn('No deleted PHP executables or modules were detected in the inspected processes.', out)
        self.assertNotIn('This does not establish', out)

    def test_supervisor_workers_explain_targeted_review_and_remain_blocked(self):
        for unit in ('supervisor.service', 'supervisord.service'):
            with self.subTest(unit=unit):
                out = self.shell(f'unit={unit}\n' + r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4200"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4200 (rr) S 1\n' > "$P2S_WORK/proc/4200/stat"
printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/4200/cgroup"
for pid in 4242 4243; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (php8.2) S 4200\n' "$pid" > "$P2S_WORK/proc/$pid/stat"
    : > "$P2S_WORK/proc/$pid/maps"
    printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/$pid/cgroup"
done
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { case "$1" in
    */4242/exe|*/4243/exe) printf '/fixture/php8.2\n';;
    */4200/exe) printf '/fixture/rr\n';;
    *) return 1;; esac; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_check_host_scope() { return 0; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
printf 'RESTART_TARGETS=%s\n' "$(cat "$P2S_WORK/services")"
p2s_fix_run
printf 'FIX_STATUS=%s|INSTALL=%s|RESTART=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED" "$P2S_RESTART_ATTEMPTED"
''')
                warnings = [row for row in out.splitlines() if row.startswith('dss:warn:')]
                self.assertEqual(len(warnings), 1)
                warning = warnings[0]
                for text in ('2 processes', 'service ' + unit,
                             'This script cannot safely restart these Supervisor-managed applications',
                             'supervisorctl status with the correct configuration',
                             'service_mapping/process_parent',
                             'Stop only those programs', 'PHP children stop and stay stopped',
                             'Retry --fix', 'restore the programs even if patching fails',
                             'Verify the applications and rerun --check',
                             'Do not stop Supervisor itself or all its programs'):
                    self.assertIn(text, warning)
                for pid in (4242, 4243):
                    self.assertIn(f'process_parent:beforefix|{pid}|4200|rr|/fixture/rr|{unit}', out)
                    self.assertIn(f'service_mapping:beforefix|{pid}|php8.2|/fixture/php8.2|{unit}|restart_target_unverified', out)
                self.assertIn('UNKNOWN=false|BLOCKED=true', out)
                self.assertIn('RESTART_TARGETS=\n', out)
                self.assertIn('FIX_STATUS=1|INSTALL=false|RESTART=false', out)

    def test_cgi_workers_explain_launcher_review_and_keep_parent_evidence(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4200"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4200 (spawn-fcgi) S 1\n' > "$P2S_WORK/proc/4200/stat"
printf '0::/system.slice/custom-fastcgi.service\n' > "$P2S_WORK/proc/4200/cgroup"
for pid in 4242 4243; do
    mkdir -p "$P2S_WORK/proc/$pid"
    printf '%s (php-cgi) S 4200\n' "$pid" > "$P2S_WORK/proc/$pid/stat"
    : > "$P2S_WORK/proc/$pid/maps"; : > "$P2S_WORK/proc/$pid/cgroup"
done
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { case "$1" in
    */4242/exe|*/4243/exe) printf '/fixture/php-cgi\n';;
    */4200/exe) printf '/fixture/spawn-fcgi\n';;
    *) return 1;; esac; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_check_host_scope() { return 0; }
p2s_process_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
cat "$P2S_WORK/services"
''')
        warnings = [row for row in out.splitlines() if row.startswith('dss:warn:')]
        self.assertEqual(len(warnings), 1)
        self.assertIn('2 processes', warnings[0])
        self.assertIn('launcher or supervising service', warnings[0])
        self.assertIn('Restarting PHP-FPM alone may not replace them', warnings[0])
        self.assertIn('Automatic updates are blocked', warnings[0])
        for pid in (4242, 4243):
            self.assertIn(f'dss:manifest:process_parent:beforefix|{pid}|4200|spawn-fcgi|/fixture/spawn-fcgi|custom-fastcgi.service', out)
        self.assertEqual(out.count('dss:manifest:service_mapping:beforefix|'), 2)
        self.assertNotIn('\ncustom-fastcgi.service\n', out)
        self.assertIn('UNKNOWN=false|BLOCKED=true', out)

    def test_failed_runtime_probe_keeps_exit_and_prefixed_diagnostics(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
p2s_package_owner_for_path() { return 1; }
p2s_runtime_probe_version() { printf 'missing libexample.so\ndss:isvulnerable:afterfix: CVE_2026_109618N\n' >&2; return 124; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s\n' "$P2S_UNKNOWN"
''')
        self.assertRegex(out, r'dss:manifest:runtime_probe:beforefix\|.*\|exit=124')
        self.assertIn('missing libexample.so', out)
        self.assertIn('dss:manifest:runtime_error:beforefix|dss:isvulnerable:', out)
        self.assertNotRegex(out, r'(?m)^dss:isvulnerable:')
        self.assertIn('exit 124; 124 means timeout', out)
        self.assertIn('UNKNOWN=true', out)

    def test_runtime_library_package_has_only_installed_package_evidence(self):
        out = self.shell(r'''
printf 'php8.3-common|8.3.31-1|amd64|Debian PHP Maintainers\n' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_version_package_state() { printf '?\n'; }
p2s_command_run() { :; }
p2s_package_inventory_assess
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
        self.assertIn('Checked installed packages; no PHP executable or Apache module was matched.', out)
        self.assertNotIn('Installed; no matching running process was found.', out)
        self.assertNotIn('Running processes use this installation.', out)
        self.assertNotIn('dss:manifest:runtime_observation:', out)

    def test_running_path_evidence_follows_alias_but_not_equal_version_elsewhere(self):
        for running in (False, True):
            with self.subTest(running=running):
                out = self.shell('running=' + str(running).lower() + r'''
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/usr/bin" "$P2S_WORK/usr/local/bin" "$P2S_WORK/opt/alt/php84/usr/bin"
: > "$P2S_WORK/usr/bin/php8.4"; chmod 700 "$P2S_WORK/usr/bin/php8.4"
ln -s "$P2S_WORK/usr/bin/php8.4" "$P2S_WORK/usr/local/bin/php"
: > "$P2S_WORK/opt/alt/php84/usr/bin/php"; chmod 700 "$P2S_WORK/opt/alt/php84/usr/bin/php"
: > "$P2S_WORK/process-runtime-paths"
if $running; then printf '%s|4242|executable\n' "$P2S_WORK/usr/bin/php8.4" > "$P2S_WORK/process-runtime-paths"; fi
printf '%s\n' 'ea-php84-php-cli|8.4.27-1|x86_64|cPanel' 'alt-php84-cli|8.4.27-2|x86_64|CloudLinux' > "$P2S_WORK/packages"
printf '%s\n' 'ea-php84-php-cli|N' 'alt-php84-cli|N' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { case "$1" in */opt/alt/*) printf 'alt-php84-cli\n';; *) printf 'ea-php84-php-cli\n';; esac; }
p2s_runtime_probe_version() { printf 'PHP 8.4.27 (cli)\n'; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
                rows = [row for row in out.splitlines() if row.startswith('dss:info: PHP ')]
                self.assertEqual(len(rows), 2)
                easy = next(row for row in rows if 'Package label: cPanel EasyApache.' in row)
                alt = next(row for row in rows if 'Package label: CloudLinux/TuxCare alt-PHP.' in row)
                self.assertIn('Installed; no matching running process was found.', alt)
                if running:
                    self.assertIn("Running processes use this installation.", easy)
                    self.assertRegex(out, r'dss:manifest:runtime_observation:beforefix\|.*/usr/local/bin/php\|running_path')
                    self.assertRegex(out, r'dss:manifest:runtime_observation:beforefix\|.*/usr/bin/php8[.]4\|running_path')
                else:
                    self.assertIn('Installed; no matching running process was found.', easy)
                    self.assertNotIn('|running_path', out)
                self.assertRegex(out, r'dss:manifest:runtime_observation:beforefix\|.*/opt/alt/php84/usr/bin/php\|executable')

    def test_running_apache_module_has_package_version_and_process_reference(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/usr/lib/httpd/modules" "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
module="$P2S_WORK/usr/lib/httpd/modules/libphp.so"
: > "$module"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (httpd) S 1\n' > "$P2S_WORK/proc/4242/stat"
printf '0000-1000 r-xp 0000 00:00 1 %s\n' "$module" > "$P2S_WORK/proc/4242/maps"
printf '0::/system.slice/httpd.service\n' > "$P2S_WORK/proc/4242/cgroup"
ln -s / "$P2S_WORK/proc/4242/root"
ln -s /fixture/httpd "$P2S_WORK/proc/4242/exe"
p2s_process_check_host_scope() { return 0; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_inventory_collect
printf 'php|8.3.33-1.el10_2.alma.1|x86_64|AlmaLinux\n' > "$P2S_WORK/packages"
printf 'php|N\n' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'php\n'; }
p2s_runtime_probe_version() { printf 'UNEXPECTED_MODULE_EXECUTION\n'; return 97; }
p2s_runtime_inventory_collect
p2s_summary_print_versions
''')
        self.assertRegex(out, r'dss:manifest:process_runtime_reference:beforefix\|4242\|module\|.*/libphp[.]so')
        self.assertRegex(out, r'dss:manifest:runtime_observation:beforefix\|.*/libphp[.]so\|running_path')
        self.assertIn('PHP 8.3.33 (Apache module): fixes verified', out)
        self.assertIn('Package label: AlmaLinux.', out)
        self.assertNotIn('Package revision:', out)
        self.assertRegex(out, r'dss:manifest:runtime_identity:beforefix\|.*\|php\|8[.]3[.]33-1[.]el10_2[.]alma[.]1\|AlmaLinux\|')
        self.assertIn("Running processes use this installation.", out)
        self.assertNotIn('UNEXPECTED_MODULE_EXECUTION', out)
        self.assertNotIn('dss:manifest:php_version:', out)

if __name__ == '__main__':
    unittest.main()
