"""Cached EL8/9 PHP stream advice; module switches and services are never executed."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))

NATIVE = '''Rocky Linux 8 - AppStream
Name Stream Profiles Summary
php 7.2 [d][e] common [d], devel, minimal PHP scripting language
php 7.3 common [d], devel, minimal PHP scripting language
php 7.4 common [d], devel, minimal PHP scripting language
php 8.0 common [d], devel, minimal PHP scripting language
php 8.2 common [d], devel, minimal PHP scripting language
'''
REMI = '''Remi's Modular repository for Enterprise Linux 8 - x86_64
Name Stream Profiles Summary
php remi-8.1 [e] common [d] [i], devel, minimal PHP scripting language
php remi-8.4 common [d], devel, minimal PHP scripting language
php remi-8.5 common [d], devel, minimal PHP scripting language
php remi-8.6 common [d], devel, minimal PHP scripting language
'''


class RpmStreamTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def fixture(self, module_list=NATIVE, version='0:7.2.24-1.module+el8.4.0+413+c9202dda',
                vendor='Rocky Enterprise Software Foundation', changes=''):
        return r'''
P2S_DISTRO=rocky; P2S_MAJOR=8; P2S_RELEASE=8.10; P2S_BACKEND=rpm
P2S_INVENTORY_MESSAGES=true
''' + 'version=' + shlex.quote(version) + '; vendor=' + shlex.quote(vendor) + '\n' + r'''
printf 'php-common|%s|x86_64|%s\n' "$version" "$vendor" > "$P2S_WORK/packages"
printf 'php-common|?\n' > "$P2S_WORK/package-states"
printf '%s\n' php-fpm.service httpd.service > "$P2S_WORK/services"
''' + 'module_list=' + shlex.quote(module_list) + r'''
p2s_command_exists() { [ "$1" = dnf ]; }
p2s_command_run() {
    case " $* " in
        *' dnf -C --disableplugin=* '*' module list php '*) printf '%s\n' "$module_list" ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
''' + changes + r'''
p2s_package_rpm_stream_guidance_report
printf 'STATE=%s|BLOCKED=%s|UNKNOWN=%s\n' "${P2S_STATE:-unset}" "$P2S_BLOCKED" "$P2S_UNKNOWN"
'''

    def test_native_72_offers_smaller_supported_74_and_native_82(self):
        out = self.shell(self.fixture())
        for target in ('7.4', '8.2'):
            self.assertIn('target=' + target + '|', out)
            self.assertIn('sudo dnf --refresh --assumeno module switch-to php:' + target, out)
            self.assertIn('sudo dnf --refresh module switch-to php:' + target, out)
        self.assertIn('vendor-maintained EL8 stream', out)
        self.assertIn('Ordinary dnf/yum upgrades stay in the enabled PHP stream', out)
        self.assertIn('7.2 to 7.4 changes regular-expression behaviour', out)
        self.assertIn("sudo php-fpm -t", out)
        self.assertIn("sudo httpd -t", out)
        self.assertIn('fixed_candidate=not_queried|manual_only', out)
        self.assertIn('STATE=unset|BLOCKED=false|UNKNOWN=false', out)
        self.assertNotIn('php:remi-', out)

    def test_existing_remi_81_recommends_reviewed_stable_stream_without_provider_change(self):
        out = self.shell(self.fixture(REMI, '0:8.1.34-1.module_php.8.1.el8.remi', 'Remi Collet'))
        self.assertIn('current=remi-8.1|target=remi-8.4/common|', out)
        self.assertIn('sudo dnf --refresh --assumeno module switch-to php:remi-8.4/common', out)
        self.assertIn('Moving between PHP 8 branches', out)
        for omitted in ('php:8.2', 'php:7.4', 'php:remi-8.1/common', 'php:remi-8.6', 'remi-release', 'module reset', '--allowerasing'):
            self.assertNotIn(omitted, out)

    def test_disabled_missing_or_ambiguous_streams_are_not_command_targets(self):
        cases = [(NATIVE.replace('php 7.4 common', 'php 7.4 [x] common'), ['8.2']),
                 (NATIVE.replace('php 8.2 common', 'php remi-8.2 common'), ['7.4']),
                 (NATIVE.replace('php 7.4 common', 'php 7x4 common').replace('php 8.2 common', 'php 8x2 common'), []),
                 (NATIVE.replace('[d][e]', '[d]'), []),
                 (NATIVE + 'php remi-8.1 [e] common PHP\n', [])]
        for listing, targets in cases:
            with self.subTest(listing=listing):
                out = self.shell(self.fixture(listing))
                rows = [r for r in out.splitlines() if 'php_stream_migration:' in r]
                self.assertEqual(len(rows), len(targets))
                for target in targets:
                    self.assertTrue(any('target=' + target + '|' in row for row in rows))

    def test_alma_verified_backport_and_retired_support_are_distinct(self):
        out = self.shell(self.fixture(changes=r'''
P2S_DISTRO=almalinux
printf 'php-common|0:7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1|x86_64|AlmaLinux\n' > "$P2S_WORK/packages"
printf 'php-common|N\n' > "$P2S_WORK/package-states"
'''))
        self.assertIn('already has verified PHP2Shell fixes', out)
        self.assertIn('concerns ongoing support', out)
        self.assertIn('target=7.4|', out)
        self.assertNotIn('First try --fix', out)

    def test_native_80_never_suggests_a_downgrade_to_74(self):
        listing = NATIVE.replace('[d][e]', '[d]').replace('php 8.0 common', 'php 8.0 [e] common')
        out = self.shell(self.fixture(listing, '0:8.0.30-1.module+el8.10.0+1+abcdef'))
        self.assertIn('target=8.2|', out)
        self.assertNotIn('target=7.4|', out)

    def test_native_el9_81_offers_82_and_83_without_an_el8_destination(self):
        listing = 'php 8.1 [e] common PHP\nphp 8.2 common PHP\nphp 8.3 common PHP\nphp 7.4 common PHP\n'
        out = self.shell(self.fixture(listing, '0:8.1.27-1.el9',
                                     changes='P2S_MAJOR=9; P2S_RELEASE=9.8'))
        self.assertIn('target=8.2|', out)
        self.assertIn('target=8.3|', out)
        self.assertNotIn('target=7.4|', out)

    def test_panel_other_blockers_and_maintained_streams_do_not_offer_migration(self):
        cases = ['P2S_PANEL=cpanel', 'P2S_DISTRO=debian', 'P2S_MAJOR=10',
                 'P2S_BLOCKED=true; printf "control_panel\\n" > "$P2S_WORK/blocker-keys"',
                 'printf "php-common|0:7.4.33-8.module+el8.10.0+40393+c071e357|x86_64|Rocky Enterprise Software Foundation\\n" > "$P2S_WORK/packages"']
        for changes in cases:
            with self.subTest(changes=changes):
                out = self.shell(self.fixture(changes=changes))
                self.assertNotIn('php_stream_migration:', out)

    def test_failed_cache_read_gives_a_refresh_command_without_guessing_target(self):
        out = self.shell(self.fixture(changes='p2s_command_run() { printf "No cached metadata available\\n" >&2; return 1; }'))
        self.assertIn('sudo dnf --refresh module list php', out)
        self.assertIn('php_module_gap:', out)
        self.assertNotIn('module switch-to', out)
        self.assertIn('BLOCKED=false|UNKNOWN=false', out)

    def test_rocky8_reviewed_74_backport_is_exact_and_architecture_bound(self):
        fixed = '0:7.4.33-8.module+el8.10.0+40393+c071e357'
        cases = [('php-common', fixed, 'x86_64', 'N'),
                 ('php-fpm', fixed, 'x86_64', 'N'),
                 ('php-cli', fixed + '.local', 'x86_64', '?'),
                 ('php-cli', fixed, 'aarch64', '?'),
                 ('php-cli', fixed.replace('0:', '1:'), 'x86_64', '?'),
                 ('alt-php74-cli', fixed, 'x86_64', '?')]
        for name, version, arch, expected in cases:
            with self.subTest(name=name, version=version, arch=arch):
                out = self.shell('P2S_DISTRO=rocky; P2S_MAJOR=8; P2S_BACKEND=rpm\n' +
                                 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, version, 'Rocky Enterprise Software Foundation', arch))))
                self.assertEqual(out.strip(), expected)


if __name__ == '__main__':
    unittest.main()
