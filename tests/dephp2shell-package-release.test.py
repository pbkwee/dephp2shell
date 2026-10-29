"""Offline build-release warnings; package versions are synthetic local metadata."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))
RUNTIME = runpy.run_path(str(Path(__file__).with_name('dephp2shell-runtime-inventory.test.py')))


class PackageReleaseTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def test_old_debian_packages_are_grouped_and_removed_config_entries_are_excluded(self):
        out = self.shell(r'''
P2S_DISTRO=debian; P2S_RELEASE=13; P2S_INVENTORY_MESSAGES=true
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() {
    printf '%s\n' \
        'libapache2-mod-php5|5.6.40+dfsg-0+deb8u12|amd64|install ok installed|Debian PHP Maintainers' \
        'php5-cli|5.6.40+dfsg-0+deb8u12|amd64|install ok installed|Debian PHP Maintainers' \
        'php5-common|5.6.40+dfsg-0+deb8u12|amd64|install ok installed|Debian PHP Maintainers' \
        'php5-gd|5.6.40+dfsg-0+deb8u12|amd64|deinstall ok config-files|Debian PHP Maintainers' \
        'php5-json|1.3.6-1|amd64|install ok installed|Debian PHP Maintainers' \
        'php5-mcrypt|5.6.27+dfsg-0+deb8u1|amd64|deinstall ok config-files|Debian PHP Maintainers'
}
p2s_package_inventory_collect
p2s_package_release_report
P2S_PHASE=afterfix
p2s_package_release_report
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        warnings = '\n'.join(line for line in out.splitlines() if line.startswith('dss:warn:'))
        self.assertEqual(warnings.count('PHP packages from an older OS release'), 1)
        self.assertIn('Their build labels identify Debian 8; this server runs debian 13', warnings)
        for name in ('libapache2-mod-php5', 'php5-cli', 'php5-common'):
            self.assertIn(name + ' (5.6.40+dfsg-0+deb8u12)', warnings)
            self.assertIn('package_release_mismatch:beforefix|' + name + '|', out)
            self.assertIn('package_release_mismatch:afterfix|' + name + '|', out)
        for name in ('php5-gd', 'php5-json', 'php5-mcrypt'):
            self.assertNotIn(name, warnings)
            self.assertNotIn('package_release_mismatch:beforefix|' + name + '|', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)

    def test_current_release_old_php_unlabelled_and_newer_builds_do_not_warn(self):
        cases = [('debian', '13', '8.4.27-1~deb13u1'),
                 ('debian', '7', '5.4.45-1~bpo70+1'),
                 ('debian', '13.1', '8.4.27-1~deb13u1'),
                 ('debian', '13', '5.6.40+dfsg-1'),
                 ('debian', '13', '5.6.40-1+0~20261001.1+debian13~1.gbpaabbcc'),
                 ('debian', '13', '8.4.27-1+deb14u1'),
                 ('debian', 'testing', '5.6.40+dfsg-0+deb8u12'),
                 ('ubuntu', '26.04', '8.5.4-0ubuntu1.5'),
                 ('ubuntu', '24.04', '8.3.6-0ubuntu0.24.04.13'),
                 ('ubuntu', '24.04', '8.3.6-1+ubuntu24.04.1+deb.sury.org+1')]
        for distro, release, version in cases:
            with self.subTest(distro=distro, release=release, version=version):
                out = self.shell(f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n' +
                                 "printf '%s\\n' " + shlex.quote(f'php5-cli|{version}|amd64|PHP Maintainers') +
                                 r''' > "$P2S_WORK/packages"
p2s_package_release_report
''')
                self.assertNotIn('package_release_mismatch:', out)
                self.assertNotIn('dss:warn:', out)

    def test_native_and_sury_markers_identify_old_target_releases(self):
        cases = [('debian', '13', '5.6.40+dfsg-0+deb8u12+b1', 'Debian 8'),
                 ('debian', '13', '5.4.45-1~bpo70+1', 'Debian 7'),
                 ('debian', '13', '5.4.45-1~bpo60+1', 'Debian 6'),
                 ('debian', '13', '1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428', 'Debian 12'),
                 ('debian', '13', '8.4.27-1~deb13u1~bpo12+1', 'Debian 12'),
                 ('ubuntu', '24.04', '8.1.2-0ubuntu0.22.04.1', 'Ubuntu 22.04'),
                 ('ubuntu', '24.04', '7.4.33-1+ubuntu22.04.1+deb.sury.org+1', 'Ubuntu 22.04')]
        for distro, release, version, expected in cases:
            with self.subTest(version=version):
                out = self.shell(f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n' +
                                 "printf '%s\\n' " + shlex.quote(f'php7.4-cli|{version}|amd64|PHP Maintainers') +
                                 r''' > "$P2S_WORK/packages"
p2s_package_release_report
''')
                self.assertIn('target=' + expected, out)
                self.assertIn('evidence=binary_version_marker', out)

    def test_installed_source_metadata_supplies_a_missing_binary_release_label(self):
        out = self.shell(r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=13
printf '%s\n' 'php5-json|1.3.6-1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
p2s_package_policy_collect() { :; }
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() { printf '%s\n' 'php5-json|1.3.6-1|amd64|php-json (1.3.6-1+deb8u1)'; }
p2s_package_sources_collect
p2s_package_release_report
''')
        self.assertIn('target=Debian 8|host=debian 13|evidence=source_version_marker|revision=1.3.6-1+deb8u1', out)
        self.assertIn('php5-json (1.3.6-1; source 1.3.6-1+deb8u1)', out)

    def test_unmatched_or_empty_source_records_cannot_supply_release_labels(self):
        for records in ('', 'php5-json|another-version|amd64|php-json|1.3.6-1+deb8u1|source_field',
                        'php5-json|1.3.6-1|arm64|php-json|1.3.6-1+deb8u1|source_field'):
            with self.subTest(records=records):
                out = self.shell(r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=13
printf '%s\n' 'php5-json|1.3.6-1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
''' + "printf '%s\\n' " + shlex.quote(records) + r''' > "$P2S_WORK/deb-source-records"
p2s_package_release_report
''')
                self.assertNotIn('package_release_mismatch:', out)

    def test_enterprise_linux_markers_compare_major_release_only(self):
        for distro, release, version, warn in [('almalinux', '9.7', '0:8.1.34-2.cp110~el8', True),
                                               ('rocky', '9.7', '8.2.29-1.el8.remi', True),
                                               ('rhel', '9.7', '8.2.29-1.el9_6', False),
                                               ('centos', '8', '8.2.29-1.el9', False)]:
            with self.subTest(distro=distro, release=release, version=version):
                out = self.shell(f'P2S_BACKEND=rpm; P2S_DISTRO={distro}; P2S_RELEASE={release}\n' +
                                 "printf '%s\\n' " + shlex.quote(f'php-cli|{version}|x86_64|Vendor') +
                                 r''' > "$P2S_WORK/packages"
p2s_package_release_report
''')
                self.assertEqual('target=Enterprise Linux 8' in out, warn)

    def test_debian_and_ubuntu_build_markers_are_recognised_on_the_other_distribution(self):
        cases = [('ubuntu', '22.04', '8.1.34-9+0~20261021.82+debian12~1.gbp4e430a', 'Debian 12'),
                 ('ubuntu', '22.04', '8.2.35-1~deb12u1', 'Debian 12'),
                 ('ubuntu', '22.04', '8.4.27-1~deb13u1~bpo12+1', 'Debian 12'),
                 ('debian', '12', '8.1.34-9+ubuntu22.04.1+deb.sury.org+1', 'Ubuntu 22.04'),
                 ('debian', '13', '8.3.6-0ubuntu0.24.04.13', 'Ubuntu 24.04')]
        for distro, release, version, expected in cases:
            with self.subTest(distro=distro, version=version):
                out = self.shell(f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n' +
                                 "printf '%s\\n' " + shlex.quote(f'php8.1-cli|{version}|amd64|PHP Maintainers') +
                                 r''' > "$P2S_WORK/packages"
p2s_package_release_report
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
''')
                self.assertIn('target=' + expected, out)
                self.assertIn('PHP packages built for another distribution', out)
                self.assertIn('changing the repository alone does not replace these installed packages', out)
                self.assertNotIn('PHP packages from an older OS release', out)
                self.assertIn('BLOCKED=false|UNKNOWN=false', out)

    def test_cross_distribution_source_marker_and_enabled_apache_configuration(self):
        out = self.shell(r'''
P2S_BACKEND=deb; P2S_DISTRO=ubuntu; P2S_RELEASE=22.04
printf '%s\n' 'libapache2-mod-php8.1|8.1.34-9|amd64|PHP Maintainers' > "$P2S_WORK/packages"
printf '%s\n' 'libapache2-mod-php8.1|8.1.34-9|amd64|php8.1|8.1.34-9+0~20261021.82+debian12~1.gbp4e430a|source_field' > "$P2S_WORK/deb-source-records"
mkdir -p "$P2S_WORK/etc/apache2/mods-enabled"
ln -s ../mods-available/php8.1.load "$P2S_WORK/etc/apache2/mods-enabled/php8.1.load"
p2s_package_release_report
p2s_package_release_usage_report
''', isolated_paths=True, isolated_sources=True)
        self.assertIn('target=Debian 12|host=ubuntu 22.04|evidence=source_version_marker', out)
        self.assertIn('Mismatched PHP installation php8.1', out)
        self.assertIn('has enabled Apache configuration', out)
        self.assertNotIn('older-release', out)
        self.assertNotIn('consider removing these packages', out)

    def usage_fixture(self, observations, setup=''):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=13; P2S_PROCESS_USAGE_COMPLETE=true
printf '%s\n' 'php5-cli|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' \
    'php5-common|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' \
    'php5-fpm|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' \
    'php5-mcrypt|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
''' + "printf '%s\\n' " + shlex.quote(observations) + r''' > "$P2S_WORK/runtime-package-observations"
''' + setup + r'''
p2s_package_release_report
p2s_package_release_usage_report
'''

    def test_running_fpm_protects_its_cli_common_files_and_extensions(self):
        out = self.shell(self.usage_fixture('php5-fpm|running_path|/usr/sbin/php5-fpm\nphp5-cli|executable|/usr/bin/php5'),
                         isolated_paths=True, isolated_sources=True)
        self.assertIn('installation=php5|target=Debian 8|usage=running|', out)
        self.assertIn('is in use by running processes', out)
        self.assertIn('php5-fpm (/usr/sbin/php5-fpm)', out)
        self.assertIn('php5-cli, php5-common, php5-fpm, php5-mcrypt', out)
        self.assertNotIn('consider removing these packages', out)

    def test_no_running_use_suggests_reviewed_removal_without_claiming_unused(self):
        out = self.shell(self.usage_fixture('php5-cli|executable|/usr/bin/php5\nphp5-fpm|executable|/usr/sbin/php5-fpm'),
                         isolated_paths=True, isolated_sources=True)
        self.assertIn('usage=no_running_use_observed|', out)
        self.assertIn('No running use was found', out)
        self.assertIn('If websites, scheduled tasks and other installed packages no longer need it, consider removing these packages', out)
        self.assertIn("Review the package manager's proposed removals first", out)
        self.assertNotIn('is unused', out)

    def test_different_php_installations_keep_separate_usage_conclusions(self):
        out = self.shell(self.usage_fixture('php5-cli|executable|/usr/bin/php5\nphp7.4-fpm|running_path|/usr/sbin/php-fpm7.4', r'''
printf '%s\n' 'php7.4-fpm|7.4.33-1+deb11u1|amd64|Debian PHP Maintainers' >> "$P2S_WORK/packages"
'''), isolated_paths=True, isolated_sources=True)
        self.assertIn('installation=php5|target=Debian 8|usage=no_running_use_observed|', out)
        self.assertIn('installation=php7.4|target=Debian 11|usage=running|', out)

    def test_enabled_apache_configuration_prevents_removal_suggestion(self):
        for filename in ('mods-enabled/php5.load', 'conf-enabled/php5-fpm.conf'):
            with self.subTest(filename=filename):
                out = self.shell(self.usage_fixture('php5-cli|executable|/usr/bin/php5',
                                 'mkdir -p "$P2S_WORK/etc/apache2/' + filename.split('/')[0] + '"\n' +
                                 'ln -s /missing-configuration "$P2S_WORK/etc/apache2/' + filename + '"\n'),
                                 isolated_paths=True, isolated_sources=True)
                self.assertIn('usage=configured|', out)
                self.assertIn('has enabled Apache configuration', out)
                self.assertNotIn('consider removing these packages', out)

    def test_incomplete_evidence_does_not_suggest_removal(self):
        for setup in ('P2S_PROCESS_USAGE_COMPLETE=false', 'P2S_PANEL=cpanel',
                      'P2S_SEPARATE_ENVIRONMENT_REVIEW=true', 'P2S_RESTART_PENDING=true',
                      'P2S_BLOCKED=true', 'rm "$P2S_WORK/runtime-package-observations"',
                      r'''printf '%s\n' '|unverified|/missing/php' >> "$P2S_WORK/runtime-package-observations"'''):
            with self.subTest(setup=setup):
                out = self.shell(self.usage_fixture('php5-cli|executable|/usr/bin/php5', setup),
                                 isolated_paths=True, isolated_sources=True)
                self.assertIn('usage=unverified|', out)
                self.assertIn('could not be established', out)
                self.assertNotIn('consider removing these packages', out)

    def test_different_publishers_with_same_php_branch_are_not_combined(self):
        out = self.shell(self.usage_fixture('ea-php82-php-fpm|running_path|/opt/cpanel/php-fpm\nphp8.2-cli|executable|/usr/bin/php8.2', r'''
printf '%s\n' 'php8.2-cli|8.2.29-1~deb12u1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
'''), isolated_paths=True, isolated_sources=True)
        self.assertIn('installation=php8.2|target=Debian 12|usage=no_running_use_observed|', out)
        self.assertNotIn('usage=running|', out)

    def test_real_process_and_runtime_inventory_feed_usage_classification(self):
        for scenario, expected in [('running', 'running'), ('idle', 'no_running_use_observed'),
                                   ('unreadable', 'unverified'), ('scheduled', 'running'), ('legacy_cgi', 'running')]:
            with self.subTest(scenario=scenario):
                out = RUNTIME['RuntimeInventoryTest']().shell('scenario=' + scenario + r'''
P2S_DISTRO=debian; P2S_RELEASE=13
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/usr/sbin" "$P2S_WORK/usr/bin"
printf '1 (init) S 0\n' > "$P2S_WORK/proc/1/stat"
runtime="$P2S_WORK/usr/sbin/php5-fpm"; fixture_owner=php5-fpm; comm=php5-fpm; unit=php5-fpm.service
if [ "$scenario" = scheduled ]; then runtime="$P2S_WORK/usr/bin/php5"; fixture_owner=php5-cli; comm=php5; unit=cron.service; fi
if [ "$scenario" = legacy_cgi ]; then runtime="$P2S_WORK/usr/bin/php5-cgi"; fixture_owner=php5-cgi; comm=php5-cgi; unit=apache2.service; fi
: > "$runtime"; chmod 700 "$runtime"
printf '%s\n' 'php5-cli|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' \
    'php5-common|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' \
    'php5-fpm|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
if [ "$scenario" = legacy_cgi ]; then printf '%s\n' 'php5-cgi|5.6.38+dfsg-0+deb8u1|amd64|Debian PHP Maintainers' >> "$P2S_WORK/packages"; fi
if [ "$scenario" != idle ]; then
    mkdir -p "$P2S_WORK/proc/4242"
    printf '4242 (%s) S 1\n' "$comm" > "$P2S_WORK/proc/4242/stat"
    : > "$P2S_WORK/proc/4242/maps"
    printf '0::/system.slice/%s\n' "$unit" > "$P2S_WORK/proc/4242/cgroup"
    [ "$scenario" = unreadable ] || ln -s "$runtime" "$P2S_WORK/proc/4242/exe"
fi
id() { printf '0\n'; }
ps() { printf 'Thu Oct 22 10:00:00 2026\n'; }
p2s_process_check_host_scope() { return 0; }
p2s_package_owner_for_path() { printf '%s\n' "$fixture_owner"; }
p2s_runtime_probe_version() { printf 'PHP 5.6.38 (cli) (built: Sep 1 2018)\n'; }
p2s_package_backport_evidence_collect() { :; }
p2s_command_run() { case "$2:$3" in dpkg-query:-L) [ "$4" != "$fixture_owner" ] || printf '%s\n' "$runtime"; return 0 ;; *) return 97 ;; esac; }
p2s_package_inventory_assess
p2s_process_inventory_collect
p2s_runtime_inventory_collect
p2s_package_release_report
p2s_package_release_usage_report
''')
                self.assertIn('installation=php5|target=Debian 8|usage=' + expected + '|', out)
                self.assertEqual('consider removing these packages' in out, scenario == 'idle')
                if scenario == 'scheduled':
                    self.assertIn('scheduled_php:', out)


if __name__ == '__main__':
    unittest.main()
