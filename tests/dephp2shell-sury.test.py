"""Sury provider continuity and exact backports; package operations are mocked."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class SuryTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def fixture(self, changes='', simulation=None):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
old='1:7.4.33-30+0~20261010.120+debian12~1.gbpabcdef'
candidate='1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428'
name=php7.4-cli; arch=amd64; proposed_arch=amd64; source=php7.4
uri=https://packages.sury.org/php; origin=deb.sury.org; suite=bookworm
extra_repo=false; extra_uri=https://deb.debian.org/debian; config='Dir "/";'; selected_source=php7.4; no_repo=false; mixed=true
fixture_native_candidate=8.2.34-1~deb12u1
selector='2:8.4+101+0~20261021.78+debian12~1.gbp53f25f'
''' + changes + r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf '%s|%s|%s|Debian PHP Maintainers\n' "$name" "$old" "$arch" > "$P2S_WORK/packages"
# A native engine and a Sury selector must stay outside the Sury transaction.
if $mixed; then
    printf '%s\n' 'php8.2-cli|8.2.34-1~deb12u1|amd64|Debian' >> "$P2S_WORK/packages"
    printf 'php-cli|%s|all|Debian\n' "$selector" >> "$P2S_WORK/packages"
fi
printf '%s|%s|%s|%s|%s|source_field\n' "$name" "$old" "$arch" "$selected_source" "$old" > "$P2S_WORK/deb-source-records"
fixture_candidate=$candidate; fixture_old=$old; fixture_name=$name; fixture_arch=$arch
fixture_proposed_arch=$proposed_arch; fixture_source=$source; fixture_uri=$uri
fixture_origin=$origin; fixture_suite=$suite; fixture_config=$config
fixture_index_arch=$arch; [ "$arch" != all ] || fixture_index_arch=amd64
p2s_command_exists() { case "$1" in apt-get|apt-cache|apt-config|dpkg) return 0;; *) return 1;; esac; }
p2s_command_run() {
    local last
    for last in "$@"; do :; done
    if $mixed; then
        case " $* " in
            *' apt-cache '*' policy php8.2-cli:amd64 '*)
                printf 'php8.2-cli:\n  Installed: 8.2.34-1~deb12u1\n  Candidate: %s\n  Version table:\n     %s 500\n        500 https://deb.debian.org/debian bookworm/main amd64 Packages\n' "$fixture_native_candidate" "$fixture_native_candidate"; return ;;
            *' apt-cache '*' show php8.2-cli:amd64='*)
                printf 'Package: php8.2-cli\nVersion: %s\nArchitecture: amd64\nSource: php8.2\n' "$fixture_native_candidate"; return ;;
        esac
    fi
    case " $* " in
        *' --audit '*|*' --get-selections '*) return 0 ;;
        *' apt-config dump '*) printf '%s\n' "$fixture_config" ;;
        *' apt-cache '*' policy '*)
            if [ "$last" = policy ]; then
                printf ' 500 %s %s/main %s Packages\n     release o=%s,n=%s,c=main,b=%s\n' "$fixture_uri" "$fixture_suite" "$fixture_index_arch" "$fixture_origin" "$fixture_suite" "$fixture_index_arch"
            else
                printf '%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n     %s 500\n' "$fixture_name" "$fixture_old" "$fixture_candidate" "$fixture_candidate"
                if ! $no_repo; then printf '        500 %s %s/main %s Packages\n' "$fixture_uri" "$fixture_suite" "$fixture_index_arch"; fi
                if $extra_repo; then printf '        500 %s bookworm/main amd64 Packages\n' "$extra_uri"; fi
            fi ;;
        *' apt-cache '*' show '*) printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSource: %s\n' "$fixture_name" "$fixture_candidate" "$fixture_proposed_arch" "$fixture_source" ;;
        *' update '*) printf 'REFRESH\n' >> "$P2S_WORK/calls" ;;
        *' -s '*)
            printf 'SIMULATE:%s\n' "$*" >> "$P2S_WORK/calls"
''' + (simulation or r'''            printf 'Inst %s [%s] (%s repo [%s])
' "$fixture_name" "$fixture_old" "$fixture_candidate" "$fixture_arch"
            if $mixed && [ "$fixture_native_candidate" != 8.2.34-1~deb12u1 ]; then
                printf 'Inst php8.2-cli [8.2.34-1~deb12u1] (%s Debian [amd64])\n' "$fixture_native_candidate"
            fi''') + r''' ;;
        *' install '*) printf 'INSTALL:%s\n' "$*" >> "$P2S_WORK/calls" ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_package_deb_update
printf 'RC=%s|ATTEMPTED=%s\n' "$?" "${P2S_TRANSACTION_ATTEMPTED:-false}"
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
'''

    def test_same_sury_branch_uses_exact_versions_and_freezes_other_packages(self):
        out = self.shell(self.fixture(), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        self.assertIn('php7.4-cli:amd64=1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428', install)
        self.assertIn('php8.2-cli:amd64=8.2.34-1~deb12u1', install)
        self.assertIn('php-cli=2:8.4+101+0~20261021.78+debian12~1.gbp53f25f', install)
        self.assertIn('APT::Get::AllowUnauthenticated=false', install)
        simulate = next(line for line in out.splitlines() if line.startswith('SIMULATE:'))
        self.assertEqual(simulate.split('install --only-upgrade ', 1)[1],
                         install.split('install --only-upgrade ', 1)[1])

    def test_no_newer_candidate_never_runs_an_empty_apt_install(self):
        out = self.shell(self.fixture('old=$candidate'), isolated_sources=True)
        self.assertIn('RC=1|ATTEMPTED=false', out)
        self.assertIn('no_candidate|', out)
        self.assertNotIn('SIMULATE:', out)
        self.assertNotIn('INSTALL:', out)

    def test_mixed_native_and_sury_engines_are_both_updated_without_provider_switch(self):
        out = self.shell(self.fixture('fixture_native_candidate=8.2.35-1~deb12u1'), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        self.assertIn('php8.2-cli:amd64=8.2.35-1~deb12u1', install)
        self.assertIn('php7.4-cli:amd64=1:7.4.33-31+', install)

    def test_unversioned_apache_selector_cannot_block_an_engine_update(self):
        fixture = self.fixture().replace('p2s_package_deb_update\n',
                                        'printf "%s\\n" "libapache2-mod-php|2:8.2+93|all|Debian" >> "$P2S_WORK/packages"\np2s_package_deb_update\n')
        out = self.shell(fixture, isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        self.assertIn('libapache2-mod-php=2:8.2+93', install)

    def test_already_current_package_can_still_restart_stale_workers(self):
        out = self.shell(self.fixture('old=$candidate; P2S_RESTART_PENDING=true'), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=false', out)
        self.assertNotIn('SIMULATE:', out)
        self.assertNotIn('INSTALL:', out)

    def test_candidate_failures_never_install(self):
        scenarios = {
            'different_provider': 'uri=https://deb.debian.org/debian; origin=Debian',
            'mixed_identical_version_origins': 'extra_repo=true',
            'mixed_local_repository': 'extra_repo=true; extra_uri=file:/local/repo',
            'mixed_copy_repository': 'extra_repo=true; extra_uri=copy:/local/repo',
            'mixed_cdrom_repository': 'extra_repo=true; extra_uri=cdrom:/local/repo',
            'wrong_release_origin': 'origin=Unrelated',
            'wrong_suite': 'suite=trixie',
            'wrong_architecture': 'proposed_arch=i386',
            'wrong_source': 'source=php8.2',
            'missing_installed_source': 'selected_source=unknown',
            'unverified_backport': "candidate='1:7.4.33-32+0~20261022.122+debian12~1.gbpabcdef'",
            'no_repository_evidence': 'no_repo=true',
            'downgrade': "old='1:7.4.33-32+0~20261022.122+debian12~1.gbpabcdef'",
            'branch_change': "candidate='1:8.2.35-1+0~20261021.94+debian12~1.gbp8bff78'",
        }
        for scenario, changes in scenarios.items():
            with self.subTest(scenario=scenario):
                out = self.shell(self.fixture(changes), isolated_sources=True)
                self.assertIn('RC=1|ATTEMPTED=false', out)
                self.assertNotIn('INSTALL:', out)
                self.assertIn('dss:manifest:blocker:', out)
                self.assertIn('candidate_' if scenario != 'downgrade' else 'package_downgrade', out)

    def test_existing_ubuntu_php_ppa_has_its_own_origin_and_versions(self):
        changes = '''P2S_DISTRO=ubuntu; P2S_RELEASE=22.04; suite=jammy
uri=https://ppa.launchpadcontent.net/ondrej/php/ubuntu; origin=LP-PPA-ondrej-php
old=1:7.4.33-30+ubuntu22.04.1+deb.sury.org+1
candidate=1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1'''
        out = self.shell(self.fixture(changes), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        out = self.shell(self.fixture(changes+'\norigin=LP-PPA-ondrej-apache2'), isolated_sources=True)
        self.assertIn('candidate_provider', out)
        self.assertNotIn('INSTALL:', out)

    def test_debian_bookworm_sury_candidate_cannot_be_installed_on_ubuntu_jammy(self):
        out = self.shell(self.fixture('P2S_DISTRO=ubuntu; P2S_RELEASE=22.04; mixed=false'),
                         isolated_sources=True)
        self.assertIn('candidate_provider', out)
        self.assertIn('RC=1|ATTEMPTED=false', out)
        self.assertNotIn('INSTALL:', out)

    def test_versioned_pecl_extensions_are_not_php_engine_versions(self):
        changes = '''name=php7.4-imagick; source=php-imagick; selected_source=php-imagick
old=3.8.1-1+0~20261010.1+debian12~1.gbpabcdef
candidate=3.8.1-2+0~20261021.2+debian12~1.gbpabcdef'''
        out = self.shell(self.fixture(changes), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)

    def test_shared_helpers_and_older_extension_selectors_are_retained(self):
        fixture = self.fixture().replace('p2s_package_deb_update\n', r'''
printf '%s\n' 'php-common|2:96+0~20250402.56+debian12~1.gbp84a5b7|all|Debian' 'php-imap|2:8.3+95|all|Debian' 'php-pear|1:1.10.16|all|Debian' >> "$P2S_WORK/packages"
p2s_package_deb_update
''')
        out = self.shell(fixture, isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        self.assertIn('php-common=2:96+0~20250402.56+debian12~1.gbp84a5b7', install)
        self.assertIn('php-imap=2:8.3+95', install)
        self.assertIn('php-pear=1:1.10.16', install)

    def test_existing_native_update_path_still_accepts_native_candidates(self):
        changes='''mixed=false; name=php8.2-cli; source=php8.2
old=8.2.34-1~deb12u1; candidate=8.2.35-1~deb12u1
uri=https://deb.debian.org/debian; origin=Debian'''
        out = self.shell(self.fixture(changes), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        self.assertIn('php8.2-cli:amd64=8.2.35-1~deb12u1', out)

    def test_non_sury_installed_package_cannot_receive_sury_candidate(self):
        out = self.shell(self.fixture('old=7.4.33-1; selector=2:8.4-1'), isolated_sources=True)
        self.assertIn('replace non-Sury package', out)
        self.assertNotIn('INSTALL:', out)

    def test_transaction_cannot_add_or_change_non_sury_packages(self):
        for plan in ('Inst php8.2-cli [old] (8.2.35)', 'Inst new-library (1.0)',
                     'Remv php7.4-cli [old]', 'Inst php7.4-cli [old] (1:7.4.33-other)'):
            with self.subTest(plan=plan):
                out = self.shell(self.fixture(simulation="printf '%s\\n' " + shlex.quote(plan)), isolated_sources=True)
                self.assertIn('RC=1|ATTEMPTED=false', out)
                self.assertNotIn('INSTALL:', out)

    def test_panel_sury_combination_blocks_before_vendor_updates(self):
        for panel in ('cpanel', 'plesk'):
            out = self.shell('''
P2S_BACKEND=deb; P2S_PANEL=''' + panel + '''
printf '%s\\n' 'php7.4-cli|1:7.4.33-30+0~20261010.120+debian12~1.gbpabcdef|amd64|Debian' > "$P2S_WORK/packages"
p2s_fix_preflight
printf 'RC=%s\\n' "$?"
''')
            self.assertIn('RC=1', out)
            self.assertIn('before any panel or PHP updates', out)

    def test_installed_backport_uses_collected_source_metadata(self):
        for source_version, expected in (('', 'N'), (' (unreviewed-source)', '?')):
            out = self.shell('''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
fixture_version=1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428
printf 'php7.4-cli|%s|amd64|Debian PHP Maintainers\\n' "$fixture_version" > "$P2S_WORK/packages"
p2s_package_policy_collect() { :; }
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() {
    case " $* " in
        *' -W '*) printf 'php7.4-cli|%s|amd64|php7.4''' + source_version + '''\\n' "$fixture_version" ;;
        *' -L '*) return 0 ;;
        *) return 97 ;;
    esac
}
p2s_package_sources_collect
p2s_package_inventory_assess
cat "$P2S_WORK/package-states"
''', isolated_paths=True, isolated_sources=True)
            self.assertIn('php7.4-cli|' + expected, out.splitlines())

    def test_insecure_apt_settings_block_before_refresh(self):
        for changes in (
                "config='APT::Get::AllowUnauthenticated \"true\";'",
                "config='Acquire::https::Verify-Peer \"false\";'",
                "config='Acquire::AllowWeakRepositories \"true\";'",
                "config='Acquire::AllowWeakRepositories \"on\";'",
                "config='Acquire::https::Verify-Host \"disable\";'",
                "config='Dir::Etc::sourcelist \"custom.list\";'",
                "mkdir -p \"$P2S_WORK/etc/apt\"; printf '%s\\n' 'deb [trusted=yes] https://packages.sury.org/php bookworm main' > \"$P2S_WORK/etc/apt/sources.list\"",
                "mkdir -p \"$P2S_WORK/etc/apt/sources.list.d\"; printf '%s\\n' 'Types: deb' 'Trusted: yes' > \"$P2S_WORK/etc/apt/sources.list.d/php.sources\"",
                "mkdir -p \"$P2S_WORK/etc/apt/sources.list.d\"; printf '%s\\n' 'Types: deb' 'Trusted:' ' yes' > \"$P2S_WORK/etc/apt/sources.list.d/php.sources\"",
                "mkdir -p \"$P2S_WORK/etc/apt/sources.list.d\"; printf 'Types: deb\\r\\nTrusted: enable\\r\\n' > \"$P2S_WORK/etc/apt/sources.list.d/php.sources\""):
            with self.subTest(changes=changes):
                out = self.shell(self.fixture(changes), isolated_sources=True)
                self.assertIn('source_authentication', out)
                self.assertNotIn('REFRESH', out)
                self.assertNotIn('INSTALL:', out)

    def test_exact_reviewed_backports_require_matching_source_suite_and_architecture(self):
        debian = [
            ('5.6','5.6.40-105+0~20261022.135','37a17e'),
            ('7.0','7.0.33-93+0~20261022.119','952195'),
            ('7.1','7.1.33-81+0~20261022.128','a88ccf'),
            ('7.2','7.2.34-66+0~20261021.122','e0bcd4'),
            ('7.3','7.3.33-35+0~20261021.144','ecf76f'),
            ('7.4','1:7.4.33-31+0~20261021.121','e9c428'),
            ('8.0','1:8.0.30-25+0~20261021.88','abebea'),
            ('8.1','8.1.34-9+0~20261021.82','4e430a')]
        for branch, revision, checksum in debian:
            for distro, releases in [('debian', ('11', '12', '13')), ('ubuntu', ('22.04', '24.04'))]:
                for release in releases:
                    version = f'{revision}+debian{release}~1.gbp{checksum}'
                    if distro == 'ubuntu':
                        base = revision.split('+0~')[0]
                        base = {'7.0':'7.0.33-92','7.1':'7.1.33-80'}.get(branch, base)
                        version = f'{base}+ubuntu{release}.1+deb.sury.org+1'
                    setup = f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n'
                    args = [f'php{branch}-cli', version, 'Debian PHP Maintainers', 'amd64', f'php{branch}', version]
                    with self.subTest(branch=branch, distro=distro, release=release):
                        out = self.shell(setup + 'p2s_version_package_state ' + ' '.join(map(shlex.quote,args)))
                        self.assertEqual(out.strip(), 'N')
                        for index, bad in [(1, version+'+unreviewed'),(3,'i386'),(4,'other-source'),(5,'other-version')]:
                            invalid = args.copy(); invalid[index] = bad
                            out = self.shell(setup+'p2s_version_package_state '+' '.join(map(shlex.quote,invalid)))
                            self.assertEqual(out.strip(), '?')

    def installed_summary(self, version, names=('php7.4-cli',), source='php7.4', distro='debian', release='12'):
        records = '\n'.join(f'{name}|{version}|amd64|Debian PHP Maintainers' for name in names)
        sources = '\n'.join(f'{name}|{version}|amd64|{source}|{version}|source_field' for name in names)
        return self.shell(f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n'
                          + 'printf "%s\\n" ' + shlex.quote(records) + ' > "$P2S_WORK/packages"\n'
                          + 'printf "%s\\n" ' + shlex.quote(sources) + r''' > "$P2S_WORK/deb-source-records"
p2s_package_backport_evidence_collect() { :; }
p2s_command_run() { return 0; }
p2s_package_inventory_assess
p2s_summary_print_versions
cat "$P2S_WORK/package-states"
''')

    def test_fixed_php74_names_packages_and_the_backported_build(self):
        version = '1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428'
        names = ('php7.4-cli', 'php7.4-common', 'libapache2-mod-php7.4')
        out = self.installed_summary(version, names)
        rows = [row for row in out.splitlines() if row.startswith('dss:info: PHP ')]
        self.assertEqual(len(rows), 1)
        self.assertIn('PHP 7.4.33', rows[0])
        self.assertIn('fixes verified for both PHP2Shell vulnerabilities', rows[0])
        self.assertIn('Installed package build: ' + version, rows[0])
        for name in names:
            self.assertIn(name, rows[0])
            self.assertIn(name + '|N', out.splitlines())

    def test_sury_comparison_reports_full_version_order_without_clearing_unreviewed_builds(self):
        for version, comparison in [
                ('1:7.4.33-30+0~20261010.120+debian12~1.gbpabcdef', 'older'),
                ('7.4.33-999+0~20261025.122+debian12~1.gbpabcdef', 'older'),
                ('1:7.4.33-32+0~20261025.122+debian12~1.gbpabcdef', 'newer')]:
            with self.subTest(version=version):
                out = self.installed_summary(version)
                self.assertIn('php7.4-cli|?', out.splitlines())
                self.assertIn('Installed package build: ' + version, out)
                self.assertIn('is ' + comparison + ' than this check\'s verified fixed build:', out)
                self.assertIn('reviewed_fixed=1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428|comparison=' + comparison, out)

    def test_equal_sury_revision_with_unverified_identity_explains_the_actual_gap(self):
        version = '1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428'
        out = self.installed_summary(version, source='unreviewed-source')
        self.assertIn('php7.4-cli|?', out.splitlines())
        self.assertIn('compares equal to the verified fixed Sury build', out)
        self.assertIn('exact build and source identity did not match', out)
        # A zero epoch compares equal, but is not an exact reviewed package identity.
        out = self.installed_summary('0:8.1.34-9+0~20261021.82+debian12~1.gbp4e430a',
                                     names=('php8.1-cli',), source='php8.1')
        self.assertIn('|comparison=equal', out)
        self.assertNotIn('tool is unavailable', out)

    def test_different_sury_builds_with_same_php_version_keep_separate_conclusions(self):
        records = [
            '7.4.33|?|command line||Sury/ondrej PHP|1:7.4.33-30|Y|package|sury_build_older|php7.4-cli|1:7.4.33-31',
            '7.4.33|?|Apache module||Sury/ondrej PHP|1:7.4.33-32|Y|package|sury_build_newer|libapache2-mod-php7.4|1:7.4.33-31']
        out = self.shell('printf "%s\\n" ' + ' '.join(map(shlex.quote, records))
                         + ' > "$P2S_WORK/summary-versions"\np2s_summary_print_versions\n')
        rows = [row for row in out.splitlines() if row.startswith('dss:warn: PHP ')]
        self.assertEqual(len(rows), 2)
        self.assertTrue(any('php7.4-cli' in row and 'is older than' in row and 'libapache2' not in row for row in rows))
        self.assertTrue(any('libapache2-mod-php7.4' in row and 'is newer than' in row and 'php7.4-cli' not in row for row in rows))

    def test_bullseye_recipe_requires_existing_sury_engines(self):
        sury = '1:7.4.33-30+0~20261010.120+debian11~1.gbpabcdef'
        for packages, allowed in [
                (f'php7.4-cli|{sury}|amd64|Sury\nphp-common|2:76|all|Debian', True),
                (f'php7.4-cli|{sury}|amd64|Sury\nphp-cli|2:7.4|all|Debian', True),
                (f'php7.4-cli|{sury}|amd64|Sury\nphp7.4|{sury}|all|Sury', True),
                (f'php7.4-cli|{sury}|amd64|Sury\nphp7.4-common|7.4.33-1|amd64|Debian', False),
                ('php7.4-cli|7.4.33-1|amd64|Debian', False),
                (f'php7.4-cli|{sury}|i386|Sury', False),
                ('php-common|2:76|all|Debian', False)]:
            with self.subTest(packages=packages):
                out = self.shell('P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_MAJOR=11; P2S_RELEASE=11\n'
                                 + 'printf "%s\\n" ' + shlex.quote(packages) + ' > "$P2S_WORK/packages"\n'
                                 + 'p2s_fix_check_distro_recipe\nprintf "BLOCKED=%s\\n" "$P2S_BLOCKED"')
                self.assertIn('BLOCKED=' + str(not allowed).lower(), out)

    def test_native_bullseye_recipe_needs_both_migration_opt_ins(self):
        for disruptive, migration, allowed in [(False, False, False), (True, False, False),
                                               (False, True, False), (True, True, True)]:
            with self.subTest(disruptive=disruptive, migration=migration):
                out = self.shell(f'P2S_DISRUPTIVE={str(disruptive).lower()}; P2S_ALLOW_SURY_MIGRATION={str(migration).lower()}\n'
                                 + 'P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_MAJOR=11; P2S_RELEASE=11\n'
                                 + 'printf "%s\\n" "php7.4-cli|7.4.33-1|amd64|Debian" > "$P2S_WORK/packages"\n'
                                 + 'p2s_fix_check_distro_recipe\nprintf "BLOCKED=%s\\n" "$P2S_BLOCKED"')
                self.assertIn('BLOCKED=' + str(not allowed).lower(), out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
