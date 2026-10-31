"""Explicit standard repository repairs, with isolated sources and mocked downloads."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class RepositoryRepairTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def fixture(self, body='', recipe='native-security-source'):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
P2S_MODE=fix; P2S_DISRUPTIVE=true
P2S_REPOSITORY_REPAIR=''' + recipe + r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d" "$P2S_WORK/usr/share/keyrings"
printf 'archive key\n' > "$P2S_WORK/usr/share/keyrings/debian-archive-keyring.gpg"
printf 'old Sury key\n' > "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg"
printf 'deb https://deb.debian.org/debian bookworm main\n' > "$P2S_WORK/etc/apt/sources.list"
printf 'deb [signed-by=%s] https://packages.sury.org/php/ bookworm main\n' "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg" > "$P2S_WORK/etc/apt/sources.list.d/php.list"
wrong_key=false; download_fail=false; owner_fail=false; mixed_suite=false
p2s_command_exists() { case "$1" in gpg|curl) return 0;; *) return 1;; esac; }
p2s_package_deb_sury_trust_preflight() { return 0; }
p2s_command_run() {
    local last part output=false
    for last in "$@"; do :; done
    case "$2" in
        dpkg-query)
            if $owner_fail; then printf 'random-package: %s\n' "$last"; return 0; fi
            case "$last" in
                *debsuryorg*) printf 'debsuryorg-archive-keyring: %s\n' "$last" ;;
                *debian-archive*) printf 'debian-archive-keyring: %s\n' "$last" ;;
                *ubuntu-archive*) printf 'ubuntu-keyring: %s\n' "$last" ;;
            esac ;;
        apt-cache)
            printf '500 https://deb.debian.org/debian bookworm/main amd64 Packages\n release o=Debian,n=bookworm,c=main,b=amd64\n'
            if $mixed_suite; then printf '500 https://deb.debian.org/debian buster/main amd64 Packages\n release o=Debian,n=buster,c=main,b=amd64\n'; fi ;;
        curl)
            printf 'DOWNLOAD\n' >> "$P2S_WORK/calls"
            if $download_fail; then return 1; fi
            for part in "$@"; do
                if $output; then printf 'fixture key\n' > "$part"; return 0; fi
                [ "$part" != --output ] || output=true
            done ;;
        gpg)
            case " $* " in
                *' --show-keys '*)
                    if $wrong_key; then printf 'pub:::::::::\nfpr:::::::::WRONG:\n'; else printf 'pub:::::::::\nfpr:::::::::15058500A0235D97F5D10063B188E2B695BD4743:\n'; fi ;;
                *' --dearmor '*) printf 'new verified key\n' ;;
                *) return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED_REPAIR_COMMAND\n'; return 97 ;;
    esac
}
''' + body

    def source_fixture(self, definition, filename='extra.list', body=''):
        # Expand only the synthetic root placeholder; never source a repository definition.
        return self.fixture("definition=" + shlex.quote(definition) + r'''
definition=${definition//FIXTURE_ROOT/$P2S_WORK}
printf '%s\n' "$definition" > "$P2S_WORK/etc/apt/sources.list.d/''' + filename + r'''"
''' + body)

    def test_installed_sury_requires_an_active_matching_binary_source(self):
        cases = [
            ('', 'php.list', False),
            ('#deb https://packages.sury.org/php/ bookworm main', 'php.list', False),
            ('deb-src https://packages.sury.org/php/ bookworm main', 'php.list', False),
            ('deb https://packages.sury.org/php/ bullseye main', 'php.list', False),
            ('deb [arch=arm64] https://packages.sury.org/php/ bookworm main', 'php.list', False),
            ('deb [arch-=amd64] https://packages.sury.org/php/ bookworm main', 'php.list', False),
            ('deb https://packages.sury.org/php/ bookworm main', 'php.list', True),
            ('deb [arch=arm64 arch+=amd64] https://packages.sury.org/php/ bookworm main', 'php.list', True),
            ('Types: deb\nURIs: https://packages.sury.org/php/\nSuites: bookworm\nEnabled: no', 'php.sources', False),
            ('Types: deb-src\nURIs: https://packages.sury.org/php/\nSuites: bookworm', 'php.sources', False),
            ('Types: deb\nURIs: https://packages.sury.org/php/\nSuites: bookworm\nArchitectures: arm64', 'php.sources', False),
            ('Types: deb deb-src\nURIs: https://packages.sury.org/php/\nSuites: bookworm\nArchitectures: amd64 arm64', 'php.sources', True),
            ('Types: deb\tdeb-src\nURIs: https://packages.sury.org/php/\nSuites: bookworm\nArchitectures: arm64\tamd64', 'php.sources', True),
        ]
        for definition, filename, active in cases:
            with self.subTest(definition=definition):
                out = self.shell(self.fixture(r'''
rm "$P2S_WORK/etc/apt/sources.list.d/php.list"
printf '%s\n' 'php7.4-cli|7.4.33-1+deb.sury.org+1|amd64|Debian PHP Maintainers' 'php7.4-common|7.4.33-1+deb.sury.org+1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
''' + "printf '%s\\n' " + shlex.quote(definition) + ' > "$P2S_WORK/etc/apt/sources.list.d/' + filename + '"\n' + r'''
p2s_repository_sury_installed_source_report
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
'''), isolated_sources=True, isolated_paths=True)
                self.assertEqual(out.count('Automatic Sury/ondrej updates need an active matching source'), 0 if active else 1)
                self.assertIn('BLOCKED=false|UNKNOWN=false', out)

    def test_missing_sury_source_on_vendor_panel_requires_mixed_source_review(self):
        out = self.shell(self.fixture(r'''
P2S_PANEL=cpanel
rm "$P2S_WORK/etc/apt/sources.list.d/php.list"
printf '%s\n' 'php7.4-cli|7.4.33-1+deb.sury.org+1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
p2s_repository_sury_installed_source_report
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('no active matching Sury/ondrej source', out)
        self.assertIn('Review the mixed package sources with the panel administrator', out)
        self.assertNotIn('Automatic Sury/ondrej updates need an active matching source', out)

    def test_ondrej_matching_source_and_native_packages_do_not_warn(self):
        out = self.shell(self.fixture(r'''
P2S_DISTRO=ubuntu; P2S_RELEASE=24.04
printf '%s\n' 'deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main' > "$P2S_WORK/etc/apt/sources.list.d/php.list"
printf '%s\n' 'php7.4-cli|7.4.33-1+0~20261001.1+debian12~1.gbp123abc|amd64|PHP Maintainers' > "$P2S_WORK/packages"
p2s_repository_sury_installed_source_report
rm "$P2S_WORK/etc/apt/sources.list.d/php.list"
printf '%s\n' 'php8.2-cli|8.2.32-1~deb12u1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
p2s_repository_sury_installed_source_report
'''), isolated_sources=True, isolated_paths=True)
        self.assertNotIn('installed_packages_without_matching_active_source', out)
        self.assertNotIn('Automatic Sury/ondrej updates need an active matching source', out)

    def test_focal_ppa_is_recognised_for_selectors_and_engine_packages(self):
        for name, arch in [('libapache2-mod-php', 'all'), ('libapache2-mod-php7.4', 'amd64')]:
            for definition, active in [
                    ('deb http://ppa.launchpad.net/ondrej/php/ubuntu focal main', True),
                    ('# deb http://ppa.launchpad.net/ondrej/php/ubuntu focal main', False),
                    ('deb http://ppa.launchpad.net/ondrej/php/ubuntu jammy main', False),
                    ('Types: deb\nURIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu\nSuites: focal\nEnabled: no', False)]:
                with self.subTest(name=name, definition=definition):
                    filename = 'ondrej.sources' if definition.startswith('Types:') else 'ondrej.list'
                    out = self.shell(self.fixture('P2S_DISTRO=ubuntu; P2S_RELEASE=20.04\n'
                        + 'rm "$P2S_WORK/etc/apt/sources.list.d/php.list"\n'
                        + 'printf "%s\\n" ' + shlex.quote(definition)
                        + ' > "$P2S_WORK/etc/apt/sources.list.d/' + filename + '"\n'
                        + 'printf "%s\\n" ' + shlex.quote(f'{name}|1:7.4.33-15+ubuntu20.04.1+deb.sury.org+1|{arch}|PHP Maintainers')
                        + ' > "$P2S_WORK/packages"\np2s_repository_sury_installed_source_report\n'),
                        isolated_sources=True, isolated_paths=True)
                    self.assertEqual('installed_packages_without_matching_active_source' in out, not active)

    def test_debian_sury_bookworm_on_ubuntu_names_the_distribution_suite_and_file(self):
        definition = '''Types: deb deb-src
URIs: https://packages.sury.org/php
Suites: bookworm
Components: main
Architectures: amd64
Signed-By: FIXTURE_ROOT/var/lib/extrepo/keys/sury.asc
Enabled: yes
'''
        out = self.shell(self.source_fixture(definition, 'extrepo_sury.sources', r'''
P2S_DISTRO=ubuntu; P2S_RELEASE=22.04
rm "$P2S_WORK/etc/apt/sources.list.d/php.list"
p2s_repository_inventory_collect
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
'''), isolated_paths=True, isolated_sources=True)
        self.assertIn('PHP repository mismatch in ', out)
        self.assertIn('/extrepo_sury.sources: the source supplies Debian packages for suite \'bookworm\'', out)
        self.assertIn('this server runs ubuntu 22.04', out)
        self.assertIn('Ubuntu PHP packages use the ondrej/php PPA for jammy', out)
        self.assertIn('Use apt-cache policy PACKAGE to inspect installed and candidate versions and their sources', out)
        self.assertNotIn('repository change alone', out)
        self.assertIn('configured=Debian bookworm|host=ubuntu 22.04|expected_suite=jammy', out)
        self.assertNotIn('extrepo update sury', out)
        self.assertNotIn('PHP packages built for another distribution are installed', out)
        self.assertIn('BLOCKED=false|UNKNOWN=false', out)

    def test_ubuntu_php_ppa_on_debian_is_reported_but_matching_ppa_is_not(self):
        for distro, release, suite, mismatch in [('debian', '12', 'jammy', True),
                                                ('debian', '12', 'bookworm', True),
                                                ('ubuntu', '22.04', 'jammy', False)]:
            definition = f'deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu {suite} main'
            with self.subTest(distro=distro, suite=suite):
                out = self.shell(self.source_fixture(definition, 'php.list',
                                 f'P2S_DISTRO={distro}; P2S_RELEASE={release}\np2s_repository_inventory_collect\n'),
                                 isolated_paths=True, isolated_sources=True)
                self.assertEqual('PHP repository mismatch' in out, mismatch)
                if mismatch:
                    self.assertIn(f"source supplies Ubuntu packages for suite '{suite}'", out)
                    self.assertIn('Debian PHP packages use packages.sury.org/php for bookworm', out)

    def test_inactive_or_commented_cross_distribution_source_does_not_get_active_warning(self):
        definitions = [('Types: deb\nURIs: https://packages.sury.org/php\nSuites: bookworm\nEnabled: no', 'php.sources'),
                       ('# deb https://packages.sury.org/php bookworm main', 'php.list')]
        for definition, filename in definitions:
            out = self.shell(self.source_fixture(definition, filename, r'''
P2S_DISTRO=ubuntu; P2S_RELEASE=22.04
rm -f "$P2S_WORK/etc/apt/sources.list.d/php.list"
''' if filename != 'php.list' else 'P2S_DISTRO=ubuntu; P2S_RELEASE=22.04\n') +
                             '\np2s_repository_inventory_collect\n', isolated_paths=True, isolated_sources=True)
            self.assertNotIn('PHP repository mismatch', out)

    def test_legacy_sury_list_and_deb822_have_manual_repair_guidance(self):
        cases = [
            ('deb https://packages.sury.org/php/ bookworm main', 'legacy.list'),
            ('deb [signed-by=/etc/apt/trusted.gpg.d/php.gpg] http://packages.sury.org/php/ bookworm main', 'legacy.list'),
            ('Types: deb\nURIs: https://packages.sury.org/php/\nSuites: bookworm\nComponents: main', 'legacy.sources'),
        ]
        for definition, filename in cases:
            with self.subTest(definition=definition):
                out = self.shell(self.source_fixture(definition, filename, r'''
p2s_repository_inventory_collect
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
[ ! -e "$P2S_WORK/calls" ] && printf 'NO_NETWORK\n'
'''), isolated_sources=True, isolated_paths=True)
                self.assertIn('|sury|legacy_or_custom|enabled=yes|suite=matching', out)
                self.assertIn('debsuryorg-archive-keyring package', out)
                self.assertIn('instead of adding a duplicate', out)
                self.assertIn('BLOCKED=false|UNKNOWN=false', out)
                self.assertIn('NO_NETWORK', out)

    def test_current_sources_and_comments_do_not_get_legacy_advice(self):
        definition = '''Types: deb deb-src
URIs: https://packages.sury.org/php/
# Comment inside a stanza must not split it.
Suites: bookworm
Signed-By: FIXTURE_ROOT/usr/share/keyrings/debsuryorg-archive-keyring.gpg
Components: main

Types: deb
URIs: https://download.virtualmin.com/virtualmin/7/gpl/apt
Suites: virtualmin
Components: main
# deb https://packages.sury.org/php/ oldsuite main
'''
        out = self.shell(self.source_fixture(definition, 'current.sources', r'''
p2s_repository_inventory_collect
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('|sury|standard|enabled=yes|suite=matching', out)
        self.assertIn('|virtualmin|current|enabled=yes|', out)
        self.assertNotIn('Legacy or custom Sury', out)
        self.assertNotIn('Legacy Virtualmin repository', out)

    def test_extrepo_layout_is_recognised_but_package_keyring_repair_is_refused(self):
        for filename, key in [('extrepo_sury.sources', 'FIXTURE_ROOT/var/lib/extrepo/keys/sury.asc'),
                              ('renamed.sources', 'FIXTURE_ROOT/var/lib/extrepo/keys/sury.asc'),
                              ('extrepo_sury.sources', 'FIXTURE_ROOT/usr/share/keyrings/custom.gpg')]:
            with self.subTest(filename=filename, key=key):
                definition = 'Types: deb\nURIs: https://packages.sury.org/php\nSuites: bookworm\nComponents: main\nSigned-By: ' + key
                out = self.shell(self.source_fixture(definition, filename, r'''
p2s_repository_inventory_collect
p2s_repository_repair_assess sury-key
printf 'RC=%s|REASON=%s\n' "$?" "$P2S_REPOSITORY_REPAIR_REASON"
P2S_REPOSITORY_REPAIR=sury-key
p2s_disruptive_repository_apply_recipe
printf 'APPLY=%s\n' "$?"
cat "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg"
[ ! -e "$P2S_WORK/calls" ] && printf 'NO_NETWORK\n'
'''), isolated_sources=True, isolated_paths=True)
                self.assertIn('extrepo-managed layout', out)
                self.assertIn('manual_review=extrepo update sury|not_executed', out)
                self.assertIn('RC=1|REASON=', out)
                self.assertIn('package-owned keyring repair does not apply', out)
                self.assertIn('APPLY=1', out)
                self.assertIn('old Sury key', out)
                self.assertIn('NO_NETWORK', out)
                self.assertNotIn('new verified key', out)
                self.assertNotIn('Legacy or custom Sury', out)

    def test_disabled_and_multistanza_sources_do_not_recommend_activation(self):
        definition = '''Types: deb
URIs: https://packages.sury.org/php
Suites: bookworm
Signed-By:
 FIXTURE_ROOT/var/lib/extrepo/keys/sury.asc
Enabled: no

Types: deb
URIs:
 https://software.virtualmin.com/gpl/debian/
Suites: virtualmin
Enabled: no
'''
        out = self.shell(self.source_fixture(definition, 'extrepo_sury.sources', r'''
p2s_repository_inventory_collect
p2s_repository_sury_source_present
printf 'PRESENT=%s\n' "$?"
p2s_repository_repair_assess sury-key
printf 'REPAIR=%s|REASON=%s\n' "$?" "$P2S_REPOSITORY_REPAIR_REASON"
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('|sury|extrepo|enabled=no|', out)
        self.assertIn('|virtualmin|legacy|enabled=no|', out)
        self.assertRegex(out, r'repository_definition:beforefix\|[^\n]*\|uris\|\[repository host=software[.]virtualmin[.]com; path redacted\]')
        self.assertIn('review_intended_state_before_repair_or_activation', out)
        self.assertIn('PRESENT=0', out)
        self.assertIn('REPAIR=1', out)
        self.assertNotIn('manual_review=extrepo update sury', out)
        self.assertNotIn('Legacy Virtualmin repository', out)

    def test_wrong_suite_has_specific_advice_and_cannot_enable_key_repair(self):
        definition = 'deb [signed-by=FIXTURE_ROOT/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php bullseye main'
        out = self.shell(self.source_fixture(definition, body=r'''
p2s_repository_inventory_collect
p2s_repository_repair_assess sury-key
printf 'REPAIR=%s\n' "$?"
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('|sury|standard|enabled=yes|suite=different', out)
        self.assertIn('different_suite|manual_review=match_installed_OS', out)
        self.assertIn('REPAIR=1', out)

    def test_legacy_virtualmin_guidance_is_specific_and_does_not_expose_credentials(self):
        definition = 'deb https://fixture-account:private-token@software.virtualmin.com/private-subscription/debian virtualmin main'
        out = self.shell(self.source_fixture(definition, body=r'''
p2s_repository_inventory_collect
[ ! -e "$P2S_WORK/calls" ] && printf 'NO_NETWORK\n'
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('Legacy Virtualmin repository', out)
        self.assertIn('virtualmin configure-repos', out)
        self.assertIn('virtualmin setup-repos', out)
        self.assertIn('it may be intentional', out)
        self.assertIn('Webmin module packaging', out)
        self.assertIn('NO_NETWORK', out)
        self.assertNotIn('private-token', out)
        self.assertNotIn('private-subscription', out)

    def test_virtualmin_rpm_disabled_state_survives_blank_lines(self):
        for enabled in ('0', '1'):
            with self.subTest(enabled=enabled):
                out = self.shell(self.fixture(r'''
mkdir -p "$P2S_WORK/etc/yum.repos.d"
printf '[virtualmin]\nbaseurl=https://software.virtualmin.com/vm/6/gpl/rhel/9/\n\nenabled=''' + enabled + r'''\n' > "$P2S_WORK/etc/yum.repos.d/virtualmin.repo"
p2s_repository_inventory_collect
'''), isolated_sources=True, isolated_paths=True)
                self.assertIn('|virtualmin|legacy|enabled=' + ('no' if enabled == '0' else 'yes'), out)
                self.assertEqual('Legacy Virtualmin repository' in out, enabled == '1')

    def test_similar_hosts_and_unrelated_extrepo_sources_are_not_misidentified(self):
        definition = '''deb https://packages.sury.org.attacker.invalid/php bookworm main
deb https://software.virtualmin.com.attacker.invalid/gpl/debian virtualmin main
deb https://packages.sury.org/apache2 bookworm main
# deb https://software.virtualmin.com/gpl/debian virtualmin main
'''
        out = self.shell(self.source_fixture(definition, 'extrepo_sury_apache2.list', r'''
p2s_repository_maintenance_report "$P2S_WORK/etc/apt/sources.list.d/extrepo_sury_apache2.list"
'''), isolated_sources=True, isolated_paths=True)
        self.assertNotIn('repository_layout:', out)
        self.assertNotIn('repository_guidance:', out)

    def test_native_missing_security_source_is_added_without_changing_main(self):
        out = self.shell(self.fixture(r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
cat "$P2S_WORK/etc/apt/sources.list.d/dephp2shell-native-security.list"
cat "$P2S_WORK/etc/apt/sources.list"
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('RC=0', out)
        self.assertIn('https://security.debian.org/debian-security bookworm-security main', out)
        self.assertIn('deb https://deb.debian.org/debian bookworm main', out)

    def test_assessment_is_observational_and_does_not_need_consent(self):
        out = self.shell(self.fixture(r'''
P2S_MODE=check; P2S_DISRUPTIVE=false
p2s_repository_repair_assess native-security-source
printf 'RC=%s\n' "$?"
[ ! -e "$P2S_WORK/etc/apt/sources.list.d/dephp2shell-native-security.list" ] && printf 'UNCHANGED\n'
[ ! -e "$P2S_WORK/calls" ] && printf 'NO_NETWORK\n'
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('RC=0', out)
        self.assertIn('UNCHANGED', out)
        self.assertIn('NO_NETWORK', out)

    def test_existing_security_definition_including_disabled_deb822_is_not_duplicated(self):
        for definition in ('deb https://security.debian.org/debian-security bookworm-security main',
                           'Types: deb\nURIs: https://security.debian.org/debian-security\nSuites: bookworm-security\nEnabled: no'):
            out = self.shell(self.fixture("printf '%s\\n' " + shlex.quote(definition) + r''' > "$P2S_WORK/etc/apt/sources.list.d/security.sources"
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
[ ! -e "$P2S_WORK/etc/apt/sources.list.d/dephp2shell-native-security.list" ] && printf 'UNCHANGED\n'
'''), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)
            self.assertIn('UNCHANGED', out)

    def test_mixed_native_suite_and_unowned_archive_keyring_are_rejected(self):
        for change in ('mixed_suite=true', 'owner_fail=true'):
            out = self.shell(self.fixture(change + r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
'''), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)

    def test_dedicated_file_and_custom_keyring_are_not_overwritten(self):
        for change in ('printf "customer file\\n" > "$P2S_WORK/etc/apt/sources.list.d/dephp2shell-native-security.list"',
                       'rm "$P2S_WORK/usr/share/keyrings/debian-archive-keyring.gpg"; ln -s /dev/null "$P2S_WORK/usr/share/keyrings/debian-archive-keyring.gpg"'):
            out = self.shell(self.fixture(change + r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
'''), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)

    def test_key_publication_failure_preserves_original_and_backup(self):
        out = self.shell(self.fixture(r'''
mv() { return 1; }
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
cat "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg"
cat "$P2S_WORK/usr/share/keyrings"/dephp2shell-sury-backup.*
''', 'sury-key'), isolated_sources=True, isolated_paths=True)
        self.assertIn('RC=1', out)
        self.assertEqual(out.count('old Sury key'), 2)
        self.assertNotIn('new verified key', out)

    def test_exact_owned_source_is_idempotent(self):
        out = self.shell(self.fixture(r'''
p2s_disruptive_repository_apply_recipe || exit 1
p2s_repository_repair_assess native-security-source
printf 'ASSESS=%s|STATE=%s\n' "$?" "$P2S_REPOSITORY_REPAIR_STATE"
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('ASSESS=0|STATE=already_available', out)
        self.assertIn('native-security-source|unchanged|already_available', out)
        self.assertIn('RC=0', out)

    def test_current_native_sources_reject_foreign_suites_despite_stale_cache(self):
        for definition in ('deb https://deb.debian.org/debian buster main',
                           'deb [arch=amd64] https://deb.debian.org/debian stable main',
                           'Types: deb\nURIs: https://deb.debian.org/debian\nSuites: buster\nComponents: main',
                           'Types: deb\nURIs:\n https://deb.debian.org/debian\nSuites: buster\nComponents: main',
                           'Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm\n buster\nComponents: main'):
            out = self.shell(self.fixture("printf '%s\\n' " + shlex.quote(definition) + r''' > "$P2S_WORK/etc/apt/sources.list.d/foreign.sources"
p2s_repository_repair_assess native-security-source
printf 'RC=%s|REASON=%s\n' "$?" "$P2S_REPOSITORY_REPAIR_REASON"
'''), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)
            self.assertIn('foreign or unreviewed OS suite', out)

    def test_matching_deb822_main_source_remains_eligible(self):
        out = self.shell(self.fixture(r'''
printf 'Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm bookworm-updates\nComponents: main\n' > "$P2S_WORK/etc/apt/sources.list.d/native.sources"
p2s_repository_repair_assess native-security-source
printf 'RC=%s\n' "$?"
'''), isolated_sources=True, isolated_paths=True)
        self.assertIn('RC=0', out)

    def test_apply_requires_fix_and_disruptive_and_known_recipe(self):
        for change in ('P2S_MODE=check', 'P2S_DISRUPTIVE=false', 'P2S_REPOSITORY_REPAIR=unknown'):
            out = self.shell(self.fixture(change + r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
[ ! -e "$P2S_WORK/calls" ] && printf 'NO_NETWORK\n'
'''), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)
            self.assertIn('NO_NETWORK', out)

    def test_sury_key_replacement_has_persistent_original_backup(self):
        out = self.shell(self.fixture(r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
cat "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg"
cat "$P2S_WORK/usr/share/keyrings"/dephp2shell-sury-backup.*
''', 'sury-key'), isolated_sources=True, isolated_paths=True)
        self.assertIn('RC=0', out)
        self.assertIn('new verified key', out)
        self.assertIn('old Sury key', out)
        self.assertIn('backup=', out)

    def test_unverified_download_and_nonstandard_source_leave_sury_key_unchanged(self):
        for change in ('wrong_key=true', 'download_fail=true', 'owner_fail=true',
                       'printf "deb https://packages.sury.org/php/ buster main\\n" > "$P2S_WORK/etc/apt/sources.list.d/php.list"'):
            out = self.shell(self.fixture(change + r'''
p2s_disruptive_repository_apply_recipe
printf 'RC=%s\n' "$?"
cat "$P2S_WORK/usr/share/keyrings/debsuryorg-archive-keyring.gpg"
''', 'sury-key'), isolated_sources=True, isolated_paths=True)
            self.assertIn('RC=1', out)
            self.assertIn('old Sury key', out)
            self.assertNotIn('new verified key', out)


if __name__ == '__main__':
    unittest.main()
