"""Opt-in equivalent-package migrations; all package/network/service calls are mocked."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class DisruptiveTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def cli(self, args, env='', status=0):
        body = r'''
unset DP2S_ALLOW_SURY_MIGRATION DP2S_ALLOW_SURY_REPOSITORY DP2S_LOG_DIR
p2s_main() { printf 'INVENTORY:%s|disruptive=%s|migration=%s|repository=%s\n' "$*" "${P2S_DISRUPTIVE:-false}" "${P2S_ALLOW_SURY_MIGRATION:-false}" "${P2S_ALLOW_SURY_REPOSITORY:-false}"; }
''' + env + '\np2s_cli --output machine ' + args + r'''
cli_status=$?
[ ! -e "$P2S_WORK/must-not-exist" ] || printf 'UNEXPECTED_LOG_CREATED\n'
exit "$cli_status"
'''
        out = self.shell(body, status=status, isolated_sources=True)
        self.assertNotIn('UNEXPECTED_LOG_CREATED', out)
        return out

    def test_disruptive_and_method_have_separate_consent(self):
        out = self.cli('--disruptive --allow-sury-migration')
        self.assertIn('INVENTORY:--fix|disruptive=true|migration=true|repository=false', out)
        out = self.cli('--disruptive', 'DP2S_ALLOW_SURY_MIGRATION=true')
        self.assertIn('INVENTORY:--fix|disruptive=true|migration=true', out)
        out = self.cli('--check --disruptive --allow-sury-migration')
        self.assertIn('INVENTORY:--check|', out)
        out = self.cli('--disruptive --allow-sury-migration --allow-sury-repository')
        self.assertIn('repository=true', out)

    def test_invalid_consent_fails_before_inventory_or_logs(self):
        for args, env in [('--disruptive', ''), ('--allow-sury-migration', ''),
                          ('--disruptive --allow-sury-repository', ''),
                          ('--disruptive', 'DP2S_ALLOW_SURY_MIGRATION=perhaps'),
                          ('--disruptive --allow-sury-migration',
                           'DP2S_ALLOW_SURY_REPOSITORY=perhaps')]:
            with self.subTest(args=args, env=env):
                out = self.cli(args, env + '\nDP2S_LOG_DIR="$P2S_WORK/must-not-exist"', status=64)
                self.assertNotIn('INVENTORY:', out)

    def test_help_does_not_inspect_server_even_with_invalid_method_environment(self):
        out = self.cli('--help', 'DP2S_ALLOW_SURY_MIGRATION=invalid')
        self.assertIn('--allow-sury-migration', out)
        self.assertNotIn('INVENTORY:', out)

    def fixture(self, changes='', plan=None):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12; P2S_PANEL=none
P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=false
P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_PENDING=false
old=8.2.29-1~deb12u1
candidate=8.2.35-1+0~20261021.94+debian12~1.gbp8bff78
arch=amd64; proposed_arch=amd64; source=php8.2
suite=bookworm; origin=deb.sury.org; installed_api=phpapi-20220829; proposed_api=phpapi-20220829
held=false; duplicate_origin=false; metadata_error=false; installed_api_error=false
''' + changes + r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf 'php8.2-cli|%s|%s|Debian PHP Maintainers\nphp8.2-common|%s|%s|Debian PHP Maintainers\n' "$old" "$arch" "$old" "$arch" > "$P2S_WORK/packages"
printf '%s\n' 'php-cli|2:8.2+93|all|Debian' 'php-common|2:93|all|Debian' \
    'php8.2-redis|6.0.2-1|amd64|Debian' >> "$P2S_WORK/packages"
for name in php8.2-cli php8.2-common; do
    printf '%s|%s|%s|php8.2|%s|source_field\n' "$name" "$old" "$arch" "$old"
done > "$P2S_WORK/deb-source-records"
printf '%s\n' 'php8.2-redis|6.0.2-1|amd64|php-redis|6.0.2-1|source_field' >> "$P2S_WORK/deb-source-records"
# Real dpkg is allowed only for its read-only version comparison operation.
dpkg() { [ "$1" = --compare-versions ] || return 97; command dpkg "$@"; }
p2s_command_exists() { case "$1" in apt-get|apt-cache|apt-config|dpkg|dpkg-query|apt-mark) return 0;; *) return 1;; esac; }
fixture_candidate=$candidate; fixture_source=$source; fixture_suite=$suite
fixture_old=$old; fixture_origin=$origin; fixture_proposed_arch=$proposed_arch
p2s_command_run() {
    local last cmd name
    for last in "$@"; do :; done
    cmd=$2
    case "$cmd" in
        dpkg) [ "$3" = --audit ] && return 0 ;;
        apt-mark) if $held; then printf 'php8.2-cli\n'; fi ;;
        apt-config) printf 'Dir "/";\n' ;;
        dpkg-query)
            if $installed_api_error; then printf 'API query failed\n' >&2; return 1; fi
            printf '%s\n' "$installed_api" ;;
        apt-cache)
            case " $* " in
                *' policy '*)
                    if [ "$last" = policy ]; then
                        printf ' 500 https://packages.sury.org/php %s/main amd64 Packages\n     release o=%s,n=%s,c=main,b=amd64\n' "$fixture_suite" "$fixture_origin" "$fixture_suite"
                    else
                        name=${last%:*}
                        printf '%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n     %s 500\n        500 https://packages.sury.org/php %s/main amd64 Packages\n' "$name" "$fixture_old" "$fixture_candidate" "$fixture_candidate" "$fixture_suite"
                        if $duplicate_origin; then printf '        500 https://deb.debian.org/debian bookworm/main amd64 Packages\n'; fi
                    fi ;;
                *' show '*)
                    if $metadata_error; then printf 'https://login:private-token@repo.invalid/private-path\n' >&2; return 124; fi
                    name=${last%%:*}; name=${name%%=*}
                    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSource: %s\n' "$name" "$fixture_candidate" "$fixture_proposed_arch" "$fixture_source"
                    printf 'Depends: libc6,\n libpcre2-8-0\nDescription: excluded fixture description\n'
                    [ "$name" != php8.2-cli ] || printf 'Provides: %s\n' "$proposed_api" ;;
                *) return 97 ;;
            esac ;;
        apt-get)
            case " $* " in
                *' update '*) printf 'REFRESH\n' >> "$P2S_WORK/calls" ;;
                *' -s '*)
                    printf 'SIMULATE:%s\n' "$*" >> "$P2S_WORK/calls"
''' + (plan or r'''
                    for name in php8.2-cli php8.2-common; do
                        printf 'Inst %s [%s] (%s repo [amd64])\n' "$name" "$fixture_old" "$fixture_candidate"
                    done
''') + r''' ;;
                *' install '*) printf 'INSTALL:%s\n' "$*" >> "$P2S_WORK/calls" ;;
                *) return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_package_deb_update
printf 'RC=%s|ATTEMPTED=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
'''

    def test_opt_in_updates_exact_engines_and_freezes_selectors_and_native_pecl(self):
        out = self.shell(self.fixture(), isolated_sources=True)
        self.assertIn('RC=0|ATTEMPTED=true', out)
        install = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        simulate = next(line for line in out.splitlines() if line.startswith('SIMULATE:'))
        self.assertEqual(simulate.split('install --only-upgrade ', 1)[1],
                         install.split('install --only-upgrade ', 1)[1])
        for exact in ['php8.2-cli:amd64=8.2.35-1+0~20261021.94+debian12~1.gbp8bff78',
                      'php8.2-common:amd64=8.2.35-1+0~20261021.94+debian12~1.gbp8bff78',
                      'php-cli=2:8.2+93', 'php-common=2:93', 'php8.2-redis:amd64=6.0.2-1']:
            self.assertIn(exact, install)
        self.assertIn('AllowUnauthenticated=false', install)
        self.assertIn('--no-remove', install)
        self.assertIn('apt_candidate_metadata:beforefix|Source: php8.2', out)
        self.assertIn('apt_candidate_metadata:beforefix| libpcre2-8-0', out)
        self.assertNotIn('excluded fixture description', out)
        self.assertIn('apt_candidate_api:beforefix|php8.2-cli|installed=phpapi-20220829|candidate=phpapi-20220829', out)

    def test_default_mode_never_converts_native_packages_to_sury(self):
        out = self.shell(self.fixture('P2S_DISRUPTIVE=false; P2S_ALLOW_SURY_MIGRATION=false'), isolated_sources=True)
        self.assertIn('RC=1|ATTEMPTED=false', out)
        self.assertIn('candidate_provider', out)
        self.assertNotIn('INSTALL:', out)

    def test_incompatible_or_unverified_candidates_never_install(self):
        cases = {'wrong_arch': 'proposed_arch=i386', 'installed_32bit': 'arch=i386',
                 'wrong_source': 'source=php8.3', 'foreign_suite': 'suite=trixie',
                 'foreign_origin': 'origin=Unrelated', 'duplicate_origin': 'duplicate_origin=true',
                 'unknown_api': 'installed_api=', 'missing_proposed_api': 'proposed_api=',
                 'changed_api': 'proposed_api=phpapi-20230831',
                 'unfixed_build': 'candidate=8.2.29-1+0~20261021.94+debian12~1.gbp8bff78',
                 'downgrade': 'old=8.2.36-1~deb12u1',
                 'branch_change': 'candidate=8.3.36-1+0~20261021.88+debian12~1.gbp250f7c',
                 'held': 'held=true', 'panel': 'P2S_PANEL=plesk', 'obsolete_os': 'P2S_RELEASE=10',
                 'metadata_failure': 'metadata_error=true', 'installed_api_failure': 'installed_api_error=true'}
        for scenario, changes in cases.items():
            with self.subTest(scenario=scenario):
                out = self.shell(self.fixture(changes), isolated_sources=True)
                self.assertIn('RC=1|ATTEMPTED=false', out)
                self.assertNotIn('INSTALL:', out)
                self.assertIn('dss:manifest:blocker:', out)
                if scenario == 'changed_api':
                    self.assertIn('installed=phpapi-20220829|candidate=phpapi-20230831', out)
                elif scenario == 'metadata_failure':
                    self.assertIn('operation=metadata|exit=124', out)
                    self.assertIn('[repository host=repo.invalid; path redacted]', out)
                    self.assertNotIn('private-token', out)
                    self.assertNotIn('private-path', out)
                elif scenario == 'installed_api_failure':
                    self.assertIn('operation=installed_API|exit=1', out)
                    self.assertIn('API query failed', out)

    def test_simulation_cannot_change_frozen_packages_dependencies_or_versions(self):
        for plan in ['Inst php-cli [2:8.2+93] (2:8.4+101 repo [all])',
                     'Inst php8.2-redis [6.0.2-1] (6.0.3-1 repo [amd64])',
                     'Inst libc6 [2.36] (2.40 repo [amd64])',
                     'Remv php8.2-cli [8.2.29-1~deb12u1]',
                     'Inst php8.2-cli [8.2.29-1~deb12u1] (8.2.36-other repo [amd64])']:
            with self.subTest(plan=plan):
                out = self.shell(self.fixture(plan="printf '%s\\n' " + shlex.quote(plan)), isolated_sources=True)
                self.assertIn('RC=1|ATTEMPTED=false', out)
                self.assertNotIn('INSTALL:', out)

    def test_disruptive_mode_keeps_existing_custom_runtime_block(self):
        out = self.shell(r'''
P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=true
P2S_BLOCKED=true
p2s_package_deb_update() { printf 'UNEXPECTED_UPDATE\n'; return 97; }
p2s_fix_run
printf 'RC=%s|ATTEMPTED=%s|RESTART=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED" "$P2S_RESTART_ATTEMPTED"
''', isolated_sources=True)
        self.assertIn('RC=1|ATTEMPTED=false|RESTART=false', out)
        self.assertNotIn('UNEXPECTED_UPDATE', out)

    def source_fixture(self, changes='', after=''):
        return r'''
P2S_MODE=fix; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=true
P2S_TRANSACTION_ATTEMPTED=false; P2S_SURY_KEY_CREATED=false; P2S_SURY_REPOSITORY_CREATED=false
fixture_fingerprint=15058500A0235D97F5D10063B188E2B695BD4743
fixture_extra_key=false; fixture_existing=false; fixture_available=false
''' + changes + r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d" "$P2S_WORK/etc/apt/keyrings"
fixture_source="$P2S_WORK/etc/apt/sources.list.d/dephp2shell-sury-php.list"
fixture_key="$P2S_WORK/etc/apt/keyrings/dephp2shell-sury-php.gpg"
if $fixture_existing; then printf 'original source\n' > "$fixture_source"; fi
curl() { return 97; }; wget() { return 97; }; gpg() { return 97; }
p2s_command_exists() { case "$1" in gpg|curl) return 0;; *) return 1;; esac; }
p2s_command_run() {
    case "$2" in
        apt-cache)
            if $fixture_available; then printf '500 https://packages.sury.org/php bookworm/main amd64 Packages\n'; fi ;;
        curl)
            printf 'DOWNLOAD:%s\n' "$*" >> "$P2S_WORK/calls"
            printf 'fixture public key\n' > "$P2S_WORK/sury.key" ;;
        gpg)
            case " $* " in
                *' --show-keys '*)
                    printf 'pub:::::::::\nfpr:::::::::%s:\nsub:::::::::\nfpr:::::::::SUBKEY:\n' "$fixture_fingerprint"
                    if $fixture_extra_key; then printf 'pub:::::::::\nfpr:::::::::EXTRAKEY:\n'; fi ;;
                *' --dearmor '*) cat ;;
                *) return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_disruptive_sury_add_repository
printf 'SOURCE_RC=%s\n' "$?"
[ ! -f "$fixture_source" ] || { printf 'SOURCE_CONTENT:'; cat "$fixture_source"; }
[ ! -f "$fixture_key" ] || printf 'KEY_PRESENT\n'
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
''' + after

    def test_added_source_is_dedicated_signed_by_and_removed_before_install(self):
        out = self.shell(self.source_fixture(after=r'''
stat -c 'MODE:%a' "$fixture_key" "$fixture_source"
p2s_disruptive_sury_cleanup_added_repository
[ ! -e "$fixture_source" ] && [ ! -e "$fixture_key" ] && printf 'OWNED_FILES_REMOVED\n'
'''), isolated_sources=True)
        self.assertIn('SOURCE_RC=0', out)
        self.assertIn('arch=amd64 signed-by=', out)
        self.assertIn('https://packages.sury.org/php bookworm main', out)
        self.assertIn('--proto =https --proto-redir =https', out)
        self.assertEqual(out.count('MODE:644'), 2)
        self.assertIn('OWNED_FILES_REMOVED', out)

    def test_added_source_is_retained_after_any_install_attempt(self):
        out = self.shell(self.source_fixture(after=r'''
P2S_TRANSACTION_ATTEMPTED=true
p2s_disruptive_sury_cleanup_added_repository
[ -f "$fixture_source" ] && [ -f "$fixture_key" ] && printf 'RECOVERY_FILES_RETAINED\n'
'''), isolated_sources=True)
        self.assertIn('SOURCE_RC=0', out)
        self.assertIn('RECOVERY_FILES_RETAINED', out)

    def test_failed_key_write_cleans_its_partial_file_and_preserves_other_sources(self):
        out = self.shell(self.source_fixture(changes=r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf 'original customer source\n' > "$P2S_WORK/etc/apt/sources.list.d/customer.list"
cat() {
    if [ "${1:-}" = "$P2S_WORK/sury.gpg" ]; then printf 'partial key\n'; return 1; fi
    command cat "$@"
}
''', after=r'''
p2s_disruptive_sury_cleanup_added_repository
[ ! -e "$fixture_key" ] && [ ! -e "$fixture_source" ] && printf 'PARTIAL_FILES_REMOVED\n'
printf 'OTHER_SOURCE:'; cat "$P2S_WORK/etc/apt/sources.list.d/customer.list"
'''), isolated_sources=True)
        self.assertIn('SOURCE_RC=1', out)
        self.assertIn('PARTIAL_FILES_REMOVED', out)
        self.assertIn('OTHER_SOURCE:original customer source', out)

    def test_unreviewed_key_or_existing_source_is_not_overwritten_or_removed(self):
        for changes in ['fixture_fingerprint=WRONGKEY', 'fixture_extra_key=true',
                        'fixture_existing=true']:
            with self.subTest(changes=changes):
                out = self.shell(self.source_fixture(changes, after=r'''
p2s_disruptive_sury_cleanup_added_repository
[ ! -e "$fixture_key" ] || printf 'UNEXPECTED_KEY_FILE\n'
[ ! -e "$fixture_source" ] || { printf 'RETAINED:'; cat "$fixture_source"; }
'''), isolated_sources=True)
                self.assertIn('SOURCE_RC=1', out)
                self.assertNotIn('UNEXPECTED_KEY_FILE', out)
                self.assertNotIn('KEY_PRESENT', out)
                if 'existing' in changes:
                    self.assertIn('RETAINED:original source', out)
                    self.assertNotIn('DOWNLOAD:', out)

    def test_existing_available_source_needs_no_new_key_or_download(self):
        out = self.shell(self.source_fixture('fixture_available=true'), isolated_sources=True)
        self.assertIn('SOURCE_RC=0', out)
        self.assertIn('matching_source_already_available', out)
        self.assertNotIn('DOWNLOAD:', out)
        self.assertNotIn('KEY_PRESENT', out)

    def test_existing_source_without_cached_index_is_retained(self):
        out = self.shell(self.source_fixture(r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf 'Types: deb\nURIs: https://packages.sury.org/php\nSuites: bookworm\nEnabled: no\n' > "$P2S_WORK/etc/apt/sources.list.d/php.sources"
'''), isolated_sources=True)
        self.assertIn('SOURCE_RC=0', out)
        self.assertIn('existing_source_definition_retained', out)
        self.assertNotIn('DOWNLOAD:', out)
        self.assertNotIn('KEY_PRESENT', out)
        self.assertNotIn('SOURCE_CONTENT:', out)

    def test_source_addition_requires_fix_mode_and_every_consent_flag(self):
        for changes in ['P2S_MODE=check', 'P2S_DISRUPTIVE=false',
                        'P2S_ALLOW_SURY_MIGRATION=false', 'P2S_ALLOW_SURY_REPOSITORY=false',
                        'P2S_RELEASE=10']:
            with self.subTest(changes=changes):
                out = self.shell(self.source_fixture(changes), isolated_sources=True)
                self.assertIn('SOURCE_RC=1', out)
                self.assertNotIn('DOWNLOAD:', out)
                self.assertNotIn('KEY_PRESENT', out)
                self.assertNotIn('SOURCE_CONTENT:', out)

    def test_ubuntu_source_uses_matching_suite_and_its_distinct_key(self):
        for release, suite in [('22.04', 'jammy'), ('24.04', 'noble')]:
            with self.subTest(release=release):
                changes = ('P2S_DISTRO=ubuntu; P2S_RELEASE=' + release + '\n'
                           'fixture_fingerprint=B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6')
                out = self.shell(self.source_fixture(changes), isolated_sources=True)
                self.assertIn('SOURCE_RC=0', out)
                self.assertIn('https://ppa.launchpadcontent.net/ondrej/php/ubuntu ' + suite + ' main', out)
                self.assertIn('https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6', out)


if __name__ == '__main__':
    unittest.main()
