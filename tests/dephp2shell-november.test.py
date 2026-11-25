"""Offline package evidence and reporting for the November PHP assessment."""
from pathlib import Path
import runpy
import unittest


HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class NovemberTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def test_upstream_thresholds_and_default_scope(self):
        result = self.shell(r'''
for version in 8.2.35 8.3.36 8.4.27 8.5.12 8.6.0; do
    p2s_version_upstream_state "$version"
done
P2S_NOVEMBER=true
for version in 8.2.35 8.2.36 8.3.36 8.3.37 8.4.27 8.4.28 8.5.12 8.5.13 8.6.0RC7 8.6.0; do
    p2s_version_upstream_state "$version"
done
''')
        self.assertEqual(result.splitlines(), list('NNNN?YNYNYNYN?N'))

    def test_vendor_revisions_distinguish_fixed_affected_and_unverified(self):
        result = self.shell(r'''
P2S_NOVEMBER=true
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
p2s_version_package_state php8.2-fpm 8.2.35-1~deb12u1 Debian amd64
p2s_version_package_state php8.2-fpm 8.2.36-1~deb12u1 Debian amd64
P2S_DISTRO=ubuntu; P2S_RELEASE=24.04
p2s_version_package_state php8.3-fpm 8.3.6-0ubuntu0.24.04.13 Ubuntu amd64
p2s_version_package_state php8.3-fpm 8.3.6-0ubuntu0.24.04.14 Ubuntu amd64
p2s_version_package_state php8.3-fpm 8.3.6-0ubuntu0.24.04.15 Ubuntu amd64
P2S_BACKEND=rpm; P2S_DISTRO=almalinux; P2S_MAJOR=10
p2s_version_package_state php8.4-fpm 0:8.4.27-2.el10_3.1 AlmaLinux x86_64
p2s_version_package_state php8.4-fpm 0:8.4.27-2.el10_3.1.alma.1 AlmaLinux x86_64
p2s_version_package_state php8.4-fpm 0:8.4.27-2.el10_3.1.alma.2 AlmaLinux x86_64
P2S_DISTRO=rocky
p2s_version_package_state php8.4-fpm 0:8.4.27-2.el10_3.1 'Rocky Enterprise Software Foundation' x86_64
p2s_version_package_state php8.4-fpm 0:8.4.27-2.el10_3.1.alma.1 'Rocky Enterprise Software Foundation' x86_64
''')
        self.assertEqual(result.splitlines(), list('YNYNNYN?Y?'))

    def test_ubuntu_native_apache_cli_and_common_builds(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=ubuntu; P2S_RELEASE=26.04
vendor='Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>'
for name in libapache2-mod-php8.5 php8.5-cli php8.5-common; do
    p2s_version_package_state "$name" 8.5.4-0ubuntu1.5 "$vendor" amd64
    p2s_version_package_state "$name" 8.5.4-0ubuntu1.6 "$vendor" amd64
done
p2s_version_package_state php8.5-fpm 8.5.4-0ubuntu1.7 "$vendor" amd64
p2s_version_package_state php8.5-fpm 8.5.4-0ubuntu1.6+ppa1 "$vendor" amd64
P2S_RELEASE=26.10
p2s_version_package_state php8.5-fpm 8.5.9-0ubuntu2.2 "$vendor" amd64
p2s_version_package_state php8.5-fpm 8.5.4-0ubuntu1.6 "$vendor" amd64
P2S_RELEASE=22.04
for name in libapache2-mod-php8.1 php8.1-cli php8.1-common php8.1-fpm; do
    p2s_version_package_state "$name" 8.1.2-1ubuntu2.28 "$vendor" amd64
    p2s_version_package_state "$name" 8.1.2-1ubuntu2.29 "$vendor" amd64
done
p2s_version_package_state php8.1-fpm 8.1.2-1ubuntu2.30 "$vendor" amd64
p2s_version_package_state php8.1-fpm 8.1.2-1ubuntu2.29+ppa1 "$vendor" amd64
P2S_RELEASE=20.04
p2s_version_package_state php7.4-fpm 7.4.3-4ubuntu2.29+esm6 "$vendor" amd64
''')
        expected_resolute_stonking = list('YNYNYNN?NY')
        expected_jammy = list('YNYNYNYNN?')
        self.assertEqual(result.splitlines(), expected_resolute_stonking + expected_jammy + ['N'])

    def test_extended_support_versions_keep_source_and_release_boundaries(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=ubuntu; P2S_RELEASE=18.04
p2s_version_package_state php7.2-cli 7.2.24-0ubuntu0.18.04.17+esm14 Ubuntu amd64
p2s_version_package_state php7.2-cli 7.2.24-0ubuntu0.18.04.17+esm16 Ubuntu amd64
p2s_version_package_state php7.2-cli 7.2.24-0ubuntu0.18.04.17+esm16.local Ubuntu amd64
P2S_DISTRO=debian; P2S_RELEASE=10.13
for version in 7.3.31-1~deb10u16 7.3.31-1~deb10u17 7.3.31-1~deb10u18 7.3.31-1~deb10u18.local; do
    p2s_version_package_state php7.3-fpm "$version" Debian amd64 php7.3 "$version"
done
p2s_version_package_state php7.3-fpm 7.3.31-1~deb10u17 Debian amd64 php7.3 7.3.31-1~deb10u16
''')
        self.assertEqual(result.splitlines(), list('YN?YNN??'))

    def test_freexian_cli_requires_november_and_explicit_permission(self):
        setup = r'''
unset DP2S_ALLOW_FREEXIAN DP2S_MIGRATE_PHP_TO_SURY DP2S_ADD_SURY_REPOSITORY DP2S_LOG_DIR
unset DP2S_CONFIGURE_PENDING_PHP_PACKAGES DP2S_REINSTALL_PHP_SAME_VERSION
unset DP2S_REFRESH_SURY_SIGNING_KEY DP2S_ADD_OS_SECURITY_REPOSITORY
p2s_main() {
    printf 'ENGINE:%s|freexian=%s|sury=%s\n' "$*" "$P2S_ALLOW_FREEXIAN" "$P2S_ALLOW_SURY_MIGRATION"
}
'''
        for options, environment, status, selection in (
            ('--fix --november-2026 --allow-freexian', '', 64, ''),
            ('--fix --enable-extra-fixes --allow-freexian', '', 64, ''),
            ('--fix --november-2026 --enable-extra-fixes --allow-freexian=invalid', '', 64, ''),
            ('--fix --november-2026 --enable-extra-fixes --allow-freexian', '', 0, '--fix|freexian=true|sury=false'),
            ('--fix --november-2026 --enable-extra-fixes --allow-freexian --migrate-php-to-sury',
             '', 0, '--fix|freexian=true|sury=true'),
            ('--fix --november-2026 --enable-extra-fixes', 'DP2S_ALLOW_FREEXIAN=yes', 0, '--fix|freexian=true|sury=false'),
            ('--check --november-2026 --allow-freexian=false', 'DP2S_ALLOW_FREEXIAN=yes', 0, '--check|freexian=false|sury=false'),
        ):
            with self.subTest(options=options, environment=environment):
                out = self.shell(f'{setup}\n{environment}\np2s_cli --output machine {options} 2>&1', status=status)
                if selection:
                    self.assertIn(f'ENGINE:{selection}', out)
                else:
                    self.assertNotIn('ENGINE:', out)

    def freexian_candidate(self, changes='', run=None):
        return self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10.13; P2S_MAJOR=10
P2S_FREEXIAN_ACTIVE=true; P2S_FREEXIAN_SIGNED_SUITES=' buster-lts '
fixture_name=php7.3-cli; fixture_source=php7.3; fixture_installed_source=php7.3
fixture_old=7.3.31-1~deb10u7; fixture_elts=7.3.31-1~deb10u17
fixture_uri=https://deb.freexian.com/extended-lts; fixture_suite=buster-lts
fixture_origin=Freexian; fixture_label=Freexian-Extended-LTS
fixture_component=main
fixture_native=; fixture_native_priority=500; fixture_duplicate=false
fixture_native_uri=https://archive.debian.org/debian; fixture_native_suite=buster
fixture_extension=php7.3-json; fixture_signer_ok=true
fixture_candidate_api=phpapi-20180731; fixture_installed_api=phpapi-20180731
fixture_install=false
''' + changes + r'''
printf ' 500 %s %s/%s amd64 Packages\n     release o=%s,a=%s,n=%s,l=%s,c=%s,b=amd64\n' \
    "$fixture_uri" "$fixture_suite" "$fixture_component" "$fixture_origin" "$fixture_suite" "$fixture_suite" "$fixture_label" "$fixture_component" > "$P2S_WORK/candidate-origins"
if [ -n "$fixture_native" ]; then
    printf ' %s %s %s/main amd64 Packages\n     release o=Debian,a=oldoldstable,n=%s,l=Debian,c=main,b=amd64\n' \
        "$fixture_native_priority" "$fixture_native_uri" "$fixture_native_suite" "$fixture_native_suite" >> "$P2S_WORK/candidate-origins"
fi
p2s_command_run() {
    local last fixture_package provides
    for last in "$@"; do :; done
    fixture_package=${last%%=*}; fixture_package=${fixture_package%:amd64}
    case " $* " in
        *' dpkg --audit '*|*' dpkg --get-selections '*|*' apt-mark showhold '*) return 0 ;;
        *' apt-config dump '*) printf 'Dir "/";\n' ;;
        *' apt-cache '*' policy ') cat "$P2S_WORK/fixture-origins" ;;
        *' apt-cache '*" policy $fixture_name:amd64 "|*' apt-cache '*" policy $fixture_extension:amd64 ")
            printf '%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n     %s 500\n        500 %s %s/%s amd64 Packages\n' \
                "$fixture_package" "$fixture_old" "$fixture_elts" "$fixture_elts" "$fixture_uri" "$fixture_suite" "$fixture_component"
            if $fixture_duplicate; then printf '        500 file:/local/repo buster-lts/main amd64 Packages\n'; fi
            if [ -n "$fixture_native" ]; then
                printf '     %s %s\n        %s %s %s/main amd64 Packages\n' \
                    "$fixture_native" "$fixture_native_priority" "$fixture_native_priority" "$fixture_native_uri" "$fixture_native_suite"
            fi
            printf ' *** %s 100\n        100 /var/lib/dpkg/status\n' "$fixture_old" ;;
        *' apt-cache '*" show $fixture_name:amd64="*|*' apt-cache '*" show $fixture_extension:amd64="*)
            provides=$fixture_candidate_api
            if [ "$fixture_package" = "$fixture_extension" ]; then provides=php-json; fi
            printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nSource: %s\nProvides: %s\n' \
                "$fixture_package" "${last#*=}" "$fixture_source" "$provides" ;;
        *' dpkg-query '*'Provides'*) printf '%s\n' "$fixture_installed_api" ;;
        *' apt-get -s '*)
            printf 'SIMULATE:%s\n' "$*" >> "$P2S_WORK/calls"
            printf 'Inst %s [%s] (%s Freexian:buster-lts [amd64])\n' "$fixture_name" "$fixture_old" "$fixture_elts" \
                "$fixture_extension" "$fixture_old" "$fixture_elts" ;;
        *' apt-get '*' update ') $fixture_install ;;
        *' apt-get -y '*" install --only-upgrade "*)
            $fixture_install || return 97
            printf 'INSTALL:%s\n' "$*" >> "$P2S_WORK/calls" ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" | tee -a "$P2S_WORK/calls" >&2; return 97 ;;
    esac
}
printf '%s\n' "$fixture_name|$fixture_old|amd64|$fixture_installed_source|$fixture_old" > "$P2S_WORK/deb-source-records"
''' + (run or r'''
p2s_package_deb_candidate "$fixture_name" "$fixture_old" amd64 false 'Debian PHP Maintainers'
printf 'CANDIDATE_RC=%s|VERSION=%s\n' "$?" "${P2S_DEB_CANDIDATE:-}"
'''), isolated_sources=bool(run))

    def test_freexian_candidate_requires_an_authenticated_matching_exclusive_origin(self):
        for release, branch, suite, old, fixed in (
            ('9', 'php7.0', 'stretch-lts', '7.0.33-0+deb9u26', '7.0.33-0+deb9u27'),
            ('10', 'php7.3', 'buster-lts', '7.3.31-1~deb10u7', '7.3.31-1~deb10u17'),
            ('11', 'php7.4', 'bullseye', '7.4.33-1+deb11u14', '7.4.33-1+deb11u15'),
        ):
            with self.subTest(release=release):
                out = self.freexian_candidate(
                    f'P2S_RELEASE={release}; P2S_MAJOR={release}; '
                    f'P2S_FREEXIAN_SIGNED_SUITES=" {suite} "; fixture_suite={suite}; '
                    f'fixture_name={branch}-cli; fixture_source={branch}; fixture_installed_source={branch}; '
                    f'fixture_old={old}; fixture_elts={fixed}'
                )
                self.assertIn(f'CANDIDATE_RC=0|VERSION={fixed}', out)
                self.assertIn('dss:manifest:freexian_candidate:', out)
        for changes in (
            'fixture_suite=bullseye-lts; P2S_FREEXIAN_SIGNED_SUITES=" bullseye-lts "',
            'fixture_origin=Other',
            'fixture_label=Other',
            'fixture_uri=http://deb.freexian.com/extended-lts',
            'fixture_uri=https://mirror.invalid/extended-lts',
            'P2S_FREEXIAN_SIGNED_SUITES=""',
            'fixture_source=php7.4',
            'fixture_candidate_api=phpapi-20200930',
            'fixture_duplicate=true',
        ):
            with self.subTest(changes=changes):
                out = self.freexian_candidate(changes)
                self.assertRegex(out, r'(?m)^CANDIDATE_RC=[1-9][0-9]*\|VERSION=')

    def test_signed_freexian_indexes_require_the_vendor_fingerprint(self):
        out = self.shell(r'''
P2S_NOVEMBER=true; P2S_DISTRO=debian; P2S_RELEASE=10.13
mkdir -p "$P2S_WORK/var/lib/apt/lists" "$P2S_WORK/usr/share/keyrings"
fixture_keyring="$P2S_WORK/usr/share/keyrings/freexian-archive-keyring.gpg"
fixture_index="$P2S_WORK/var/lib/apt/lists/deb.freexian.com_extended-lts_dists_buster-lts_InRelease"
touch "$fixture_keyring" "$fixture_index"
p2s_command_exists() { [ "$1" = gpgv ]; }
p2s_command_run() {
    case "$2" in
        apt-config) printf "lists='%s/var/lib/apt/lists/'\n" "$P2S_WORK" ;;
        gpgv)
            case " $* " in *" --keyring $fixture_keyring --status-fd 1 $fixture_index ") ;;
                *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
            esac
            printf '[GNUPG:] VALIDSIG %s 2026-11-21 1795266925 0 4 0 1 10 01 %s\n' \
                "$fixture_fingerprint" "$fixture_fingerprint"
            return "$fixture_exit" ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
fixture_exit=0; fixture_fingerprint=AB597C4F6F3380BD4B2BEBC2A07310D369055D5A
p2s_freexian_signed_indexes; printf 'SIGNED_RC=%s|SUITES=%s\n' "$?" "$P2S_FREEXIAN_SIGNED_SUITES"
fixture_exit=1
p2s_freexian_signed_indexes; printf 'FAILED_RC=%s\n' "$?"
fixture_exit=0; fixture_fingerprint=1111111111111111111111111111111111111111
p2s_freexian_signed_indexes; printf 'OTHER_KEY_RC=%s\n' "$?"
''', isolated_paths=True, isolated_sources=True)
        self.assertIn('SIGNED_RC=0|SUITES= buster-lts ', out)
        self.assertIn('FAILED_RC=1', out)
        self.assertIn('OTHER_KEY_RC=1', out)

    def test_released_debian_candidate_wins_at_equal_priority(self):
        out = self.freexian_candidate('fixture_elts=7.3.31-1~deb10u19; fixture_native=7.3.31-1~deb10u18')
        self.assertIn('CANDIDATE_RC=0|VERSION=7.3.31-1~deb10u18', out)
        self.assertNotIn('dss:manifest:freexian_candidate:', out)

    def test_normal_candidate_needs_freexian_consent(self):
        out = self.freexian_candidate('P2S_FREEXIAN_ACTIVE=false; P2S_FREEXIAN_SIGNED_SUITES=""')
        self.assertIn('APT selected a Freexian build for php7.3-cli', out)
        self.assertIn('CANDIDATE_RC=1|VERSION=', out)
        out = self.freexian_candidate(
            'P2S_FREEXIAN_ACTIVE=false; P2S_FREEXIAN_SIGNED_SUITES=""; '
            'fixture_elts=7.3.31-1~deb10u19; fixture_native=7.3.31-1~deb10u18')
        self.assertIn('CANDIDATE_RC=0|VERSION=7.3.31-1~deb10u18', out)

    def test_private_freexian_policy_reports_package_matches_without_the_token(self):
        out = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10.13
p2s_command_run() {
    [ "$2" = apt-cache ] || return 97
    cat <<'POLICY'
php5.6-fpm:
  Installed: 5.6.40-1+freexian1
  Candidate: 5.6.40-1+freexian2
  Version table:
     5.6.40-1+freexian2 500
        500 https://php.freexian.com/c/example-secret buster/main amd64 Packages
 *** 5.6.40-1+freexian1 500
        500 https://php.freexian.com/c/example-secret buster/main amd64 Packages
        100 /var/lib/dpkg/status
     5.6.40-1+freexian0 500
        500 https://php.freexian.com/c/example-secret buster/main amd64 Packages
php7.3-cli:
  Installed: 7.3.31-1~deb10u17
  Candidate: 7.3.31-1~deb10u17
  Version table:
 *** 7.3.31-1~deb10u17 500
        500 https://deb.freexian.com/extended-lts buster-lts/main amd64 Packages
        100 /var/lib/dpkg/status
POLICY
}
p2s_package_deb_policy_collect php5.6-fpm php7.3-cli
printf 'APT error reading /var/lib/apt/lists/partial/php.freexian.com_c_example-secret_dists_buster_InRelease\n' |
    p2s_manifest_redact_repository_urls
p2s_version_package_state php5.6-fpm 5.6.40-1+freexian1 Debian amd64
''', isolated_sources=True)
        self.assertIn('freexian_php_lts_package:beforefix|php5.6-fpm|5.6.40-1+freexian1|installed_version_match|cached_index_match', out)
        self.assertIn('freexian_php_lts_package:beforefix|php5.6-fpm|5.6.40-1+freexian2|candidate_match|cached_index_match', out)
        self.assertEqual(out.count('dss:manifest:freexian_php_lts_package:'), 2)
        self.assertIn('[Freexian PHP LTS index name redacted]', out)
        self.assertNotIn('example-secret', out)
        self.assertTrue(out.endswith('?\n'))

    def test_community_backports_use_exact_published_builds_for_the_host(self):
        out = self.shell(r'''
P2S_BACKEND=deb; P2S_NOVEMBER=true
P2S_DISTRO=debian; P2S_RELEASE=10.13
fixed=5.6.40-110+debsuryorg12.1+1+debian10+animaa1
old=5.6.40-29+0~20200514.35+debian10~1.gbpcc49a4
p2s_package_provider php5.6-fpm Debian "$fixed"
p2s_version_package_state php5.6-fpm "$old" Debian amd64 php5.6 "$old"
p2s_version_package_state php5.6-fpm "$fixed" Debian arm64 php5.6 "$fixed"
p2s_version_package_state php5.6-fpm "$fixed" Debian armhf php5.6 "$fixed"
p2s_version_package_state php5.6-fpm "$fixed" Debian amd64 php5.6 "$old"
old_community=5.6.40-105+0~20261022.135+debian10~1+animaa1
p2s_version_package_state php5.6-fpm "$old_community" Debian amd64 php5.6 "$old_community"
P2S_DISTRO=ubuntu; P2S_RELEASE=20.04
ubuntu_fixed=1:7.4.33-38+debsuryorg12.1+1+ubuntu20.04+animaa1
p2s_version_package_state php7.4-cli "$ubuntu_fixed" Debian arm64 php7.4 "$ubuntu_fixed"
p2s_version_package_state php5.6-fpm "$fixed" Debian amd64 php5.6 "$fixed"
''')
        self.assertEqual(out.splitlines(), ['debian-php-backports (revision hint)', *'YN??YN?'])

    def test_configured_backports_need_a_signed_exact_simulation(self):
        settings = r'''
fixture_name=php5.6-fpm; fixture_extension=php5.6-json
fixture_source=php5.6; fixture_installed_source=php5.6
fixture_old=5.6.40-29+0~20200514.35+debian10~1.gbpcc49a4
fixture_elts=5.6.40-110+debsuryorg12.1+1+debian10+animaa1
fixture_uri=https://animaartificialis.github.io/debian-php-backports
fixture_suite=buster; fixture_component=sury
fixture_origin=debian-php-backports; fixture_label=debian-php-backports
fixture_candidate_api=phpapi-20131226; fixture_installed_api=phpapi-20131226
fixture_preferred=false; fixture_default_install=false
'''
        run = r'''
cp "$P2S_WORK/candidate-origins" "$P2S_WORK/fixture-origins"
printf '%s\n' "$fixture_name|$fixture_old|amd64|Debian" "$fixture_extension|$fixture_old|amd64|Debian" \
    'php7.3-cli|7.3.31-1~deb10u7|amd64|Debian' 'php-cli|2:7.3+69|all|Debian' > "$P2S_WORK/packages"
printf '%s\n' "$fixture_extension|$fixture_old|amd64|php5.6|$fixture_old" >> "$P2S_WORK/deb-source-records"
printf '%s\n' unsupported_os > "$P2S_WORK/blocker-keys"
P2S_MODE=check; P2S_BLOCKED=true; P2S_STATE=Y; P2S_REPOSITORY_REFRESH=refreshed
p2s_backports_signed_index() { "$fixture_signer_ok"; }
p2s_repository_repair_assess() { return 1; }
if $fixture_preferred; then p2s_fix_plan_options() { P2S_VERIFIED_PROVIDER_PLAN=true; }; fi
if $fixture_default_install; then
    P2S_MODE=fix; P2S_BLOCKED=false
    p2s_package_inventory_collect() { sed -i "s/$fixture_old/$fixture_elts/g" "$P2S_WORK/packages"; }
    p2s_package_sources_collect() { return 0; }
    p2s_november_apt_update
    printf 'UPDATE_RC=%s\n' "$?"
elif $fixture_install; then
    P2S_MODE=fix; P2S_BLOCKED=false
    p2s_backports_update_last
    printf 'UPDATE_RC=%s\n' "$?"
else
    p2s_fix_recommend_options
fi
if [ -r "$P2S_WORK/calls" ]; then cat "$P2S_WORK/calls"; fi
'''
        recommendation = 'fix_recommendation:beforefix|existing_provider|options=--fix|'
        out = self.freexian_candidate(settings, run=run)
        self.assertIn('php_branch_update:beforefix|php5.6|backports|configured_source', out)
        self.assertIn(recommendation, out)
        self.assertRegex(out, r'(?m)^SIMULATE:.* php5\.6-fpm:amd64=5\.6\.40-110\S+ '
                              r'php5\.6-json:amd64=5\.6\.40-110\S+ php7\.3-cli:amd64=7\.3\.31-1~deb10u7 php-cli=2:7\.3\+69$')
        for rejected in ('fixture_signer_ok=false', 'fixture_duplicate=true', 'fixture_candidate_api=phpapi-20200930'):
            with self.subTest(rejected=rejected):
                out = self.freexian_candidate(settings + rejected + '\n', run=run)
                self.assertNotIn(recommendation, out)
                self.assertNotIn('SIMULATE:', out)
        out = self.freexian_candidate(settings + 'fixture_install=true\n', run=run)
        self.assertIn('UPDATE_RC=0', out)
        simulation = next(line for line in out.splitlines() if line.startswith('SIMULATE:'))
        installation = next(line for line in out.splitlines() if line.startswith('INSTALL:'))
        self.assertEqual(simulation.split('install --only-upgrade ')[1], installation.split('install --only-upgrade ')[1])
        out = self.freexian_candidate(settings + 'fixture_install=true; fixture_default_install=true\n', run=run)
        self.assertIn('php_branch_update:beforefix|php5.6|backports|configured_source', out)
        self.assertIn('UPDATE_RC=0', out)
        self.assertEqual(out.count('\nINSTALL:'), 1)
        out = self.freexian_candidate(settings + 'fixture_install=true; fixture_preferred=true\n', run=run)
        self.assertIn('A preferred PHP update or repository repair is available.', out)
        self.assertIn('UPDATE_RC=1', out)
        self.assertNotIn('INSTALL:', out)

        ubuntu = r'''
P2S_DISTRO=ubuntu; P2S_RELEASE=20.04; P2S_MAJOR=20
fixture_name=php7.4-fpm; fixture_extension=php7.4-json
fixture_source=php7.4; fixture_installed_source=php7.4
fixture_old=7.4.3-4ubuntu2.29+esm5; fixture_elts=1:7.4.33-38+debsuryorg12.1+1+ubuntu20.04+animaa1
fixture_suite=focal; fixture_native_suite=focal; fixture_native=7.4.3-4ubuntu2.29+esm6
fixture_native_uri=https://esm.ubuntu.com/infra/ubuntu; fixture_native_priority=400
'''
        out = self.freexian_candidate(settings + ubuntu, run=r'''
P2S_BACKPORTS_ACTIVE=true
p2s_package_deb_candidate "$fixture_name" "$fixture_old" amd64 false Ubuntu
printf 'CANDIDATE_RC=%s\n' "$?"
''')
        self.assertIn('A preferred PHP security build is available for php7.4-fpm (7.4.3-4ubuntu2.29+esm6).', out)
        self.assertIn('CANDIDATE_RC=1', out)

    def test_freexian_recommendation_simulates_the_exact_branch_with_its_extensions(self):
        fixture = r'''
cp "$P2S_WORK/candidate-origins" "$P2S_WORK/fixture-origins"
printf '%s\n' "$fixture_name|$fixture_old|amd64|Debian" "$fixture_extension|$fixture_old|amd64|Debian" \
    'php-cli|2:7.3+69|all|Debian' > "$P2S_WORK/packages"
printf '%s\n' "$fixture_extension|$fixture_old|amd64|$fixture_installed_source|$fixture_old" >> "$P2S_WORK/deb-source-records"
printf '%s\n' "7.3.31|Y|command line||Debian|$fixture_old|Y|package|verified_affected_version_rule" > "$P2S_WORK/summary-versions"
printf '%s\n' unsupported_os > "$P2S_WORK/blocker-keys"
P2S_MODE=check; P2S_BLOCKED=true; P2S_STATE=Y; P2S_REPOSITORY_REFRESH=refreshed
p2s_freexian_signed_indexes() { P2S_FREEXIAN_SIGNED_SUITES=' buster-lts '; "$fixture_signer_ok"; }
p2s_repository_repair_assess() { return 1; }
p2s_fix_recommend_options
if [ -r "$P2S_WORK/calls" ]; then cat "$P2S_WORK/calls"; fi
'''
        out = self.freexian_candidate(run=fixture)
        self.assertIn('php_branch_update:beforefix|php7.3|freexian|configured_source', out)
        self.assertIn('fix_recommendation:beforefix|existing_provider|options=--fix|', out)
        self.assertRegex(out, r'(?m)^SIMULATE:.* php7\.3-cli:amd64=7\.3\.31-1~deb10u17 '
                              r'php7\.3-json:amd64=7\.3\.31-1~deb10u17 php-cli=2:7\.3\+69$')
        self.assertNotIn('dss:manifest:freexian_guidance:', out)
        self.assertNotIn('UNEXPECTED administrative command:', out)
        out = self.freexian_candidate('fixture_signer_ok=false', run=fixture)
        self.assertNotIn('fix_recommendation:beforefix|existing_provider|', out)
        self.assertIn('freexian_guidance:beforefix|extended_lts|buster|php7.3|administrator_review', out)
        self.assertNotIn('UNEXPECTED administrative command:', out)

    def test_buster_without_a_working_feed_shows_manual_guidance_for_both_php_branches(self):
        out = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10.13; P2S_MAJOR=10
P2S_BLOCKED=true; P2S_STATE=Y; P2S_REPOSITORY_REFRESH=failed
printf '%s\n' unsupported_os repositories > "$P2S_WORK/blocker-keys"
printf '%s\n' 'php7.3-cli|7.3.31-1~deb10u7|amd64|Debian' \
    'php5.6-fpm|5.6.40-29+0~20200514.35+debian10~1.gbp123abc|amd64|Debian' > "$P2S_WORK/packages"
printf '%s\n' '7.3.31|Y|command line||Debian|7.3.31-1~deb10u7|Y|package|verified_affected_version_rule' \
    '5.6.40|?|PHP-FPM||Sury/ondrej PHP (revision hint)|5.6.40-29+0~20200514.35+debian10~1.gbp123abc|Y|package|no_verified_vendor_rule_or_unrecognised_version' \
    '8.2.36|N|command line||Sury/ondrej PHP|8.2.36-3|N|package|verified_version_rule' > "$P2S_WORK/summary-versions"
p2s_repository_repair_assess() { return 1; }
p2s_package_deb_update() { printf 'UNEXPECTED administrative command\n'; return 1; }
p2s_fix_recommend_options
''', isolated_paths=True, isolated_sources=True)
        self.assertIn('dss:warn: Freexian Extended LTS publishes a November fix for native PHP 7.3 on Debian 10.', out)
        self.assertIn('dss:warn: The separate Freexian PHP LTS subscription lists PHP 5.6 for this OS.', out)
        self.assertIn('freexian_guidance:beforefix|php_lts|debian|10.13|PHP 5.6|exact_build_and_access_unverified', out)
        self.assertNotIn('PHP 8.2', out)
        self.assertNotIn('fix_recommendation:', out)
        self.assertNotIn('UNEXPECTED administrative command', out)

    def test_buster_can_attempt_configured_sources_for_multiple_php_branches(self):
        out = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10.13; P2S_MAJOR=10
P2S_STATE=Y; P2S_COUNT=1; P2S_ALLOW_FREEXIAN=false
printf '%s\n' 'php7.3-cli|7.3.31-1~deb10u7|amd64|Debian' > "$P2S_WORK/packages"
p2s_fix_check_distro_recipe
printf 'DEFAULT_RC=%s\n' "$?"
P2S_ALLOW_FREEXIAN=true
p2s_freexian_native_scope
printf 'ELTS_SCOPE_RC=%s\n' "$?"
printf '%s\n' 'php5.6-fpm|5.6.40-18+0~20191128.27+debian10~1.gbp123abc|amd64|Debian' >> "$P2S_WORK/packages"
p2s_fix_check_distro_recipe
printf 'MIXED_RC=%s\n' "$?"
P2S_NOVEMBER=false; P2S_ALLOW_FREEXIAN=false
p2s_fix_check_distro_recipe
printf 'OCTOBER_RC=%s\n' "$?"
''')
        self.assertIn('DEFAULT_RC=0', out)
        self.assertIn('ELTS_SCOPE_RC=0', out)
        self.assertIn('MIXED_RC=0', out)
        self.assertIn('OCTOBER_RC=1', out)
        self.assertIn('dss:manifest:blocker:beforefix|unsupported_os|', out)

    def test_one_backports_approval_covers_both_buster_branches(self):
        out = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10.13; P2S_MAJOR=10
P2S_MODE=check; P2S_STATE=Y; P2S_REPOSITORY_REFRESH=refreshed
cat > "$P2S_WORK/packages" <<'PACKAGES'
php5.6-fpm|5.6.40-105+0~20261022.135+debian10~1.gbp123abc|amd64|Debian
php7.4-cli|1:7.4.33-31+0~20261021.121+debian10~1.gbp123abc|amd64|Debian
PACKAGES
awk -F'|' '{split($1,n,"-"); print $1 "|" $2 "|" $3 "|" n[1] "|" $2}' "$P2S_WORK/packages" > "$P2S_WORK/deb-source-records"
p2s_package_deb_preflight() { return 0; }
p2s_package_deb_sury_trust_preflight() { return 0; }
p2s_package_deb_refresh_indexes() { return 0; }
p2s_november_apt_route() {
    [ "$P2S_MODE" = check ] && return 1
    printf 'INSTALL:%s:%s\n' "$1" "$(paste -sd, "$2")"
}
p2s_repository_sury_source_present() { return 0; }
p2s_repository_repair_assess() { return 1; }
p2s_backports_missing_components() { printf '%s\n' "$2"; }
p2s_backports_add_preflight() { return 0; }
p2s_disruptive_backports_add_repository() {
    printf 'ADD:%s:%s\n' "$*" "$(cut -d'|' -f1 "$P2S_WORK/apt-selected" | paste -sd, -)"
}
p2s_backports_scope_preferences_verified() { return 0; }
p2s_november_apt_update
P2S_MODE=fix; P2S_ALLOW_BACKPORTS_REPOSITORY=true; P2S_PHP_SOURCE_BRANCHES=php5.6
p2s_november_apt_update
printf 'EXPANDED_RC=%s\n' "$?"
P2S_BLOCKED=false; P2S_PHP_SOURCE_BRANCHES=php5.6,php7.4
p2s_november_apt_update
''', isolated_sources=True)
        self.assertEqual(out.count('source_add_scope:beforefix|debian_php_backports|php5.6,php7.4'), 1)
        self.assertIn('--add-debian-php-backports --php-source-branches=php5.6,php7.4', out)
        self.assertIn('EXPANDED_RC=1', out)
        self.assertIn('approval for php7.4', out)
        self.assertEqual(out.count('ADD:buster sury:php5.6-fpm,php7.4-cli'), 1)
        self.assertEqual(out.count('INSTALL:backports:php5.6,php7.4'), 1)

    def test_enterprise_linux_backports_match_only_reviewed_builds(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=rpm; P2S_DISTRO=rocky; P2S_MAJOR=9
vendor='Rocky Enterprise Software Foundation'
for build in 8.2.35-1.module+el9.9.0+40474+554e1069.0.1 8.3.36-1.module+el9.9.0+40475+972eba12.0.1 8.4.27-1.module+el9.9.0+40476+dc5d3092.0.1; do
    p2s_version_package_state php-common "0:$build" "$vendor" x86_64
    p2s_version_package_state php-cli "0:$build" "$vendor" aarch64
    p2s_version_package_state php-cli "0:$build" 'Other RPM publisher' x86_64
    p2s_version_package_state php-cli "0:$build.local" "$vendor" x86_64
done
p2s_version_package_state php-common 0:8.0.30-8.el9_8.1 "$vendor" x86_64
P2S_MAJOR=8
for build in 7.4.33-8.module+el8.10.0+40472+363a2c29.0.1 8.2.35-1.module+el8.10.0+40473+6f592aac.0.1; do
    p2s_version_package_state php-common "0:$build" "$vendor" x86_64
    p2s_version_package_state php-cli "0:$build" "$vendor" aarch64
done
P2S_DISTRO=almalinux
p2s_version_package_state php-common 0:7.4.33-9.module_el8.10.0+4385+9e3d9df0 AlmaLinux x86_64
p2s_version_package_state php-common 0:7.4.33-9.module_el8.10.0+4385+9e3d9df0 AlmaLinux aarch64
p2s_version_package_state php-common 0:7.4.33-8.module_el8.10.0+4379+4cffe92b.alma.1 AlmaLinux x86_64
P2S_MAJOR=9
p2s_version_package_state php-common 0:8.0.30-8.el9_8.alma.1 AlmaLinux x86_64
p2s_version_package_state php-common 0:8.0.30-8.el9_8.1 AlmaLinux x86_64
p2s_version_package_state php-common 0:8.0.30-8.el9_8.1.alma.1 AlmaLinux x86_64
p2s_version_package_state php-common 0:8.0.30-8.el9_8.1.alma.2 AlmaLinux x86_64
''')
        self.assertEqual(result.splitlines(), list('NN??NN??NN??YNNNNNNNYYN?'))

    def test_native_rpm_comparison_preserves_release_and_publisher(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=rpm; P2S_DISTRO=rocky; P2S_MAJOR=8
vendor='Rocky Enterprise Software Foundation'
p2s_command_run() {
    case "$2:$3:$4" in
        rpm:--eval:*"'7.4.33', '7.4.33'"*"'10.module+el8.10.0+40500+deadbeef', '8.module+el8.10.0+40472+363a2c29.0.1'"*) printf '1\n' ;;
        rpm:--eval:*"'8.module+el8.10.0+40450+deadbeef', '8.module+el8.10.0+40472+363a2c29.0.1'"*) printf '%s\n' -1 ;;
        *) printf 'UNEXPECTED version comparison: %s\n' "$*" >> "$P2S_WORK/unexpected"; return 97 ;;
    esac
}
for release in 9.module+el8.10.0+40479+a65e1b9e 10.module+el8.10.0+40500+deadbeef 8.module+el8.10.0+40450+deadbeef 10.module+el9.10.0+40500+deadbeef 10.module+el8.10.0+40500+deadbeef.local; do
    p2s_version_package_state php-fpm "0:7.4.33-$release" "$vendor" aarch64
done
p2s_version_package_state php-fpm 0:7.4.33-10.module+el8.10.0+40500+deadbeef 'Other RPM publisher' aarch64
test ! -f "$P2S_WORK/unexpected"
''')
        self.assertEqual(result.splitlines(), list('NN????'))

    def test_report_retains_affected_build_after_candidate_changes(self):
        result = self.shell(r'''
P2S_NOVEMBER=true
P2S_PHASE=afterfix; P2S_BACKEND=deb; P2S_DISTRO=ubuntu; P2S_RELEASE=24.04
printf '%s\n' 'php8.3-fpm|8.3.6-0ubuntu0.24.04.13|amd64|Ubuntu' > "$P2S_WORK/packages.before"
p2s_november_package_build_report php8.3-fpm 8.3.6-0ubuntu0.24.04.13 amd64 Ubuntu Y
p2s_november_package_build_report php8.3-fpm 8.3.6-0ubuntu0.24.04.15 amd64 Ubuntu '?'
''')
        self.assertIn('known_affected=8.3.6-0ubuntu0.24.04.13', result)
        self.assertIn('comparison=unchanged|state=Y', result)
        self.assertIn('is still on affected build', result)
        self.assertIn('comparison=changed|state=?', result)
        self.assertIn('November fixes still need verification', result)

    def test_sury_november_revision_formats(self):
        result = self.shell(r'''
for version in 5.6.40-110+debsuryorg12.1+1 8.2.36-2+debsuryorg12.1+php+1 8.3.37-2+0~deb.sury.org.1+debian12 8.4.28-2+0~deb.sury.org.1+ubuntu22.04 8.4.28-2+custom.sury.package; do
    if p2s_package_deb_is_sury "$version"; then printf 'accepted\n'; else printf 'rejected\n'; fi
done
''')
        self.assertEqual(result.splitlines(), ['accepted'] * 4 + ['rejected'])

    def test_legacy_sury_rule_requires_matching_release_architecture_and_source(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12.3
build=5.6.40-110+debsuryorg12.1+1
p2s_version_package_state php5.6-fpm "$build" Debian amd64 php5.6 "$build"
p2s_version_package_state php5.6-fpm "$build" Debian armhf php5.6 "$build"
p2s_version_package_state php5.6-fpm "$build" Debian ppc64el php5.6 "$build"
p2s_version_package_state php5.6-fpm "$build" Debian amd64 php5.6
p2s_version_package_state php5.6-fpm "$build" Debian amd64 php5.5 "$build"
P2S_RELEASE=13
p2s_version_package_state php5.6-fpm "$build" Debian amd64 php5.6 "$build"
build=1:7.4.33-37+debsuryorg13.1+php+1
p2s_version_package_state libapache2-mod-php7.4 "$build" Debian arm64 php7.4 "$build"
P2S_DISTRO=ubuntu; P2S_RELEASE=24.04
build=7.2.34-70+ubuntu24.04.1+deb.sury.org+1
p2s_version_package_state php7.2-cli "$build" Ubuntu ppc64el php7.2 "$build"
build=7.2.34-70+debsuryorg24.04.1+php+1
p2s_version_package_state php7.2-cli "$build" Ubuntu amd64 php7.2 "$build"
''')
        self.assertEqual(result.splitlines(), list('NN????NN?'))

    def test_current_and_later_sury_builds_in_both_repositories(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=deb
for platform in debian:12 debian:13.2 ubuntu:22.04 ubuntu:24.04 ubuntu:26.04; do
    P2S_DISTRO=${platform%:*}; P2S_RELEASE=${platform#*:}
    release=$P2S_RELEASE; [ "$P2S_DISTRO" != debian ] || release=${release%%.*}
    for spec in php5.6:5.6.40-110 php7.0:7.0.33-98 php7.1:7.1.33-86 php7.2:7.2.34-71 php7.3:7.3.33-42 php7.4:1:7.4.33-38 php8.0:1:8.0.30-32 php8.1:8.1.34-15; do
        name=${spec%%:*}; build=${spec#*:}+debsuryorg$release.1+1
        for arch in amd64 arm64 armhf; do
            p2s_version_package_state "$name-fpm" "$build" '' "$arch" "$name" "$build"
        done
    done
done
P2S_DISTRO=debian; P2S_RELEASE=13
for build in 7.3.33-43+debsuryorg13.1+2 7.3.33-41+debsuryorg13.1+php+1 7.3.33-41+debsuryorg13.1+1 7.3.33-43+debsuryorg12.1+1 7.3.33-43+custom+debsuryorg13.1+1 7.3.33-43+debsuryorg13.1+1.local 1:7.3.33-43+debsuryorg13.1+1; do
    p2s_version_package_state php7.3-cli "$build" '' amd64 php7.3 "$build"
done
build=7.3.33-43+debsuryorg13.1+2
p2s_version_package_state php7.3-cli "$build" '' amd64 php7.2 "$build"
p2s_version_package_state php7.3-cli "$build" '' amd64 php7.3 7.3.33-42+debsuryorg13.1+1
p2s_version_package_state php7.3-cli "$build" '' ppc64el php7.3 "$build"
P2S_DISTRO=ubuntu; P2S_RELEASE=24.04
build=7.3.33-42+ubuntu24.04.1+deb.sury.org+2
p2s_version_package_state php7.3-cli "$build" '' ppc64el php7.3 "$build"
''')
        self.assertEqual(result.splitlines(), ['N'] * (5 * 8 * 3) + list('NN????????N'))

    def test_legacy_panel_rpms_match_the_exact_build_and_publisher(self):
        result = self.shell(r'''
P2S_NOVEMBER=true; P2S_BACKEND=rpm; P2S_DISTRO=almalinux; P2S_MAJOR=8
p2s_version_package_state cpanel-php81 0:8.1.34-2.cp110~el8 '(none)' x86_64
p2s_version_package_state cpanel-php81 0:8.1.34-3.cp110~el8 '(none)' x86_64
p2s_version_package_state cpanel-php81 0:8.1.34-3.cp110~el8 '(none)' aarch64
p2s_version_package_state cpanel-php81 0:8.1.34-4.cp110~el8 '(none)' x86_64
p2s_version_package_state ea-php74-php-cli 0:7.4.34-3.3.1.cpanel 'cPanel, Inc.' x86_64
p2s_version_package_state ea-php74-php-fpm 0:7.4.34-2.2.3.cpanel 'cPanel, Inc.' x86_64
p2s_version_package_state ea-php74-php-cli 0:7.4.34-3.3.1.cpanel CloudLinux x86_64
P2S_DISTRO=cloudlinux
p2s_version_package_state ea-php80-php-cli 1:8.0.31-2.el8.cloudlinux.2 CloudLinux x86_64
p2s_version_package_state ea-php80-php-cli 1:8.0.31-2.el8.cloudlinux.1 CloudLinux x86_64
p2s_version_package_state ea-php80-php-cli 0:8.0.31-2.el8.cloudlinux.2 CloudLinux x86_64
p2s_version_package_state alt-php81-common 0:8.1.34-43.el8 CloudLinux x86_64
p2s_version_package_state alt-php81-common 0:8.1.34-43.el9 CloudLinux x86_64
P2S_MAJOR=9
p2s_version_package_state alt-php81-common 0:8.1.34-43.el9 CloudLinux x86_64
''')
        self.assertEqual(result.splitlines(), list('YN??NY?NY?N?N'))


if __name__ == '__main__':
    unittest.main()
