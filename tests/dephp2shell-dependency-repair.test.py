"""Bounded APT dependency approval; no package/network/service mutation."""
from pathlib import Path
import runpy
import shlex
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class DependencyRepairTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def fixture(self, changes=''):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
P2S_DISRUPTIVE=false
lib=libxml2; old=2.9.14-1; candidate=2.9.15-1; arch=amd64; installed_arch=amd64
source=libxml2; installed_source=libxml2; maintainer='Debian XML Team'
uri=https://deb.debian.org/debian; suite=bookworm; origin=Debian
native_uri=https://security.debian.org/debian-security; native_suite=bookworm-security
native_origin=Debian; native_arch=amd64; installed_repo_version=
duplicate_installed=false; missing_native=false
installed_metadata_source=; installed_metadata_arch=; installed_metadata_version=
normal_candidate=2.9.15-1; duplicate=false; dependency='libxml2 (>= 2.9.15)'
''' + changes + r'''
installed_repo_version=${installed_repo_version:-$old}
fixture_installed_metadata_source=${installed_metadata_source:-$installed_source}
fixture_installed_metadata_arch=${installed_metadata_arch:-$installed_arch}
fixture_installed_metadata_version=${installed_metadata_version:-$old}
fixture_installed_source=$installed_source; fixture_maintainer=$maintainer; fixture_arch=$arch
printf '%s\n' 'php8.2-cli|8.2.35-1|amd64|php8.2-cli' > "$P2S_WORK/apt-approved"
printf '%s\n' 'php8.2-cli|8.2.29-1|amd64|Debian' > "$P2S_WORK/packages"
printf ' 500 %s %s/main amd64 Packages\n     release o=%s,n=%s,c=main,b=amd64\n' "$uri" "$suite" "$origin" "$suite" > "$P2S_WORK/candidate-origins"
printf ' 500 %s %s/main %s Packages\n     release o=%s,n=%s,c=main,b=%s\n' "$native_uri" "$native_suite" "$native_arch" "$native_origin" "$native_suite" "$native_arch" >> "$P2S_WORK/candidate-origins"
printf 'Inst php8.2-cli [8.2.29-1] (8.2.35-1 Debian:12 [amd64])\nInst %s [%s] (%s Debian:12 [%s])\n' "$lib" "$old" "$candidate" "$arch" > "$P2S_WORK/plan"
dpkg() { [ "$1" = --compare-versions ] || return 97; command dpkg "$@"; }
p2s_command_run() {
    local last
    for last in "$@"; do :; done
    case "$2" in
        dpkg-query) printf 'install ok installed|%s|%s|%s|%s|%s\n' "$lib" "$old" "$installed_arch" "$fixture_installed_source" "$fixture_maintainer" ;;
        apt-cache)
            case " $* " in
                *' policy '*)
                    printf '%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n     %s 500\n        500 %s %s/main amd64 Packages\n' "$lib" "$old" "$normal_candidate" "$candidate" "$uri" "$suite"
                    if $duplicate; then printf '        500 https://foreign.invalid/repo bookworm/main amd64 Packages\n'; fi
                    printf ' *** %s 500\n' "$installed_repo_version"
                    if ! $missing_native; then printf '        500 %s %s/main %s Packages\n' "$native_uri" "$native_suite" "$native_arch"; fi
                    if $duplicate_installed; then printf '        500 https://foreign.invalid/repo bookworm/main amd64 Packages\n'; fi
                    printf '        100 /var/lib/dpkg/status\n' ;;
                *' show '*)
                    case "$last" in
                        php*) printf 'Package: php8.2-cli\nVersion: 8.2.35-1\nArchitecture: amd64\nDepends: %s\n' "$dependency" ;;
                        *"=$old") printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSource: %s\n' "${lib%:*}" "$fixture_installed_metadata_version" "$fixture_installed_metadata_arch" "$fixture_installed_metadata_source" ;;
                        *) printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSource: %s\n' "${lib%:*}" "$candidate" "$fixture_arch" "$source" ;;
                    esac ;;
                *) return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED_DEPENDENCY_OPERATION\n'; return 97 ;;
    esac
}
'''

    def run_plan(self, changes='', before=''):
        return self.shell(self.fixture(changes) + before + r'''
p2s_package_deb_dependency_approve_plan "$P2S_WORK/plan"
printf 'RC=%s\n' "$?"
printf 'APPROVED\n'; cat "$P2S_WORK/apt-approved"
printf 'ARGUMENTS\n'; cat "$P2S_WORK/dependency-arguments" 2>/dev/null
:
''')

    def test_necessary_native_shared_library_is_pinned(self):
        out = self.run_plan()
        self.assertIn('RC=0', out)
        self.assertIn('libxml2|2.9.15-1|amd64|libxml2', out)
        self.assertIn('libxml2:amd64=2.9.15-1', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_required_pcre_upgrade_is_approved_without_extra_permissions(self):
        out = self.run_plan("lib=libpcre2-8-0; source=pcre2; installed_source=pcre2; "
                            "old=10.42-1; candidate=10.42-2; normal_candidate=10.42-2; "
                            "dependency='libpcre2-8-0 (>= 10.42-2)'")
        self.assertIn('RC=0', out)
        self.assertIn('libpcre2-8-0:amd64=10.42-2', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_already_current_unversioned_selectors_are_not_plan_actions(self):
        for name in ('php', 'php-cli', 'php-common', 'libapache2-mod-php'):
            with self.subTest(name=name):
                out = self.run_plan(before="printf '%s\\n' '" + name +
                                    " is already the newest version (2:7.4+76).' >> \"$P2S_WORK/plan\"\n")
                self.assertIn('RC=0', out)
                self.assertIn('libxml2:amd64=2.9.15-1', out)

    def test_apt_transient_broken_dependency_tails_are_not_architectures(self):
        for tail in (' []', ' [php7.4-cli:amd64 ]',
                     ' [php7.4-cli:amd64 libapache2-mod-php7.4:amd64 ]'):
            with self.subTest(tail=tail):
                out = self.run_plan(before="sed -i 's/$/" + tail + "/' \"$P2S_WORK/plan\"\n")
                self.assertIn('RC=0', out)
                self.assertIn('libxml2|2.9.15-1|amd64|libxml2', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_autoremove_advice_is_not_a_removal_action(self):
        for command, target in (('apt', 'it'), ('apt', 'them'), ('apt-get', 'it'), ('apt-get', 'them')):
            advice = "Use '" + command + " autoremove' to remove " + target + "."
            before = "printf '%s\\n' " + shlex.quote(advice) + ' >> "$P2S_WORK/plan"\n'
            with self.subTest(command=command, target=target):
                out = self.run_plan(before=before)
                self.assertIn('RC=0', out)
                self.assertIn('libxml2:amd64=2.9.15-1', out)
                self.assertNotIn('UNEXPECTED_', out)
            with self.subTest(command=command, target=target, removal=True):
                out = self.run_plan(before=before +
                                    "printf '%s\\n' 'Remv libold [1.0-1]' >> \"$P2S_WORK/plan\"\n")
                self.assertIn('RC=1', out)
                self.assertNotIn('dependency_approval:', out)

    def test_malformed_or_extended_autoremove_advice_is_refused(self):
        for advice in ("Use 'apt autoremove' to remove them. extra text",
                       "Use 'apt autoremove' to remove it. extra text",
                       "Use 'apt-get autoremove' to remove it. Remv libold [1.0-1]",
                       "Use 'apt-get autoremove' to remove them. Remv libold [1.0-1]",
                       "Use 'apt autoremove' to remove it",
                       "Use 'apt autoremove' to remove them", "Use apt autoremove to remove them.",
                       "Use 'apt --purge autoremove' to remove them."):
            with self.subTest(advice=advice):
                out = self.run_plan(before="printf '%s\\n' " + shlex.quote(advice) +
                                    ' >> "$P2S_WORK/plan"\n')
                self.assertIn('RC=1', out)
                self.assertNotIn('dependency_approval:', out)

    def sury_pcre(self, changes='', before=''):
        return self.run_plan('''
P2S_SURY_MIGRATION_ACTIVE=true; P2S_RELEASE=11
lib=libpcre2-8-0; source=pcre2; installed_source=pcre2
old=10.36-2+deb11u1; candidate=10.40-1+0~20220713.16+debian11~1.gbpb6cec5
normal_candidate=$candidate; dependency='libpcre2-8-0 (>= 10.38)'
uri=https://packages.sury.org/php; suite=bullseye; origin=deb.sury.org
native_suite=bullseye-security
maintainer='Matthew Vernon <matthew@debian.org>'
''' + changes, before='''
sed -i 's/php8.2-cli/php7.4-cli/g' "$P2S_WORK/apt-approved" "$P2S_WORK/packages" "$P2S_WORK/plan"
''' + before)

    def test_explicit_debian11_sury_migration_approves_necessary_pcre(self):
        out = self.sury_pcre()
        self.assertIn('RC=0', out)
        self.assertIn('libpcre2-8-0|10.40-1+0~20220713.16+debian11~1.gbpb6cec5|amd64|libpcre2-8-0', out)
        self.assertIn('libpcre2-8-0:amd64=10.40-1+0~20220713.16+debian11~1.gbpb6cec5', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_sury_pcre_exception_stays_bounded(self):
        for changes in ('P2S_SURY_MIGRATION_ACTIVE=false', 'unset P2S_SURY_MIGRATION_ACTIVE',
                        'P2S_BACKEND=rpm',
                        'P2S_RELEASE=12', 'P2S_DISTRO=ubuntu; P2S_RELEASE=22.04',
                        'arch=arm64', 'installed_arch=arm64', 'source=pcre2-custom',
                        'installed_source=pcre2-custom', 'duplicate=true', 'suite=bookworm',
                        'origin=Debian', 'uri=https://foreign.invalid/php',
                        "lib=libxml2; source=libxml2; installed_source=libxml2; dependency='libxml2 (>= 10.38)'",
                        "dependency='libpcre2-8-0 (>= 10.36)'",
                        "dependency='libpcre2-8-0 (>= 10.38) | libother'"):
            with self.subTest(changes=changes):
                out = self.sury_pcre(changes)
                self.assertIn('RC=1', out)
                approved = out.split('APPROVED\n')[1].split('ARGUMENTS')[0]
                self.assertNotIn('libpcre2-8-0|', approved)
                self.assertNotIn('UNEXPECTED_', out)

    def test_native_version_proof_does_not_depend_on_maintainer_branding(self):
        for maintainer in ('Matthew Vernon <matthew@debian.org>', 'Unknown'):
            with self.subTest(maintainer=maintainer):
                out = self.run_plan("maintainer='" + maintainer + "'")
                self.assertIn('RC=0', out)
                self.assertIn('libxml2:amd64=2.9.15-1', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_installed_version_needs_exclusive_matching_native_index_proof(self):
        for changes in ('missing_native=true', 'installed_repo_version=1.0-1',
                        'native_uri=https://foreign.invalid/repo',
                        'native_suite=trixie-security', 'native_origin=Foreign',
                        'native_arch=arm64', 'duplicate_installed=true',
                        'installed_metadata_source=custom', 'installed_metadata_arch=arm64',
                        'installed_metadata_version=1.0-1'):
            with self.subTest(changes=changes):
                for migration in (False, True):
                    with self.subTest(migration=migration):
                        out = self.sury_pcre(changes) if migration else self.run_plan(changes)
                        self.assertIn('RC=1', out)
                        self.assertNotIn('dependency_approval:', out)
                        self.assertNotIn('UNEXPECTED_', out)

    def test_unsupported_platforms_are_refused(self):
        for changes in ('P2S_BACKEND=rpm', 'P2S_RELEASE=10'):
            with self.subTest(changes=changes):
                self.assertIn('RC=1', self.run_plan(changes))

    def test_held_libraries_are_refused(self):
        for name in ('libxml2', 'libxml2:amd64'):
            with self.subTest(name=name):
                out = self.run_plan(before='printf "%s\\n" ' + name + ' > "$P2S_WORK/holds"\n')
                self.assertIn('RC=1', out)
                self.assertIn('held_package', out)
                self.assertNotIn('dependency_approval:', out)

    def test_unsafe_candidates_do_not_expand_approved_scope(self):
        cases = ('lib=libc6', 'lib=libssl3', 'lib=systemd', 'lib=libcurl4',
                 'candidate=2.9.13-1; normal_candidate=2.9.13-1',
                 'normal_candidate=2.9.16-1', 'duplicate=true', 'suite=trixie',
                 'origin=deb.sury.org', 'uri=https://packages.sury.org/php',
                 'source=libxml2-custom', 'installed_source=libxml2-custom',
                 'arch=arm64', 'installed_arch=arm64',
                 'old=2.9.14+0~20261021-1')
        for changes in cases:
            with self.subTest(changes=changes):
                out = self.run_plan(changes)
                self.assertIn('RC=1', out)
                self.assertNotIn('libxml2|2.9.15-1|amd64|libxml2', out.split('APPROVED\n')[1].split('ARGUMENTS')[0])

    def test_unnecessary_or_ambiguous_dependency_upgrade_is_refused(self):
        for dep in ('libxml2', 'libxml2 (>= 2.9.12)', 'libxml2 (>= 2.9.15) | libother',
                    'libother (>= 2.9.15)', 'libxml2 (>= 2.9.99)'):
            with self.subTest(dep=dep):
                self.assertIn('RC=1', self.run_plan("dependency='" + dep + "'"))

    def test_removals_additions_and_unknown_install_format_are_refused(self):
        for line in ('Remv libold [1.0-1]', 'Purg libold [1.0-1]',
                     'Inst libnew (1.0-1 Debian:12 [amd64])',
                     'Inst libxml2 [2.9.14-1] unsupported-output',
                     'E: Broken packages', 'W: Failed to fetch',
                     'php is already the newest version (2:7.4+76). extra-output',
                     'UnexpectedAction libxml2'):
            with self.subTest(line=line):
                self.assertIn('RC=1', self.run_plan(before="printf '%s\\n' '" + line + "' >> \"$P2S_WORK/plan\"\n"))

    def test_malformed_transient_dependency_tails_are_refused(self):
        for tail in (' [php7.4-cli:amd64', ' [php7.4-cli:amd64 ] garbage',
                     ' [[php7.4-cli:amd64 ]]', ' [php7.4-cli:amd64; ]',
                     ' [] []'):
            with self.subTest(tail=tail):
                self.assertIn('RC=1', self.run_plan(
                    before="printf '%s\\n' 'Inst libxml2 [2.9.14-1] (2.9.15-1 Debian:12 [amd64])" +
                    tail + "' >> \"$P2S_WORK/plan\"\n"))

    def test_transitive_required_native_library_is_approved(self):
        body = self.fixture()
        body = body.replace('    case "$2" in', r'''    case "$last" in
        libonig5|libonig5:amd64|libonig5:amd64=1.0-1|libonig5:amd64=2.0-1)
            case "$2" in
                dpkg-query) printf 'install ok installed|libonig5|1.0-1|amd64|libonig|Debian Maintainers\n' ;;
                apt-cache)
                    case " $* " in
                        *' policy '*) printf 'libonig5:\n  Installed: 1.0-1\n  Candidate: 2.0-1\n  Version table:\n     2.0-1 500\n        500 https://deb.debian.org/debian bookworm/main amd64 Packages\n *** 1.0-1 500\n        500 https://security.debian.org/debian-security bookworm-security/main amd64 Packages\n        100 /var/lib/dpkg/status\n' ;;
                        *' show '*) printf 'Package: libonig5\nVersion: %s\nArchitecture: amd64\nSource: libonig\n' "${last##*=}" ;;
                        *) return 97 ;;
                    esac ;;
                *) return 97 ;;
            esac
            return 0 ;;
    esac
    case "$2" in''')
        body = body.replace('"$fixture_arch" "$source" ;;', '"$fixture_arch" "$source"; printf "Depends: libonig5 (>= 2.0)\\n" ;;')
        out = self.shell(body + r'''
printf 'Inst libonig5 [1.0-1] (2.0-1 Debian:12 [amd64])\n' >> "$P2S_WORK/plan"
p2s_package_deb_dependency_approve_plan "$P2S_WORK/plan"
printf 'RC=%s\n' "$?"
cat "$P2S_WORK/apt-approved"
''')
        self.assertIn('RC=0', out)
        self.assertIn('libxml2|2.9.15-1|amd64|libxml2', out)
        self.assertIn('libonig5|2.0-1|amd64|libonig5', out)

    def test_no_extra_packages_needs_no_metadata_queries(self):
        out = self.run_plan(before='sed -n \'1p\' "$P2S_WORK/plan" > "$P2S_WORK/only-php"\nmv "$P2S_WORK/only-php" "$P2S_WORK/plan"\n')
        self.assertIn('RC=0', out)
        self.assertNotIn('dependency_approval:', out)


if __name__ == '__main__':
    unittest.main()
