"""Bounded native APT dependency approval; no package/network/service mutation."""
from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class DependencyRepairTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def fixture(self, changes=''):
        return r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
P2S_DISRUPTIVE=true; P2S_ALLOW_PHP_DEPENDENCY_UPDATES=true
lib=libxml2; old=2.9.14-1; candidate=2.9.15-1; arch=amd64; installed_arch=amd64
source=libxml2; installed_source=libxml2; maintainer='Debian XML Team'
uri=https://deb.debian.org/debian; suite=bookworm; origin=Debian
normal_candidate=2.9.15-1; duplicate=false; dependency='libxml2 (>= 2.9.15)'
''' + changes + r'''
fixture_installed_source=$installed_source; fixture_maintainer=$maintainer; fixture_arch=$arch
printf '%s\n' 'php8.2-cli|8.2.35-1|amd64|php8.2-cli' > "$P2S_WORK/apt-approved"
printf '%s\n' 'php8.2-cli|8.2.29-1|amd64|Debian' > "$P2S_WORK/packages"
printf ' 500 %s %s/main amd64 Packages\n     release o=%s,n=%s,c=main,b=amd64\n' "$uri" "$suite" "$origin" "$suite" > "$P2S_WORK/candidate-origins"
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
                    if $duplicate; then printf '        500 https://foreign.invalid/repo bookworm/main amd64 Packages\n'; fi ;;
                *' show '*)
                    case "$last" in
                        php*) printf 'Package: php8.2-cli\nVersion: 8.2.35-1\nArchitecture: amd64\nDepends: %s\n' "$dependency" ;;
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
p2s_disruptive_php_dependency_approve_plan "$P2S_WORK/plan"
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

    def test_permissions_default_to_refusal(self):
        for changes in ('P2S_DISRUPTIVE=false', 'P2S_ALLOW_PHP_DEPENDENCY_UPDATES=false',
                        'unset P2S_ALLOW_PHP_DEPENDENCY_UPDATES', 'P2S_BACKEND=rpm',
                        'P2S_RELEASE=10'):
            with self.subTest(changes=changes):
                self.assertIn('RC=1', self.run_plan(changes))

    def test_unsafe_candidates_do_not_expand_approved_scope(self):
        cases = ('lib=libc6', 'lib=libssl3', 'lib=systemd', 'lib=libcurl4',
                 'candidate=2.9.13-1; normal_candidate=2.9.13-1',
                 'normal_candidate=2.9.16-1', 'duplicate=true', 'suite=trixie',
                 'origin=deb.sury.org', 'uri=https://packages.sury.org/php',
                 'source=libxml2-custom', 'installed_source=libxml2-custom',
                 'arch=arm64', 'installed_arch=arm64', 'maintainer=Unknown',
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
                     'UnexpectedAction libxml2'):
            with self.subTest(line=line):
                self.assertIn('RC=1', self.run_plan(before="printf '%s\\n' '" + line + "' >> \"$P2S_WORK/plan\"\n"))

    def test_transitive_required_native_library_is_approved(self):
        body = self.fixture()
        body = body.replace('    case "$2" in', r'''    case "$last" in
        libonig5|libonig5:amd64|libonig5:amd64=2.0-1)
            case "$2" in
                dpkg-query) printf 'install ok installed|libonig5|1.0-1|amd64|libonig|Debian Maintainers\n' ;;
                apt-cache)
                    case " $* " in
                        *' policy '*) printf 'libonig5:\n  Installed: 1.0-1\n  Candidate: 2.0-1\n  Version table:\n     2.0-1 500\n        500 https://deb.debian.org/debian bookworm/main amd64 Packages\n' ;;
                        *' show '*) printf 'Package: libonig5\nVersion: 2.0-1\nArchitecture: amd64\nSource: libonig\n' ;;
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
p2s_disruptive_php_dependency_approve_plan "$P2S_WORK/plan"
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
