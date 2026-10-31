"""Offline APT regressions for selector upgrades and pinned dependency plans.

Synthetic versions retain the captured PHP dependency shape. Sury unit tests
separately check the script's generated arguments; no customer fixtures are used.
"""
from pathlib import Path
import os
import re
import runpy
import shlex
import shutil
import subprocess
import tempfile
import unittest

DEPENDENCY_HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell-dependency-repair.test.py')))


class PinnedDependencyPlanTest(unittest.TestCase):
    shell = DEPENDENCY_HELPERS['DependencyRepairTest'].shell

    def test_only_unchanged_pinned_resimulation_reaches_installation(self):
        fixture = DEPENDENCY_HELPERS['DependencyRepairTest']().fixture().replace(
            'p2s_command_run() {', 'fixture_dependency_command() {')
        for scenario in ('unchanged', 'architecture', 'version', 'removal', 'unapproved'):
            with self.subTest(scenario=scenario):
                out = self.shell(fixture + '\nscenario=' + shlex.quote(scenario) + r'''
P2S_MODE=fix
cp "$P2S_WORK/candidate-origins" "$P2S_WORK/fixture-origins"
sed -i '1s/$/ []/; 2s/$/ [php8.2-cli:amd64 ]/' "$P2S_WORK/plan"
printf '%s\n' 'php is already the newest version (2:7.4+76).' >> "$P2S_WORK/plan"
printf '%s\n' "Use 'apt autoremove' to remove them." "Use 'apt-get autoremove' to remove them." >> "$P2S_WORK/plan"
p2s_command_exists() { case "$1" in apt-get|apt-cache|dpkg|apt-mark) return 0 ;; *) return 1 ;; esac; }
p2s_package_deb_candidate() { P2S_DEB_CANDIDATE=8.2.35-1; }
p2s_command_run() {
    local last
    for last in "$@"; do :; done
    case "$2" in
        apt-mark|dpkg) return 0 ;;
        dpkg-query) fixture_dependency_command "$@" ;;
        apt-cache)
            if [ "$last" = policy ]; then cat "$P2S_WORK/fixture-origins"; return 0; fi
            fixture_dependency_command "$@" ;;
        apt-get)
            case " $* " in
                *' update ') return 0 ;;
                *' -s '*)
                    printf '%s\n' "$*" >> "$P2S_WORK/simulations"
                    cp "$P2S_WORK/plan" "$P2S_WORK/current-plan"
                    case " $* " in
                        *' libxml2:amd64=2.9.15-1 '*)
                            case "$scenario" in
                                architecture) sed -i '2s/\[amd64\]/[arm64]/' "$P2S_WORK/current-plan" ;;
                                version) sed -i '2s/(2.9.15-1 /(2.9.16-1 /' "$P2S_WORK/current-plan" ;;
                                removal) printf 'Remv libold [1.0-1]\n' >> "$P2S_WORK/current-plan" ;;
                                unapproved) printf 'Inst libother [1.0-1] (2.0-1 Debian:12 [amd64]) []\n' >> "$P2S_WORK/current-plan" ;;
                            esac ;;
                    esac
                    cat "$P2S_WORK/current-plan" ;;
                *' install '*) printf 'INSTALLED %s\n' "$*" >> "$P2S_WORK/installations" ;;
                *) printf 'UNEXPECTED_APT_OPERATION\n'; return 97 ;;
            esac ;;
        *) printf 'UNEXPECTED_UPDATE_OPERATION\n'; return 97 ;;
    esac
}
p2s_package_deb_update
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
printf 'SIMULATIONS=%s\n' "$(wc -l < "$P2S_WORK/simulations")"
cat "$P2S_WORK/installations" 2>/dev/null
:
''')
                self.assertIn('SIMULATIONS=2', out)
                self.assertIn('dependency_approval:', out)
                self.assertNotIn('UNEXPECTED_', out)
                if scenario == 'unchanged':
                    self.assertIn('RC=0|BLOCKED=false', out)
                    self.assertRegex(out, r'INSTALLED .*php8\.2-cli:amd64=8\.2\.35-1 libxml2:amd64=2\.9\.15-1')
                else:
                    self.assertIn('RC=1|BLOCKED=true', out)
                    self.assertIn('pinned dependency simulation changed scope', out)
                    self.assertNotIn('INSTALLED', out)


@unittest.skipUnless(shutil.which('apt-get'), 'requires APT')
class AptSolverTest(unittest.TestCase):
    def test_freezing_other_php_packages_preserves_branch_and_auto_marks(self):
        with tempfile.TemporaryDirectory(prefix='dephp2shell-apt-solver-') as work:
            root = Path(work)
            for directory in ('etc/apt/apt.conf.d', 'etc/apt/sources.list.d',
                              'etc/apt/preferences.d', 'var/lib/dpkg',
                              'var/lib/apt/lists/partial', 'var/cache/apt/archives/partial',
                              'var/log/apt', 'empty-methods'):
                (root / directory).mkdir(parents=True)
            # APT queries the local file method even for simulations; no network methods exist.
            (root / 'empty-methods/file').symlink_to('/usr/lib/apt/methods/file')

            def package(name, version, dependencies='', source_version='1'):
                architecture = 'all' if name in ('php-common', 'php-xml') else 'amd64'
                return (f'Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n'
                        f'Filename: pool/{name}_{version}.deb\nSize: 1\n'
                        f'Description: synthetic PHP solver fixture\n'
                        + (f'Source: php-defaults ({source_version})\n'
                           if name in ('php-common', 'php-xml') else '')
                        + (f'Depends: {dependencies}\n' if dependencies else ''))

            installed = [
                package('php-common', '1'),
                package('php7.0-common', '7.0.1', 'php-common (>= 1)'),
                package('php7.0-json', '7.0.1', 'php7.0-common (= 7.0.1)'),
                package('php-xml', '1', 'php-common, php8.3-xml', source_version='0'),
                package('php8.3-xml', '8.3.1', 'php-common'),
            ]
            available = [
                package('php-common', '1'),
                package('php7.0-common', '7.0.2', 'php-common (>= 1)'),
                package('php7.0-json', '7.0.2', 'php7.0-common (= 7.0.2)'),
                package('php-xml', '2', 'php-common, php8.4-xml'),
                package('php8.3-xml', '8.3.1', 'php-common'),
                package('php8.4-common', '8.4.1', 'php-common'),
                package('php8.4-xml', '8.4.1', 'php8.4-common (= 8.4.1)'),
            ]
            (root / 'var/lib/dpkg/status').write_text(''.join(
                item + 'Status: install ok installed\n\n' for item in installed))
            (root / 'var/lib/apt/lists/_fixture_dists_test_main_binary-amd64_Packages').write_text(
                '\n'.join(available) + '\n')
            (root / 'etc/apt/sources.list').write_text(
                'deb [trusted=yes] file:/fixture test main\n')
            config = root / 'apt.conf'
            config.write_text(f'''
Dir "{root}";
Dir::State::status "{root}/var/lib/dpkg/status";
Dir::Etc::parts "{root}/etc/apt/apt.conf.d";
Dir::Etc::main "{root}/etc/apt/apt.conf";
Dir::Bin::dpkg "/bin/false";
Dir::Bin::methods "{root}/empty-methods";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
''')
            env = dict(os.environ, APT_CONFIG=str(config), LC_ALL='C')

            def apt(arguments):
                result = subprocess.run(['apt-get'] + arguments, env=env, text=True,
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout

            def changes(output):
                return re.findall(r'^Inst (\S+)', output, re.MULTILINE)

            apt(['-s', 'check'])
            selected = ['php7.0-common=7.0.2', 'php7.0-json=7.0.2']
            simulate = ['-s', '--no-install-recommends', '--no-remove',
                        'install', '--only-upgrade']
            # Visiting php-common also upgrades its php-defaults source siblings.
            self.assertIn('php8.4-common', changes(apt(simulate + selected)))
            frozen = ['php-common=1', 'php-xml=1', 'php8.3-xml=8.3.1']
            self.assertEqual(set(changes(apt(simulate + selected + frozen))),
                             {'php7.0-common', 'php7.0-json'})

            states = root / 'var/lib/apt/extended_states'
            auto = ''.join(f'Package: {item.splitlines()[0][9:]}\n'
                           'Architecture: amd64\nAuto-Installed: 1\n\n'
                           for item in installed)
            states.write_text(auto)
            current = ['php7.0-common=7.0.1', 'php7.0-json=7.0.1'] + frozen
            # This is a real no-op in isolated state; dpkg is denied even if it regresses.
            noop = ['--no-download', '--no-remove', '--assume-yes', 'install']
            output = apt(noop + ['--only-upgrade'] + current)
            self.assertIn('0 upgraded, 0 newly installed', output)
            self.assertEqual(states.read_text(), auto)
            # Positive control proves the auto-state file participates in the test.
            apt(noop + current)
            self.assertNotEqual(states.read_text(), auto)

            # A newer helper can conflict with a retained legacy selector without being needed by the engine.
            available.append(package('php-common', '2') + 'Breaks: php-xml (<< 2)\n')
            (root / 'var/lib/apt/lists/_fixture_dists_test_main_binary-amd64_Packages').write_text('\n'.join(available) + '\n')
            conflict = subprocess.run(['apt-get'] + simulate + selected +
                                      ['php-common=2', 'php-xml=1', 'php8.3-xml=8.3.1'],
                                      env=env, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn('Breaks:', conflict.stdout + conflict.stderr)
            self.assertEqual(set(changes(apt(simulate + selected + frozen))),
                             {'php7.0-common', 'php7.0-json'})


if __name__ == '__main__':
    unittest.main()
