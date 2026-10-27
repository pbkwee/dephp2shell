"""Offline terminal presentation tests with mocked inspection and capabilities."""
from pathlib import Path
import errno
import os
import pty
import re
import select
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'dephp2shell.sh'
if not SCRIPT.exists():
    SCRIPT = ROOT / 'scripts/serverpatch/dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')
RAW = ('dss:info: Checking PHP.\n'
       'dss:warn: Review PHP.\n'
       'dss:error: Unable to verify.\n'
       'dss:info: Result: Review required.\n'
       'dss:manifest:example:beforefix|evidence\n')
PLAIN = ('Checking PHP.\nWarning: Review PHP.\nError: Unable to verify.\n'
         'Result: Review required.\n')
ANSI = re.compile(r'\x1b\[[0-9;]*m')


class OutputStyleTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='dephp2shell-style-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_cli(self, *arguments, env=None, terminal=False):
        settings = dict(os.environ)
        for name in ('DP2S_OUTPUT', 'DP2S_LOG_DIR', 'DP2S_COLOR', 'DP2S_BOLD', 'NO_COLOR'):
            settings.pop(name, None)
        settings.update(HOME=str(self.root), TERM='xterm',
                        FIXTURE_ROOT=str(self.root), FIXTURE_CAPABILITIES='full')
        settings.update(env or {})
        body = r'''
source "$1"
shift
uname() { printf 'Linux\n'; }
p2s_main() {
    printf called > "$FIXTURE_ROOT/called"
    printf '%s\n' 'dss:info: Checking PHP.' 'dss:warn: Review PHP.' \
        'dss:error: Unable to verify.' 'dss:info: Result: Review required.' \
        'dss:manifest:example:beforefix|evidence'
}
p2s_command_exists() {
    if [ "$1" = tput ] && [ "$FIXTURE_CAPABILITIES" = missing ]; then return 1; fi
    command -v "$1" >/dev/null 2>&1
}
tput() {
    case "$TERM:$FIXTURE_CAPABILITIES" in unknown:*|*:missing|*:broken) return 1 ;; esac
    case "$1" in
        colors) if [ "$FIXTURE_CAPABILITIES" = fewcolors ]; then printf '4\n'; else printf '8\n'; fi ;;
        setaf) [ "$FIXTURE_CAPABILITIES" != nobasiccolor ] || return 1
            case "$2" in 1) printf '\033[31m' ;; 3) printf '\033[33m' ;; *) return 1 ;; esac ;;
        sgr0) [ "$FIXTURE_CAPABILITIES" != noreset ] || return 1; printf '\033[0m' ;;
        bold) [ "$FIXTURE_CAPABILITIES" != nobold ] || return 1; printf '\033[1m' ;;
        *) return 1 ;;
    esac
}
(p2s_cli "$@")
'''
        command = [BASH, '-c', body, 'fixture', str(SCRIPT), *arguments]
        if not terminal:
            return subprocess.run(command, cwd=self.root, env=settings,
                                  capture_output=True, text=True, timeout=8)
        master, slave = pty.openpty()
        process = subprocess.Popen(command, cwd=self.root, env=settings,
                                   stdout=slave, stderr=subprocess.PIPE)
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 8
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail('Terminal output did not finish')
                readable, _, _ = select.select([master], [], [], min(remaining, 0.2))
                if not readable:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            _, errors = process.communicate(timeout=2)
            return subprocess.CompletedProcess(command, process.returncode,
                                               output.decode().replace('\r\n', '\n'),
                                               errors.decode())
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)

    def assert_ok(self, run):
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def assert_plain(self, run):
        self.assert_ok(run)
        self.assertEqual(run.stdout, PLAIN)

    def test_pipe_defaults_to_plain_even_with_terminal_capabilities(self):
        self.assert_plain(self.run_cli())

    def test_terminal_auto_styles_labels_without_changing_message_text(self):
        run = self.run_cli(terminal=True)
        self.assert_ok(run)
        self.assertIn('\x1b[33m!\x1b[0m ', run.stdout)
        self.assertIn('\x1b[31m!\x1b[0m ', run.stdout)
        for label in ('Warning:', 'Error:', 'Result:'):
            self.assertIn('\x1b[1m' + label + '\x1b[0m', run.stdout)
        self.assertEqual(ANSI.sub('', run.stdout).replace('! ', ''), PLAIN)
        self.assertNotIn('\x1b[', run.stderr)

    def test_forced_style_works_through_pipe_and_only_colors_decorative_markers(self):
        run = self.run_cli('--color=always', '--bold', 'always',
                           env={'TERM': 'dumb', 'FIXTURE_CAPABILITIES': 'missing'})
        self.assert_ok(run)
        colored = re.findall(r'\x1b\[(?:31|33)m(.*?)\x1b\[39m', run.stdout)
        self.assertEqual(colored, ['!', '!'])
        codes = set(ANSI.findall(run.stdout))
        self.assertTrue(codes <= {'\x1b[31m', '\x1b[33m', '\x1b[39m',
                                 '\x1b[1m', '\x1b[22m'}, codes)
        self.assertIn('\x1b[1mResult:\x1b[22m', run.stdout)

    def test_aliases_disable_independent_styles(self):
        self.assert_plain(self.run_cli('--no-color', '--no-bold', terminal=True))
        bold_only = self.run_cli('--no-color', '--bold=always')
        self.assert_ok(bold_only)
        self.assertIn('\x1b[1mWarning:', bold_only.stdout)
        self.assertNotIn('! ', bold_only.stdout)
        color_only = self.run_cli('--color=always', '--no-bold')
        self.assert_ok(color_only)
        self.assertIn('\x1b[33m!\x1b[39m ', color_only.stdout)
        self.assertNotIn('\x1b[1m', color_only.stdout)

    def test_no_color_nonempty_overrides_environment_but_not_explicit_cli(self):
        settings = {'NO_COLOR': '1', 'DP2S_COLOR': 'always', 'DP2S_BOLD': 'never'}
        self.assert_plain(self.run_cli(env=settings, terminal=True))
        forced = self.run_cli('--color', 'always', env=settings)
        self.assert_ok(forced)
        self.assertIn('\x1b[33m', forced.stdout)
        empty = self.run_cli(env={'NO_COLOR': '', 'DP2S_COLOR': 'always',
                                  'DP2S_BOLD': 'never'})
        self.assert_ok(empty)
        self.assertIn('\x1b[33m', empty.stdout)

    def test_no_color_does_not_disable_bold(self):
        run = self.run_cli(env={'NO_COLOR': '1'}, terminal=True)
        self.assert_ok(run)
        self.assertIn('\x1b[1mWarning:', run.stdout)
        self.assertNotIn('! ', run.stdout)
        self.assertNotIn('\x1b[33m', run.stdout)

    def test_environment_styles_and_cli_precedence(self):
        self.assert_plain(self.run_cli('--color', 'never', '--bold=never',
                                      env={'DP2S_COLOR': 'always', 'DP2S_BOLD': 'always'}))
        forced = self.run_cli(env={'DP2S_COLOR': 'always', 'DP2S_BOLD': 'always'})
        self.assert_ok(forced)
        self.assertIn('\x1b[33m', forced.stdout)
        self.assertIn('\x1b[1mResult:', forced.stdout)

    def test_unsupported_terminals_and_missing_or_broken_capabilities_are_plain(self):
        for settings in ({'TERM': ''}, {'TERM': 'dumb'}, {'TERM': 'unknown'},
                         {'FIXTURE_CAPABILITIES': 'missing'},
                         {'FIXTURE_CAPABILITIES': 'broken'},
                         {'FIXTURE_CAPABILITIES': 'noreset'}):
            with self.subTest(settings=settings):
                self.assert_plain(self.run_cli(env=settings, terminal=True))

    def test_color_and_bold_capability_failures_are_independent(self):
        for capability in ('fewcolors', 'nobasiccolor'):
            with self.subTest(capability=capability):
                run = self.run_cli(env={'FIXTURE_CAPABILITIES': capability}, terminal=True)
                self.assert_ok(run)
                self.assertNotIn('! ', run.stdout)
                self.assertIn('\x1b[1mWarning:', run.stdout)
        run = self.run_cli(env={'FIXTURE_CAPABILITIES': 'nobold'}, terminal=True)
        self.assert_ok(run)
        self.assertIn('\x1b[33m!\x1b[0m ', run.stdout)
        self.assertNotIn('\x1b[1m', run.stdout)

    def test_invalid_style_options_do_not_create_logs_or_run_engine(self):
        cases = [(['--color'], {}), (['--bold'], {}), (['--color=bright'], {}),
                 (['--bold='], {}), ([], {'DP2S_COLOR': 'invalid'}),
                 ([], {'DP2S_BOLD': 'invalid'})]
        for arguments, settings in cases:
            with self.subTest(arguments=arguments, settings=settings):
                run = self.run_cli(*arguments, env=settings)
                self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                self.assertFalse((self.root / 'called').exists())
                self.assertFalse((self.root / 'dephp2shellinfo').exists())

    def test_machine_and_detailed_logs_are_raw_even_with_forced_styles(self):
        run = self.run_cli('--output=machine', '--color=always', '--bold=always')
        self.assert_ok(run)
        self.assertEqual(run.stdout, RAW)
        self.assertEqual(run.stderr, '')
        self.assertEqual(list(self.root.rglob('output.log')), [])
        logged = self.run_cli('--output=machine', '--color=always', '--bold=always',
                              '--log-dir', str(self.root / 'explicit logs'))
        self.assert_ok(logged)
        self.assertEqual(logged.stdout, RAW)
        human = self.run_cli('--color=always', '--bold=always')
        self.assert_ok(human)
        self.assertIn('\x1b[', human.stdout)
        logs = list(self.root.rglob('output.log'))
        self.assertEqual(len(logs), 2)
        for log in logs:
            self.assertEqual(log.read_text(), RAW)


if __name__ == '__main__':
    unittest.main()
