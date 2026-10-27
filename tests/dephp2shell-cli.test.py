"""Offline command-line and logging tests; inspection and updates are mocked."""
from pathlib import Path
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'dephp2shell.sh'
if not SCRIPT.exists():
    SCRIPT = ROOT / 'scripts/serverpatch/dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')
RAW = ('dss:info: Checking PHP.\n'
       'dss:manifest:example:beforefix|private evidence\n'
       'RET:HOSTNAME:example.invalid\n'
       'dss:warn: Review this installation.\n'
       'dss:isvulnerable:afterfix: CVE_2026_109618?\n')
ERROR = 'dss:error: A mocked diagnostic.\n'


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='dephp2shell-cli-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_cli(self, *arguments, env=None, setup=''):
        settings = dict(os.environ)
        settings.pop('DP2S_OUTPUT', None)
        settings.pop('DP2S_LOG_DIR', None)
        settings.pop('DP2S_COLOR', None)
        settings.pop('DP2S_BOLD', None)
        settings.pop('NO_COLOR', None)
        settings.update(HOME=str(self.root), FIXTURE_ROOT=str(self.root),
                        FIXTURE_STATUS='0')
        settings.update(env or {})
        body = r'''
source "$1"
shift
uname() { printf 'Linux\n'; }
p2s_main() {
    printf '%s\n' "$*" >> "$FIXTURE_ROOT/calls"
    printf '%s\n' 'dss:info: Checking PHP.' \
        'dss:manifest:example:beforefix|private evidence' \
        'RET:HOSTNAME:example.invalid' \
        'dss:warn: Review this installation.' \
        'dss:isvulnerable:afterfix: CVE_2026_109618?'
    printf '%s\n' 'dss:error: A mocked diagnostic.' >&2
    if [ "${FIXTURE_EXIT:-false}" = true ]; then exit "$FIXTURE_STATUS"; fi
    return "$FIXTURE_STATUS"
}
'''
        return subprocess.run([BASH, '-c', body + setup + '\n(p2s_cli "$@")',
                               'fixture', str(SCRIPT), *arguments],
                              cwd=self.root, env=settings, capture_output=True,
                              text=True, timeout=10)

    def logs(self):
        return list(self.root.rglob('output.log'))

    def assert_no_run(self):
        self.assertFalse((self.root / 'calls').exists())
        self.assertEqual(self.logs(), [])
        self.assertFalse((self.root / 'dephp2shellinfo').exists())

    def test_defaults_are_human_check_with_private_timestamped_raw_log(self):
        run = self.run_cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, 'Checking PHP.\nWarning: Review this installation.\n'
                         'Error: A mocked diagnostic.\n')
        self.assertEqual((self.root / 'calls').read_text(), '--check\n')
        log, = self.logs()
        self.assertEqual(log.read_text(), RAW + ERROR)
        self.assertEqual(log.parent.parent, self.root / 'dephp2shellinfo/runs')
        self.assertRegex(log.parent.name, r'^\d{8}T\d{6}Z\.[A-Za-z0-9.]+$')
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(log.parent.stat().st_mode), 0o700)
        self.assertEqual((log.parent / 'exit-status').read_text(), '0\n')
        self.assertIn(str(log), run.stderr)

    def test_machine_preserves_stdout_stderr_status_and_creates_no_logs(self):
        for action in ('--check', '--fix', '--check-vuln', '--fix-vuln'):
            with self.subTest(action=action):
                run = self.run_cli(action, '--output', 'machine',
                                   env={'FIXTURE_STATUS': '23'})
                self.assertEqual(run.returncode, 23, run.stderr)
                self.assertEqual(run.stdout, RAW)
                self.assertEqual(run.stderr, ERROR)
        self.assertEqual((self.root / 'calls').read_text().splitlines(),
                         ['--check', '--fix', '--check', '--fix'])
        self.assertEqual(self.logs(), [])
        self.assertFalse((self.root / 'dephp2shellinfo').exists())

    def test_environment_and_cli_precedence(self):
        log_root = self.root / 'environment logs'
        run = self.run_cli('--fix', '--output=human',
                           env={'DP2S_OUTPUT': 'machine', 'DP2S_LOG_DIR': str(log_root)})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn('dss:', run.stdout)
        log, = self.logs()
        self.assertEqual(log.parent.parent, log_root)
        self.assertEqual((self.root / 'calls').read_text(), '--fix\n')

    def test_cli_machine_overrides_human_environment_without_default_logs(self):
        run = self.run_cli('--output', 'machine', env={'DP2S_OUTPUT': 'human'})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, RAW)
        self.assertEqual(run.stderr, ERROR)
        self.assertEqual(self.logs(), [])

    def test_explicit_log_directory_accepts_spaces_and_leading_dash(self):
        run = self.run_cli('--output=machine', '--log-dir', '-private logs',
                           env={'DP2S_LOG_DIR': str(self.root / 'unused')})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, RAW + ERROR)
        log, = self.logs()
        self.assertEqual(log.parent.parent, self.root / '-private logs')
        self.assertFalse((self.root / 'unused').exists())

    def test_help_invalid_arguments_and_disruptive_never_start_engine(self):
        cases = [(['--help'], 0), (['-h'], 0), (['--unknown'], 64),
                 (['--output'], 64), (['--output=xml'], 64),
                 (['--log-dir'], 64), (['--log-dir='], 64),
                 (['--check', '--fix'], 64), (['--enable-extra-fixes'], 64),
                 (['--fix', '--enable-extra-fixes'], 64)]
        for arguments, status in cases:
            with self.subTest(arguments=arguments):
                run = self.run_cli(*arguments)
                self.assertEqual(run.returncode, status, run.stdout + run.stderr)
                self.assert_no_run()
        run = self.run_cli(env={'DP2S_OUTPUT': 'invalid'})
        self.assertEqual(run.returncode, 64)
        self.assert_no_run()

    def test_non_linux_platforms_exit_before_inventory_and_logs(self):
        for kernel in ('Darwin', 'FreeBSD', 'OpenBSD', 'NetBSD', 'SunOS', 'AIX',
                       'CYGWIN_NT-10.0', 'MINGW64_NT-10.0', 'MSYS_NT-10.0', ''):
            for action in ('--check', '--fix'):
                for output in ('human', 'machine'):
                    with self.subTest(kernel=kernel, action=action, output=output):
                        run = self.run_cli(action, '--output', output,
                                           '--log-dir', str(self.root / 'unused'),
                                           setup='uname() { printf "%s\\n" "' + kernel + '"; }')
                        self.assertEqual(run.returncode, 69, run.stdout + run.stderr)
                        self.assert_no_run()
                        self.assertFalse((self.root / 'unused').exists())
                        if output == 'human':
                            self.assertEqual(run.stdout, '')
                            self.assertIn('requires Linux', run.stderr)
                        else:
                            self.assertEqual(run.stderr, '')
                            self.assertIn('dss:error:', run.stdout)
                            self.assertIn('beforefix: CVE_2026_109618?', run.stdout)
                            self.assertIn('afterfix: CVE_2026_109618?', run.stdout)
                            self.assertNotIn('CVE_2026_109618N', run.stdout)

    def test_unavailable_platform_detection_exits_before_engine(self):
        run = self.run_cli('--fix', setup='uname() { return 1; }')
        self.assertEqual(run.returncode, 69, run.stdout + run.stderr)
        self.assertIn('requires Linux', run.stderr)
        self.assert_no_run()

    def test_help_does_not_require_platform_detection(self):
        run = self.run_cli('--help', setup='uname() { exit 97; }')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('Usage:', run.stdout)
        self.assert_no_run()

    def test_main_return_and_exit_failures_survive_successful_logging(self):
        for abrupt in ('false', 'true'):
            with self.subTest(abrupt=abrupt):
                run = self.run_cli(env={'FIXTURE_STATUS': '27', 'FIXTURE_EXIT': abrupt})
                self.assertEqual(run.returncode, 27, run.stderr)
        for log in self.logs():
            self.assertEqual((log.parent / 'exit-status').read_text(), '27\n')

    def test_logging_and_filter_failures_fail_without_masking_action_status(self):
        failures = [r'tee() { cat; return 19; }',
                    r'p2s_output_print_human() { cat > /dev/null; return 19; }']
        for setup in failures:
            for action_status in ('0', '29'):
                with self.subTest(setup=setup, action_status=action_status):
                    run = self.run_cli(setup=setup, env={'FIXTURE_STATUS': action_status})
                    self.assertEqual(run.returncode, int(action_status) or 1, run.stderr)
                    self.assertIn('could not be saved or displayed completely', run.stderr)

    def test_mkdir_fallback_keeps_log_private_when_mktemp_is_missing(self):
        setup = r'''
p2s_command_exists() {
    [ "$1" != mktemp ] && command -v "$1" > /dev/null 2>&1
}
'''
        run = self.run_cli(setup=setup)
        self.assertEqual(run.returncode, 0, run.stderr)
        log, = self.logs()
        self.assertEqual(stat.S_IMODE(log.parent.stat().st_mode), 0o700)
        self.assertEqual(log.read_text(), RAW + ERROR)

    def test_unterminated_human_message_is_not_lost(self):
        run = self.run_cli(setup=r'''p2s_main() { printf 'dss:warn: Last line'; }''')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, 'Warning: Last line\n')
        log, = self.logs()
        self.assertEqual(log.read_text(), 'dss:warn: Last line')

    def test_log_setup_failure_does_not_start_engine(self):
        blocked = self.root / 'not a directory'
        blocked.write_text('existing file')
        run = self.run_cli('--fix', '--log-dir', str(blocked))
        self.assertEqual(run.returncode, 1)
        self.assert_no_run()
        self.assertEqual(blocked.read_text(), 'existing file')

    def test_symlink_log_root_is_rejected_before_engine(self):
        target = self.root / 'target'
        target.mkdir()
        link = self.root / 'link'
        link.symlink_to(target, target_is_directory=True)
        run = self.run_cli('--fix', '--log-dir', str(link))
        self.assertEqual(run.returncode, 1)
        self.assert_no_run()
        self.assertEqual(list(target.iterdir()), [])

    def test_writable_log_roots_are_rejected_before_engine(self):
        for permissions in (0o777, 0o770):
            with self.subTest(permissions=oct(permissions)):
                log_root = self.root / ('unsafe-' + oct(permissions))
                log_root.mkdir()
                log_root.chmod(permissions)
                run = self.run_cli('--fix', '--log-dir', str(log_root))
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assert_no_run()
                self.assertEqual(list(log_root.iterdir()), [])
                self.assertEqual(stat.S_IMODE(log_root.stat().st_mode), permissions)

    def test_owned_private_or_readable_log_roots_are_accepted(self):
        for permissions in (0o700, 0o755):
            with self.subTest(permissions=oct(permissions)):
                log_root = self.root / ('safe-' + oct(permissions))
                log_root.mkdir()
                log_root.chmod(permissions)
                run = self.run_cli('--log-dir', str(log_root))
                self.assertEqual(run.returncode, 0, run.stderr)
                log, = log_root.rglob('output.log')
                self.assertEqual(log.read_text(), RAW + ERROR)
                self.assertEqual(stat.S_IMODE(log.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(log_root.stat().st_mode), permissions)

    def test_terminal_group_interrupts_do_not_leave_the_mock_action_running(self):
        for interruption in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(interruption=interruption):
                ready = self.root / ('ready-' + str(interruption))
                completed = self.root / ('completed-' + str(interruption))
                body = r'''
source "$1"
uname() { printf 'Linux\n'; }
# Keep marker paths in positional arguments for the mock, not the CLI.
fixture_ready=$2; fixture_completed=$3; fixture_python=$5
p2s_main() {
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Signal only after the blocking child has installed its handlers; no later fork/exec.
    "$fixture_python" -c 'import signal, sys, time; signal.signal(signal.SIGINT, signal.SIG_DFL); signal.signal(signal.SIGTERM, signal.SIG_DFL); open(sys.argv[1], "w").write("ready"); time.sleep(30)' "$fixture_ready"
    printf unexpected > "$fixture_completed"
}
(p2s_cli --log-dir "$4")
'''
                process = subprocess.Popen(
                    [BASH, '-c', body, 'fixture', str(SCRIPT), str(ready),
                     str(completed), str(self.root / 'signals'), sys.executable],
                    cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True)
                try:
                    deadline = time.monotonic() + 3
                    while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), 'Mock action did not start')
                    os.killpg(process.pid, interruption)
                    output, errors = process.communicate(timeout=3)
                    self.assertNotEqual(process.returncode, 0, output + errors)
                    self.assertFalse(completed.exists())
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=3)


if __name__ == '__main__':
    unittest.main()
