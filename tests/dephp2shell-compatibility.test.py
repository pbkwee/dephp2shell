#!/usr/bin/env python3
"""Old-host fallbacks and process-group deadlines, using only harmless local fixtures."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')
AWK = os.environ.get('DP2S_TEST_AWK', 'awk')

class CompatibilityTest(unittest.TestCase):
    def test_process_module_patterns_on_old_awk(self):
        programs = re.findall(r"awk '([^']*libphp[^']*)'", SCRIPT.read_text())
        self.assertEqual(len(programs), 2)
        maps = ('1234 r-xp 0 0 0 /usr/lib/apache2/modules/libphp8.4.so (deleted)\n'
                '1235 r-xp 0 0 0 /usr/lib/libssl.so\n'
                '1236 r-xp 0 0 0 /libphp-directory/unrelated.so\n')
        for program in programs:
            with self.subTest(program=program):
                run = subprocess.run([AWK, program], input=maps, text=True,
                                     capture_output=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stderr, '')
                expected = ('PHP module loaded\n' if 'found=1' in program else
                            '/usr/lib/apache2/modules/libphp8.4.so (deleted)\n')
                self.assertEqual(run.stdout, expected)

    def shell(self, body, status=0, release_files=None):
        with tempfile.TemporaryDirectory(prefix='dephp2shell-compat-test-') as work:
            script = SCRIPT
            if release_files is not None:
                etc = Path(work) / 'etc'
                etc.mkdir()
                for name, content in release_files.items():
                    (etc / name).write_text(content)
                script = Path(work) / 'fixture.sh'
                script.write_text(SCRIPT.read_text().replace('/etc/', str(etc) + '/'))
            setup = 'source "$1"\nP2S_WORK="$2"; P2S_PHASE=beforefix\n'
            run = subprocess.run([BASH, '-c', setup + body, 'fixture', str(script), work],
                                 text=True, capture_output=True, timeout=40)
            self.assertEqual(run.returncode, status, run.stdout + run.stderr)
            return run.stdout, run.stderr

    def test_source_does_not_run_main_on_old_bash(self):
        out, err = self.shell("printf 'definitions only\\n'")
        self.assertEqual(out, 'definitions only\n')
        self.assertEqual(err, '')

    def test_standalone_help_on_old_bash(self):
        run = subprocess.run([BASH, str(SCRIPT), '--help'], text=True, capture_output=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('Usage:', run.stdout)
        self.assertNotIn('dss:manifest:', run.stdout)

    def test_distro_release_file_fallbacks(self):
        cases = [
            ({'redhat-release': 'Fedora release 10 (Cambridge)\n'}, 'fedora', '10'),
            ({'redhat-release': 'Fedora Core release 5 (Bordeaux)\n'}, 'fedora', '5'),
            ({'fedora-release': 'Fedora Core release 6 (Zod)\n'}, 'fedora', '6'),
            ({'fedora-release': 'Fedora release 12 (Constantine)\n',
              'redhat-release': 'CentOS release 5.11 (Final)\n'}, 'fedora', '12'),
            ({'os-release': 'ID=fedora\nVERSION_ID="43"\n',
              'fedora-release': 'Fedora release 10 (Cambridge)\n'}, 'fedora', '43'),
            ({'lsb-release': 'DISTRIB_ID=Fedora\nDISTRIB_RELEASE=7\n'}, 'fedora', '7'),
            ({'redhat-release': 'CentOS release 6.10 (Final)\n'}, 'centos', '6.10'),
            ({'redhat-release': 'Example release 10\n'}, 'unknown', '10'),
            ({}, 'unknown', 'unknown'),
        ]
        for files, distro, release in cases:
            with self.subTest(files=files):
                out, err = self.shell('p2s_distro_detect', release_files=files)
                self.assertIn('dss:manifest:distro:beforefix|' + distro + '|' + release + '|', out)
                self.assertIn('RET:DISTROINFO: ' + distro + ' ' + release + '\n', out)
                self.assertIn('dss:distroinfo: ' + distro + ' ' + release + '\n', out)
                self.assertEqual(err, '')

    def test_no_mktemp_uses_private_atomic_directory(self):
        out, err = self.shell("p2s_command_exists() { return 1; }; p2s_work_directory_create")
        directory = Path(out.strip())
        try:
            self.assertTrue(str(directory).startswith('/tmp/rh-dephp2shell.'))
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(err, '')
        finally:
            directory.rmdir()

    def test_no_timeout_or_perl_dispatches_to_embedded_watchdog(self):
        out, err = self.shell(r'''
p2s_command_exists() { [ "$1" = sleep ]; }
p2s_command_run_watchdog() { printf 'EMBEDDED:%s:%s\n' "$1" "$2"; }
p2s_command_run 5 fixture-command
''')
        self.assertEqual(out, 'EMBEDDED:5:fixture-command\n')
        self.assertEqual(err, '')

    def test_embedded_watchdog_preserves_ordinary_status(self):
        started = time.monotonic()
        out, err = self.shell("p2s_command_run_watchdog 5 /bin/sh -c 'printf fixture; exit 7'", status=7)
        self.assertEqual(out, 'fixture')
        self.assertEqual(err, '')
        self.assertLess(time.monotonic() - started, 4)

    def test_timeout_is_failure_even_if_term_handler_exits_zero(self):
        # Worker exits 0 on TERM, while its child ignores TERM. Both must be accounted for.
        out, err = self.shell(r'''
p2s_command_run_watchdog 1 /bin/sh -c '
    (trap "" TERM; exec sleep 30) &
    child=$!
    printf "%s\n" "$child" > "$1"
    trap "exit 0" TERM
    wait "$child"
' fixture "$P2S_WORK/child"
result=$?
child=$(cat "$P2S_WORK/child")
if [ -r "/proc/$child/stat" ]; then
    state=$(sed 's/.*) //' "/proc/$child/stat")
    case "$state" in Z*) ;; *) printf 'CHILD_STILL_RUNNING\n';; esac
fi
exit "$result"
''', status=124)
        self.assertNotIn('CHILD_STILL_RUNNING', out)
        self.assertEqual(err, '')

    def test_timeout_kills_term_ignoring_worker(self):
        out, err = self.shell("p2s_command_run_watchdog 1 /bin/sh -c 'trap \"\" TERM; exec sleep 30'", status=124)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

if __name__ == '__main__':
    unittest.main(verbosity=2)
