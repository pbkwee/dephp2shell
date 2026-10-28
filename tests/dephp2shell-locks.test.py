'''Offline package-lock warnings against synthetic metadata and a private POSIX lock.'''
import fcntl
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')
TEXT = SCRIPT.read_text()
FUNCTION = 'p2s_package_lock_warn'
MATCH = re.search(r'^(?:function )?' + FUNCTION + r'\(\) \{\n.*?^}\n', TEXT, re.M | re.S)
assert MATCH, FUNCTION


class PackageLockWarnings(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='package-lock-warning-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / 'var/lib/apt/lists/lock'
        self.lock.parent.mkdir(parents=True)
        self.lock.write_text('persistent lock file\n')
        self.proc = self.root / 'proc/locks'
        self.proc.parent.mkdir()
        self.proc.write_text('')
        info = self.lock.stat()
        self.identity = '%02x:%02x:%s' % (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        self.definitions = MATCH.group()
        for prefix in ('/proc/', '/var/'):
            self.definitions = self.definitions.replace(prefix, str(self.root) + prefix)

    def locks(self, record=None):
        self.proc.write_text(record or ('12: POSIX ADVISORY WRITE 4242 ' + self.identity + ' 0 EOF\n'))

    def run_warning(self, elapsed='35-02:03:04', extra='', command='apt-get'):
        mocks = r'''
p2s_command_run() { shift; "$@"; }
manifest_run_bounded() { shift; "$@"; }
p2s_manifest_record() { printf 'record:%s|%s\n' "$1" "$2"; }
p2s_message_print() { printf 'dss:%s: %s\n' "$1" "$2" >&2; }
awk() { command "$fixture_awk" "$@"; }
ps() { printf '99 %s %s\n' "$fixture_elapsed" "$fixture_command"; }
kill() { printf 'UNEXPECTED signal\n' >&2; return 99; }
rm() { printf 'UNEXPECTED deletion\n' >&2; return 99; }
apt-get() { printf 'UNEXPECTED package operation\n' >&2; return 99; }
dpkg() { printf 'UNEXPECTED package operation\n' >&2; return 99; }
'''
        result = subprocess.run([BASH, '--noprofile', '--norc', '-c',
                                 self.definitions + mocks + extra + '\n' + FUNCTION + '\n'],
                                cwd=self.root, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                                   'fixture_elapsed': elapsed, 'fixture_command': command,
                                                   'fixture_awk': os.environ.get('DP2S_TEST_AWK', 'awk')},
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('UNEXPECTED', result.stdout + result.stderr)
        self.assertEqual(self.lock.read_text(), 'persistent lock file\n')
        return result.stdout + result.stderr

    def test_old_owner_reports_identity_and_reviewed_term_command(self):
        self.locks()
        output = self.run_warning()
        self.assertIn('PID 4242 (apt-get, parent 99)', output)
        self.assertIn('running for 35-02:03:04', output)
        self.assertIn('Lock acquisition time is unavailable', output)
        self.assertIn('Check its progress before stopping it', output)
        self.assertIn('kill -TERM 4242', output)
        self.assertIn('packages unfinished', output)
        self.assertNotIn('kill -KILL', output)

    def test_threshold_and_legacy_ps_elapsed_formats(self):
        self.locks()
        for elapsed, warns in [('59:59', False), ('00:59:59', False), ('01:00:00', True),
                               ('1-00:00:00', True), ('125:00', True), ('garbage', False), ('', False)]:
            with self.subTest(elapsed=elapsed):
                self.assertEqual('kill -TERM 4242' in self.run_warning(elapsed), warns)

    def test_file_without_kernel_lock_and_open_descriptor_are_ignored(self):
        with self.lock.open():
            self.assertEqual(self.run_warning(), '')

    def test_waiters_read_locks_unrelated_devices_and_unknown_owners_are_ignored(self):
        for record in [
            '12: -> POSIX ADVISORY WRITE 4242 ' + self.identity + ' 0 EOF\n',
            '12: POSIX ADVISORY READ 4242 ' + self.identity + ' 0 EOF\n',
            '12: POSIX ADVISORY WRITE 4242 ff:ff:999999 0 EOF\n',
            '12: OFDLCK ADVISORY WRITE -1 ' + self.identity + ' 0 EOF\n',
            '12: POSIX ADVISORY WRITE not-a-pid ' + self.identity + ' 0 EOF\n',
            '12: POSIX ADVISORY WRITE 1 ' + self.identity + ' 0 EOF\n',
        ]:
            with self.subTest(record=record):
                self.locks(record)
                self.assertEqual(self.run_warning(), '')

    def test_missing_probes_or_exited_owner_leave_operation_status_unchanged(self):
        self.locks()
        for extra in ['stat() { return 1; }', 'stat() { echo malformed; }',
                      'ps() { return 1; }', 'ps() { echo malformed; }']:
            with self.subTest(extra=extra):
                self.assertEqual(self.run_warning(extra=extra), '')
        self.proc.unlink()
        self.assertEqual(self.run_warning(), '')

    def test_repeat_probe_suppresses_duplicate_warning(self):
        self.locks()
        output = self.run_warning(extra=FUNCTION + '\n')
        self.assertEqual(output.count('kill -TERM 4242'), 1)

    def test_multiple_owners_are_reported_and_process_arguments_are_not_queried(self):
        self.locks('12: POSIX ADVISORY WRITE 4242 ' + self.identity + ' 0 10\n' +
                   '13: POSIX ADVISORY WRITE 4243 ' + self.identity + ' 11 EOF\n')
        output = self.run_warning()
        self.assertIn('kill -TERM 4242', output)
        self.assertIn('kill -TERM 4243', output)
        for field in ('args=', 'cmd=', 'command='):
            self.assertNotIn('-o ' + field, self.definitions)

    def test_real_private_posix_lock_matches_stat_device_and_inode(self):
        with self.lock.open('r+') as handle:
            fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Keep only this fixture's real kernel record; no host package operations.
            self.proc.write_text(''.join(line for line in Path('/proc/locks').read_text().splitlines(True)
                                         if self.identity in line and str(os.getpid()) in line.split()))
            output = self.run_warning()
            self.assertIn('kill -TERM ' + str(os.getpid()), output)

    def test_warning_precedes_package_lock_requests(self):
        fix = re.search(r'^p2s_fix_run\(\) \{\n.*?^}\n', TEXT, re.M | re.S).group()
        self.assertLess(fix.index(FUNCTION), fix.index('p2s_package_lock_wait'))
        main = TEXT[TEXT.index('p2s_main() {'):]
        self.assertLess(main.index(FUNCTION), main.index('mkdir /var/run/rh-php2shell.lock'))


if __name__ == '__main__':
    unittest.main()
