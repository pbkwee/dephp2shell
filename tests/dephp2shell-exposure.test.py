"""Manual shutdown suggestions use observed PHP services, never execute stops."""
from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class ExposureAdviceTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    setup = r'''
P2S_MODE=fix; P2S_STATE='?'
p2s_command_run() {
    if [ "$*" = '10 systemctl show php8.2-fpm.service -p TriggeredBy' ]; then
        printf 'TriggeredBy=php8.2-fpm.socket php-recheck.timer php-config.path\n'
    elif [ "$*" = '10 systemctl show apache2.service -p TriggeredBy' ]; then
        printf 'TriggeredBy=\n'
    else printf 'UNEXPECTED_COMMAND:%s\n' "$*"; return 97
    fi
}
'''

    def test_stop_only_after_unresolved_fix(self):
        for mode, state, expected in [('fix', 'Y', True), ('fix', '?', True),
                                      ('fix', 'N', False), ('check', 'Y', False),
                                      ('check', '?', False)]:
            with self.subTest(mode=mode, state=state):
                out = self.shell(self.setup + f"P2S_MODE={mode}; P2S_STATE='{state}'\n" + r'''
printf 'php8.2-fpm.service\n' > "$P2S_WORK/services"
p2s_fix_print_exposure_advice
''')
                self.assertEqual('To stop PHP served by' in out, expected)
                self.assertNotIn('UNEXPECTED_COMMAND', out)

    def test_exact_services_and_activation_triggers_are_printed_without_running_them(self):
        out = self.shell(self.setup + r'''
printf 'php8.2-fpm.service\napache2.service\nphp8.2-fpm.service\n' > "$P2S_WORK/services"
p2s_fix_print_exposure_advice
''')
        self.assertIn("run: sudo systemctl stop 'php8.2-fpm.socket' 'php-recheck.timer' 'php-config.path' 'php8.2-fpm.service'", out)
        self.assertIn("run: sudo systemctl stop 'apache2.service'", out)
        self.assertEqual(out.count('To stop PHP served by php8.2-fpm.service'), 1)
        self.assertIn('including non-PHP sites', out)
        self.assertIn('expose PHP source', out)
        self.assertIn('does not run them', out)
        self.assertNotIn('UNEXPECTED_COMMAND', out)

    def test_missing_trigger_evidence_is_explicit_and_unsafe_triggers_are_not_commands(self):
        for response in ["return 124", "printf 'TriggeredBy=bad;name.socket other.service\\n'", "printf ''"]:
            out = self.shell(self.setup + '\np2s_command_run() { ' + response + '; }\n' + r'''
printf 'php8.2-fpm.service\n' > "$P2S_WORK/services"
p2s_fix_print_exposure_advice
''')
            self.assertIn('Activation triggers for php8.2-fpm.service could not be fully checked', out)
            commands = [line for line in out.splitlines() if 'run: sudo' in line]
            self.assertEqual(commands, ["dss:warn: To stop PHP served by php8.2-fpm.service, run: sudo systemctl stop 'php8.2-fpm.service'"])

    def test_init_services_and_untrusted_names(self):
        for available in ('true', 'false'):
            out = self.shell(self.setup + f'available={available}\n' + r'''
p2s_command_exists() { [ "$1" = service ] && $available; }
printf '%s\n' init:php8.2-fpm 'php;evil.service' "php'evil.service" '-evil.service' 'init:-evil' > "$P2S_WORK/services"
p2s_fix_print_exposure_advice
''')
            command = "sudo service 'php8.2-fpm' stop" if available == 'true' else "sudo '/etc/init.d/php8.2-fpm' stop"
            self.assertIn('run: ' + command, out)
            self.assertNotIn('evil', out)
            self.assertNotIn('UNEXPECTED_COMMAND', out)

    def test_observed_fpm_template_can_be_stopped_without_an_automatic_restart_recipe(self):
        out = self.shell(self.setup + r'''
printf 'php-fpm|/usr/sbin/php-fpm|php-fpm@site.service\nphp-cgi|/usr/bin/php-cgi|supervisor.service\n' > "$P2S_WORK/unmapped-services"
p2s_command_run() { printf 'TriggeredBy=\n'; }
p2s_fix_print_exposure_advice
''')
        self.assertIn("run: sudo systemctl stop 'php-fpm@site.service'", out)
        self.assertNotIn("run: sudo systemctl stop 'supervisor.service'", out)
        self.assertIn('sudo supervisorctl stop PROGRAM', out)

    def test_unmapped_scheduled_and_separate_php_are_not_claimed_contained(self):
        out = self.shell(self.setup + r'''
printf 'php-cgi|/usr/bin/php-cgi|supervisor.service\n' > "$P2S_WORK/unmapped-services"
printf '1234|99|/usr/bin/php\n' > "$P2S_WORK/scheduled-php"
P2S_SEPARATE_ENVIRONMENT_REVIEW=true
p2s_fix_print_exposure_advice
''')
        self.assertIn('No verified PHP service stop command could be identified', out)
        self.assertIn('sudo supervisorctl status', out)
        self.assertIn('do not stop cron', out)
        self.assertIn('host service commands above do not stop that exposure', out)
        self.assertNotIn('run: sudo', out)
        self.assertNotIn('UNEXPECTED_COMMAND', out)


if __name__ == '__main__':
    unittest.main()
