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
        self.assertEqual(result.splitlines(), list('YNYN?YN?Y?'))

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
p2s_version_package_state php8.1-fpm 8.1.2-1ubuntu2.29 "$vendor" amd64
P2S_RELEASE=20.04
p2s_version_package_state php7.4-fpm 7.4.3-4ubuntu2.29+esm6 "$vendor" amd64
''')
        self.assertEqual(result.splitlines(), list('YNYNYN??NY??'))

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
for version in 8.2.36-2+debsuryorg12.1+php+1 8.3.37-2+0~deb.sury.org.1+debian12 8.4.28-2+0~deb.sury.org.1+ubuntu22.04 8.4.28-2+custom.sury.package; do
    if p2s_package_deb_is_sury "$version"; then printf 'accepted\n'; else printf 'rejected\n'; fi
done
''')
        self.assertEqual(result.splitlines(), ['accepted'] * 3 + ['rejected'])


if __name__ == '__main__':
    unittest.main()
