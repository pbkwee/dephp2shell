"""Offline tests of the shipped PHP2Shell functions; no package/service operations.

Run: python3 rimuhosting/test/dephp2shell.test.py
Set DP2S_TEST_BASH to an older Bash binary to repeat compatibility fixtures.
All administrative entry points are replaced with fixture functions before use.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'dephp2shell.sh'
BASH = os.environ.get('DP2S_TEST_BASH', '/bin/bash')


class PHP2ShellTest(unittest.TestCase):
    def shell(self, body, status=0, isolated_paths=False, isolated_sources=False):
        with tempfile.TemporaryDirectory(prefix='dephp2shell-test-') as work:
            script = SCRIPT
            if isolated_paths or isolated_sources:
                # Only fixture copies are changed; production source remains untouched.
                script = Path(work) / 'fixture.sh'
                source = SCRIPT.read_text()
                for prefix in (('/usr/', '/opt/', '/proc/') if isolated_paths else ()) + (('/etc/', '/var/') if isolated_sources else ()):
                    source = source.replace(prefix, work + prefix)
                script.write_text(source)
            setup = '''
source "$1"
P2S_WORK="$2"; P2S_PHASE=beforefix; P2S_BLOCKED=false
P2S_UNKNOWN=false; P2S_COUNT=0; P2S_VULNERABLE=false; P2S_RESTART_PENDING=false; P2S_FIX_FAILED=false
# Deny every actual package/network/service call, including accidental new paths.
p2s_command_run() { printf 'UNEXPECTED administrative command: %s\\n' "$*" >&2; return 97; }
# Listener observations are exercised with isolated /proc fixtures in the runtime suite.
p2s_web_listener_inventory_collect() { :; }
apt-get() { return 97; }; yum() { return 97; }; dnf() { return 97; }
timeout() { [ \"$1\" = --help ] && printf '%s\\n' --kill-after; };
systemctl() { return 97; }; service() { return 97; }; rpm() { return 97; }
'''
            run = subprocess.run([BASH, '-c', setup + body, 'fixture', str(script), work],
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, status, run.stdout + run.stderr)
            self.assertNotIn('UNEXPECTED administrative command:', run.stderr)
            return run.stdout

    def test_failed_apt_policy_keeps_error_without_repository_credentials(self):
        out = self.shell(r'''
p2s_command_exists() { [ "$1" = apt-cache ]; }
p2s_command_run() { printf 'E: failed https://login:private-token@repo.invalid/private-path\n' >&2; return 1; }
p2s_package_deb_policy_collect php8.2-cli
''')
        self.assertIn('apt_policy_error:beforefix|E: failed [repository host=repo.invalid; path redacted]', out)
        self.assertIn('APT package policy unavailable', out)
        self.assertNotIn('private-token', out)
        self.assertNotIn('private-path', out)

    def test_failed_candidate_query_keeps_operation_exit_and_redacted_error(self):
        out = self.shell(r'''
p2s_command_run() { printf 'E: failed https://login:private-token@repo.invalid/private-path\n' >&2; return 124; }
p2s_package_deb_candidate php8.2-cli 8.2.29-1 amd64 false
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
''')
        self.assertIn('apt_candidate_error:beforefix|php8.2-cli|operation=policy|exit=124', out)
        self.assertIn('E: failed [repository host=repo.invalid; path redacted]', out)
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertNotIn('private-token', out)
        self.assertNotIn('private-path', out)

    def test_audit_context_distinguishes_installed_metadata_and_pending_packages(self):
        for scenario in ('metadata', 'pending_only'):
            with self.subTest(scenario=scenario):
                out = self.shell('scenario=' + scenario + r'''
mkdir -p "$P2S_WORK/var/lib/dpkg/info"
touch "$P2S_WORK/var/lib/dpkg/info/libfixture.list" "$P2S_WORK/var/lib/dpkg/info/php8.2-fpm:amd64.md5sums"
p2s_command_exists() { [ "$1" = apt-get ] || [ "$1" = dpkg-query ]; }
p2s_command_run() {
    case "$2" in
        dpkg)
            if [ "$scenario" = metadata ]; then
                printf 'The following packages are missing the md5sums control file:\n libfixture  Fixture library\n'
            else printf 'dpkg: audit failed\n' >&2; return 1; fi ;;
        dpkg-query)
            printf '%s\n' 'libfixture|1.0-1|amd64|install ok installed' \
                'php8.2-fpm|8.2.29-1|amd64|install ok unpacked' \
                'php8.2-cli|8.2.29-1|amd64|install ok installed' \
                'removed-lib|1.0-1|amd64|deinstall ok config-files' ;;
        *) printf 'UNEXPECTED_DIAGNOSTIC\n'; return 97 ;;
    esac
}
p2s_package_deb_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
''', isolated_sources=True)
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertIn('package_audit_status:beforefix|php8.2-fpm|8.2.29-1|amd64|install ok unpacked', out)
                self.assertIn('php8.2-fpm|list=missing_or_unreadable|md5sums=readable', out)
                self.assertNotIn('package_audit_status:beforefix|php8.2-cli', out)
                self.assertNotIn('package_audit_status:beforefix|removed-lib', out)
                self.assertNotIn('UNEXPECTED_', out)
                if scenario == 'metadata':
                    self.assertIn('package_audit_status:beforefix|libfixture|1.0-1|amd64|install ok installed', out)
                    self.assertIn('libfixture|list=readable|md5sums=missing_or_unreadable', out)
                else:
                    self.assertNotIn('package_audit_status:beforefix|libfixture', out)

    def test_audit_context_query_failure_preserves_block_and_redacts_error(self):
        out = self.shell(r'''
p2s_command_exists() { [ "$1" = apt-get ] || [ "$1" = dpkg-query ]; }
p2s_command_run() {
    if [ "$2" = dpkg ]; then printf 'audit warning\n'; return 0; fi
    printf 'https://login:private-token@repo.invalid/private-path\n' >&2; return 124
}
p2s_package_deb_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
''')
        self.assertIn('package_audit_gap:beforefix|status_query_exit=124', out)
        self.assertIn('[repository host=repo.invalid; path redacted]', out)
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertNotIn('private-token', out)
        self.assertNotIn('private-path', out)

    def test_provider_hints_do_not_confuse_sury_with_debian_maintainer(self):
        cases = [
            ('php8.3-cli', 'Debian PHP Maintainers', '8.3.36-1+0~20261021.88+debian13~1.gbp250f7c', 'Sury/ondrej PHP (revision hint)'),
            ('php8.3-cli', 'Debian PHP Maintainers', '8.3.36-1~deb13u1', 'Debian'),
            ('php-cli', 'Remi Collet', '0:8.3.36-1.el9.remi', 'Remi (revision hint)'),
            ('php5-cli', 'Debian PHP Maintainers', '5.6.40+freexian1', 'Freexian PHP LTS (revision hint)'),
            ('php5-cli', 'Debian PHP Maintainers', '5.6.40+dfsg-0+deb8u23+rhphp2shell1', 'RimuHosting PHP2Shell backport (revision hint)'),
            ('php-cli', 'Ubuntu Developers', '8.3.36-1ppa1', 'Ubuntu PPA (package publisher unverified)'),
            ('ea-php83-php-cli', 'Debian PHP Maintainers', '8.3.36+0~1', 'cPanel EasyApache'),
            ('alt-php83-php-cli', 'TuxCare', '8.3.36-1', 'CloudLinux/TuxCare alt-PHP (namespace hint)'),
        ]
        for name, vendor, version, expected in cases:
            with self.subTest(name=name, version=version):
                out = self.shell('p2s_package_provider ' + ' '.join(map(shlex.quote, (name, vendor, version))))
                self.assertEqual(out.strip(), expected)

    def test_repository_url_redaction_keeps_hosts_without_subscription_secrets(self):
        out = self.shell(r'''
printf '%s\n' 'https://account:password@packages.sury.org/php?token=secret' \
    'https://deb.freexian.com/subscription-secret/php' \
    'http://[2001:db8::1]:8080/private' 'file:///private/token' | p2s_manifest_redact_repository_urls
''')
        for host in ('packages.sury.org', 'deb.freexian.com', '[2001:db8::1]:8080'):
            self.assertIn(host, out)
        for secret in ('password', 'token', 'subscription-secret', '/private', '/php', 'account'):
            self.assertNotIn(secret, out)

    def test_url_redaction_preserves_c_locale_whitespace_boundaries(self):
        out = self.shell(r'''
printf 'https://user:secret@one.invalid/private\tfirst\rsecond\014third\013fourth\n' |
    p2s_manifest_redact_repository_urls
printf '%s\n' 'E: https://user:secret@two.invalid/private "quoted"' > "$P2S_WORK/package.log"
p2s_package_log_report "$P2S_WORK/package.log"
''')
        # The text-mode subprocess normalises the preserved carriage return to a newline.
        self.assertIn('[repository host=one.invalid; path redacted]\tfirst\nsecond\fthird\vfourth', out)
        self.assertIn('[repository host=two.invalid; path redacted] "quoted"', out)
        self.assertNotIn('user:secret', out)
        self.assertNotIn('/private', out)

    def test_repository_files_are_data_and_hide_auth_fields(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d" "$P2S_WORK/etc/yum.repos.d"
cat > "$P2S_WORK/etc/apt/sources.list" <<'EOF'
# deb https://disabled.invalid/php trixie main
deb [signed-by=/key.gpg] https://user:password@packages.sury.org/php trixie main
EOF
cat > "$P2S_WORK/etc/apt/sources.list.d/php.sources" <<'EOF'
Types: deb
URIs: https://deb.freexian.com/subscription-secret/php
 https://mirror.invalid/private-key/php
Suites: bullseye
Components: main
Enabled: no
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 key-must-not-be-reported
EOF
cat > "$P2S_WORK/etc/yum.repos.d/php.repo" <<'EOF'
[remi-php83]
baseurl=https://user:password@rpms.remirepo.net/private/
enabled=1
gpgcheck=1
password=private-password
proxy=https://proxy:password@proxy.invalid/
$(touch /tmp/never-execute-repository-text)
EOF
p2s_repository_inventory_collect
''', isolated_sources=True)
        self.assertIn('packages.sury.org', out)
        self.assertIn('trixie main', out)
        self.assertIn('|suites|bullseye', out)
        self.assertIn('|enabled|no', out)
        self.assertIn('rpms.remirepo.net', out)
        self.assertIn('rpm-repo=remi-php83|gpgcheck|1', out)
        for hidden in ('password', 'subscription-secret', 'private-key', 'key-must-not', 'proxy.invalid', 'disabled.invalid', 'touch'):
            self.assertNotIn(hidden, out)


    def test_apt_pin_inventory_preserves_stanzas_and_ignores_disabled_files(self):
        out = self.shell(r"""
P2S_BACKEND=deb
mkdir -p "$P2S_WORK/etc/apt/preferences.d"
cat > "$P2S_WORK/etc/apt/preferences.d/debian-virtualmin-restricted-packages" <<'EOF'
Package: libapache2-mod-php*
Pin: release *
Pin-Priority: -1

Package: *
Pin: origin "https://user:password@repo.invalid/private"
Pin-Priority: 1001
Password: secret-auth-field
$(touch /tmp/never-execute-pin)
EOF
printf 'Package: ignored-php\nPin-Priority: -1\n' > "$P2S_WORK/etc/apt/preferences.d/php.disabled"
p2s_package_policy_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
""", isolated_sources=True)
        for expected in ('debian-virtualmin-restricted-packages|stanza=1|line=1|Package: libapache2-mod-php*',
                         '|stanza=1|line=3|Pin-Priority: -1', '|stanza=2|line=5|Package: *',
                         'ignored_fragment_extension', 'UNKNOWN=false|BLOCKED=false'):
            self.assertIn(expected, out)
        for hidden in ('password', 'secret-auth-field', 'touch', 'ignored-php', '/private'):
            self.assertNotIn(hidden, out)

    def test_rpm_policy_reports_excludes_locks_and_module_state_without_plugins(self):
        out = self.shell(r"""
P2S_BACKEND=rpm
mkdir -p "$P2S_WORK/etc/dnf/plugins" "$P2S_WORK/etc/dnf/modules.d" "$P2S_WORK/etc/yum.repos.d"
cat > "$P2S_WORK/etc/dnf/dnf.conf" <<'EOF'
[main]
excludepkgs=php* # password=hidden-comment
includepkgs=kernel*
plugins=1
password=secret-password
proxy=https://user:password@proxy.invalid/private
EOF
cat > "$P2S_WORK/etc/yum.repos.d/php.repo" <<'EOF'
[php-vendor]
priority=5
module_hotfixes=0
includepkgs=*
baseurl=https://user:password@repo.invalid/private
EOF
printf '[main]\nenabled=1\nlocklist=/custom/lock-file\n' > "$P2S_WORK/etc/dnf/plugins/versionlock.conf"
printf 'php-0:8.2.28-1.el9.*\n!php-0:8.2.35-1.el9.*\nphp-[89]*\n' > "$P2S_WORK/etc/dnf/plugins/versionlock.list"
printf '[php]\nname=php\nstream=8.2\nstate=enabled\n' > "$P2S_WORK/etc/dnf/modules.d/php.module"
p2s_package_policy_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
""", isolated_sources=True)
        for expected in ('excludepkgs=php*', 'includepkgs=kernel*', 'priority=5', 'module_hotfixes=0',
                         'locklist=/custom/lock-file', 'versionlock.list|line=1|php-0:8.2.28',
                         'versionlock.list|line=2|!php-0:8.2.35', 'versionlock.list|line=3|php-[89]*', 'stream=8.2',
                         'custom_paths_and_full_precedence_not_evaluated', 'UNKNOWN=false|BLOCKED=false'):
            self.assertIn(expected, out)
        for hidden in ('password', 'proxy.invalid', 'secret-password', 'repo.invalid', '/private', 'hidden-comment'):
            self.assertNotIn(hidden, out)
        self.assertNotIn('dss:warn:', out)

    def test_policy_excerpts_report_truncation(self):
        out = self.shell(r"""
P2S_BACKEND=deb
mkdir -p "$P2S_WORK/etc/apt/preferences.d"
awk 'BEGIN { for (i=0;i<201;i++) print "Package: php*" }' > "$P2S_WORK/etc/apt/preferences.d/long.pref"
p2s_package_policy_collect
""", isolated_sources=True)
        self.assertIn('truncated_after_200_lines', out)
        self.assertNotIn('|line=201|', out)
        out = self.shell(r"""
P2S_BACKEND=deb
mkdir -p "$P2S_WORK/etc/apt/preferences.d"
awk 'BEGIN { printf "Package: *\nPin: origin https://sensitive-user:"; for(i=0;i<600;i++) printf "x"; print "@repo.invalid/private" }' > "$P2S_WORK/etc/apt/preferences.d/long-url.pref"
p2s_package_policy_collect
""", isolated_sources=True)
        self.assertIn('omitted_over_512_characters', out)
        self.assertNotIn('sensitive-user', out)

    def apt_pin_policy(self):
        # Effective version priority -1 is distinct from the underlying repository priority 500.
        return r"""
p2s_command_exists() { [ "$1" = apt-cache ]; }
p2s_command_run() {
    cat <<'EOF'
php8.2-common:
  Installed: 8.2.28-1~deb12u1
  Candidate: 8.2.35-1~deb12u1
  Version table:
     8.2.35-1~deb12u1 500
        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages
 *** 8.2.28-1~deb12u1 100
        100 /var/lib/dpkg/status
libapache2-mod-php8.2:
  Installed: 8.2.28-1~deb12u1
  Candidate: (none)
  Version table:
     8.2.35-1~deb12u1 -1
        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages
 *** 8.2.28-1~deb12u1 -1
        100 /var/lib/dpkg/status
EOF
}
"""

    def test_apt_negative_pin_warning_identifies_missing_candidate_without_changing_state(self):
        out = self.shell(self.apt_pin_policy() + r"""
mkdir -p "$P2S_WORK/etc/apt/preferences.d"
: > "$P2S_WORK/etc/apt/preferences.d/debian-virtualmin-restricted-packages"
p2s_package_deb_policy_collect php8.2-common libapache2-mod-php8.2
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
""", isolated_sources=True)
        self.assertIn('apt_version_priority:beforefix|libapache2-mod-php8.2|8.2.35-1~deb12u1|-1', out)
        self.assertIn('apt_package_candidate:beforefix|php8.2-common|installed=8.2.28-1~deb12u1|candidate=8.2.35-1~deb12u1', out)
        self.assertIn('no allowed installation candidate for these installed PHP packages: libapache2-mod-php8.2.', out)
        self.assertIn('Negative APT priorities', out)
        self.assertIn('debian-virtualmin-restricted-packages', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)


    def test_cached_pin_gap_makes_patchability_uncertain_without_blocking_refresh(self):
        out = self.shell(self.apt_pin_policy() + r"""
p2s_package_deb_policy_collect libapache2-mod-php8.2
P2S_STATE=Y; P2S_BACKEND=deb
p2s_command_exists() { return 0; }
p2s_fix_preflight() { return 0; }; p2s_package_deb_preflight() { return 0; }
p2s_fix_report_patchability
printf 'STATE=%s|BLOCKED=%s\n' "$P2S_STATE" "$P2S_BLOCKED"
""", isolated_sources=True)
        self.assertIn('patchability:beforefix|unknown', out)
        self.assertIn('package_policy_review=true', out)
        self.assertIn('STATE=Y|BLOCKED=false', out)

    def test_apt_missing_candidate_without_negative_priority_does_not_blame_a_pin(self):
        out = self.shell(r"""
p2s_command_exists() { [ "$1" = apt-cache ]; }
p2s_command_run() { printf 'php8.2-cli:\n  Installed: 8.2.28-1\n  Candidate: (none)\n'; }
p2s_package_deb_policy_collect php8.2-cli
""", isolated_sources=True)
        self.assertIn('no allowed installation candidate', out)
        self.assertNotIn('Negative APT priorities were reported', out)

    def test_dependency_failure_has_a_customer_explanation_without_overriding_restrictions(self):
        for diagnostic in ('E: Packages need to be removed but remove is disabled.',
                           'libapache2-mod-php : Depends: libapache2-mod-php8.2 but it is not installable',
                           'All matches were filtered out by modular filtering',
                           'package php-cli is excluded by versionlock'):
            with self.subTest(diagnostic=diagnostic):
                out = self.shell("printf '%s\\n' " + shlex.quote(diagnostic) + r""" > "$P2S_WORK/failure"
p2s_package_log_report "$P2S_WORK/failure"
""")
                self.assertIn('could not find an allowed, compatible update', out)
                self.assertIn('Restrictions and package-removal protection were not bypassed', out)


    def test_loading_versionlock_plugin_is_not_reported_as_an_update_failure(self):
        out = self.shell(r"""
printf 'Loaded plugins: fastestmirror, versionlock\nNothing to do.\n' > "$P2S_WORK/success"
p2s_package_log_report "$P2S_WORK/success"
""")
        self.assertNotIn('package_resolution_failure', out)
        self.assertNotIn('dss:warn:', out)

    def test_php_extension_warnings_survive_successful_fpm_config_test(self):
        out = self.shell(r"""
p2s_command_run() {
    printf "PHP Warning: PHP Startup: Unable to load dynamic library 'pdo_mysql': undefined symbol: pdo_parse_params\n" >&2
    printf 'configuration file test is successful\n'
    return 0
}
p2s_service_check_config 'PHP-FPM (PID 4242)' /fixture/php-fpm -t
printf 'RC=%s|UNKNOWN=%s|BLOCKED=%s\n' "$?" "$P2S_UNKNOWN" "$P2S_BLOCKED"
""")
        self.assertIn('PHP startup warnings were detected', out)
        self.assertIn('pdo_parse_params', out)
        self.assertIn('RC=0|UNKNOWN=false|BLOCKED=false', out)
        self.assertIn('CVE_state_unchanged', out)

    def test_apt_source_matches_installed_versions_not_every_enabled_repository(self):
        out = self.shell(r'''
P2S_BACKEND=deb
printf '%s\n' 'php8.3-cli|8.3.35-1+0~1|amd64|Debian PHP Maintainers' > "$P2S_WORK/packages"
p2s_command_exists() { [ "$1" = apt-cache ]; }
p2s_command_run() {
    case " $* " in
        *' -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy '*) : ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
    if [ "$8" = php8.3-cli ]; then
        cat <<'EOF'
php8.3-cli:
  Installed: 8.3.35-1+0~1
  Candidate: 8.3.36-1+0~1
  Version table:
     8.3.36-1+0~1 500
        500 https://packages.sury.org/php trixie/main amd64 Packages
 *** 8.3.35-1+0~1 100
        100 /var/lib/dpkg/status
        500 https://account:password@packages.sury.org/private trixie/main amd64 Packages
     8.3.34-1 500
        500 https://deb.debian.org/debian trixie/main amd64 Packages
EOF
    else
        printf '%s\n' '500 https://packages.sury.org/php trixie/main amd64 Packages' \
            'release o=deb.sury.org,a=trixie,n=trixie,l=deb.sury.org,c=main,b=amd64'
    fi
}
p2s_package_sources_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('Sury/ondrej PHP (revision hint)', out)
        self.assertIn('provider_website=https://sury.org/', out)
        self.assertIn('|8.3.35-1+0~1|installed_version_match|', out)
        self.assertIn('|8.3.36-1+0~1|candidate_match|', out)
        self.assertIn('|8.3.34-1|other_available|', out)
        self.assertIn('n=trixie', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)
        self.assertNotIn('password', out)
        self.assertNotIn('/private', out)

    def test_debian_source_identity_preserves_rebuild_and_multiarch_versions_without_apt_cache(self):
        out = self.shell(r'''
P2S_BACKEND=deb
printf '%s\n' 'php8.2-cli|8.2.29-1+b1|amd64|Debian' > "$P2S_WORK/packages"
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() {
    case " $* " in
        *' dpkg-query -W '*)
            printf '%s\n' 'php8.2-cli|8.2.29-1+b1|amd64|php8.2 (8.2.29-1)' \
                'libapache2-mod-php8.2|8.2.29-1|amd64|php8.2' \
                'php-redis:i386|6.0.2-1|i386|' ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_package_sources_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        for expected in (
                'deb_source_package:beforefix|php8.2-cli|8.2.29-1+b1|amd64|php8.2|8.2.29-1|source_field',
                'deb_source_package:beforefix|libapache2-mod-php8.2|8.2.29-1|amd64|php8.2|8.2.29-1|source_field',
                'deb_source_package:beforefix|php-redis:i386|6.0.2-1|i386|php-redis|6.0.2-1|binary_name_version_fallback',
                'apt-cache unavailable', 'UNKNOWN=false|BLOCKED=false'):
            self.assertIn(expected, out)

    def test_debian_source_identity_failure_is_only_an_observation_gap(self):
        out = self.shell(r'''
P2S_BACKEND=deb
printf '%s\n' 'php8.2-cli|8.2.29-1|amd64|Debian' > "$P2S_WORK/packages"
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() { return 124; }
p2s_package_sources_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('source_gap:beforefix|Debian source-package metadata unavailable', out)
        self.assertNotIn('deb_source_package:', out)
        self.assertIn('UNKNOWN=false|BLOCKED=false', out)

    def test_source_metadata_failure_does_not_change_cve_state(self):
        for backend in ('deb', 'rpm'):
            with self.subTest(backend=backend):
                out = self.shell('P2S_BACKEND=' + backend + r'''
printf '%s\n' 'php-cli|8.4.27-1|amd64|unknown' > "$P2S_WORK/packages"
p2s_command_exists() { case "$1" in apt-cache|dnf) return 0;; *) return 1;; esac; }
p2s_command_run() { return 124; }
p2s_package_sources_collect
printf 'UNKNOWN=%s|BLOCKED=%s\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
                self.assertIn('dss:manifest:source_gap:', out)
                self.assertIn('UNKNOWN=false|BLOCKED=false', out)
                self.assertNotIn('dss:warn:', out)

    def test_rpm_source_records_separate_headers_from_recorded_origins(self):
        for manager in ('dnf', 'yum'):
            with self.subTest(manager=manager):
                out = self.shell('fixture_manager=' + manager + r'''
P2S_BACKEND=rpm
printf '%s\n' 'php-cli|0:8.3.36-1.el9.remi|x86_64|Remi' > "$P2S_WORK/packages"
mkdir -p "$P2S_WORK/var/lib/yum/yumdb/p/hash-php-cli-8.3.36-1.el9.remi-x86_64"
printf '%s\n' 'remi-php83' > "$P2S_WORK/var/lib/yum/yumdb/p/hash-php-cli-8.3.36-1.el9.remi-x86_64/from_repo"
p2s_command_exists() { [ "$1" = "$fixture_manager" ]; }
p2s_command_run() {
    if [ "$2" = rpm ]; then
        printf '%s\n' 'php-cli|8.3.36-1.el9.remi|x86_64|Remi|Packager|php-8.3.36-1.src.rpm|123|456'
    else
        case " $* " in *' -C --disableplugin=* '*) :;; *) return 97;; esac
        case "$fixture_manager:$*" in dnf:*' info --installed '*|yum:*' info installed '*) :;; *) return 97;; esac
        printf '%s\n' 'Name : php-cli' 'Version : 8.3.36' 'Release : 1.el9.remi' 'From repo : remi-php83' 'Description : omit-this'
    fi
}
p2s_package_sources_collect
''', isolated_sources=True)
                self.assertIn('rpm_package_build:beforefix|php-cli|8.3.36', out)
                self.assertIn('package_repository_record:beforefix|php-cli|0:8.3.36', out)
                self.assertIn('|yumdb|', out)
                self.assertIn(manager + '|From repo : remi-php83', out)
                self.assertNotIn('omit-this', out)

    def test_upstream_thresholds(self):
        cases = {'4.4.4': '?', '5.3.29': '?', '5.4.0': 'Y', '5.6.33': 'Y', '5.6.40': 'Y', '7.4.33': 'Y',
                 '8.0.30': 'Y', '8.1.33': 'Y', '8.2.34': 'Y', '8.2.35': 'N',
                 '8.3.35': 'Y', '8.3.36': 'N', '8.4.26': 'Y', '8.4.27': 'N',
                 '8.5.11': 'Y', '8.5.12': 'N', '8.6.0': '?', '9.0.0': '?',
                 '8.4.27RC1': '?', '8.4.27-dev': '?', '8.4.27beta1': '?',
                 '1:8.4.27-1': 'N', '8.4': '?', 'garbage': '?', '': '?',
                 '8.4.26-20261021': 'Y'}
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(self.shell('p2s_version_upstream_state ' + shlex.quote(version)).strip(), expected)

    def test_debian_ubuntu_backports(self):
        cases = [
            ('ubuntu', '22.04', 'php8.1-cli', '8.1.2-1ubuntu2.28', 'Ubuntu Developers', 'N'),
            ('ubuntu', '22.04', 'php8.1-cli', '8.1.2-1ubuntu2.27', 'Ubuntu Developers', 'Y'),
            ('ubuntu', '22.04', 'php8.1-cli', '1:8.1.2-1ubuntu2.28', 'Ubuntu Developers', 'N'),
            ('ubuntu', '24.04', 'php8.3-fpm', '8.3.6-0ubuntu0.24.04.13', 'Ubuntu Developers', 'N'),
            ('ubuntu', '26.10', 'php8.5-cli', '8.5.9-0ubuntu2.1', 'Ubuntu Developers', 'N'),
            ('ubuntu', '26.04', 'php8.5-cli', '8.5.4-0ubuntu1.5', 'Ubuntu Developers', 'N'),
            ('ubuntu', '20.04', 'php7.4-cli', '7.4.3-4ubuntu2.29+esm5', 'Ubuntu Developers', 'N'),
            ('ubuntu', '18.04', 'php7.2-cli', '7.2.24-0ubuntu0.18.04.17+esm14', 'Ubuntu Developers', 'N'),
            ('ubuntu', '16.04', 'php7.0-cli', '7.0.33-0ubuntu0.16.04.16+esm22', 'Ubuntu Developers', 'N'),
            ('ubuntu', '14.04', 'php5-cli', '5.5.9+dfsg-1ubuntu4.29+esm18', 'Ubuntu Developers', 'N'),
            ('debian', '13', 'php8.4-fpm', '8.4.27-1~deb13u1', 'Debian PHP Maintainers', 'N'),
            ('ubuntu', '24.04', 'php8.3-fpm', '8.3.6-0ubuntu0.24.04.13', 'Sury', '?'),
            ('ubuntu', '24.04', 'php8.1-cli', '8.1.2-1ubuntu2.28', 'Ubuntu Developers', '?'),
            ('debian', '12', 'php8.2-cli', '8.2.35-1~deb12u1', 'Debian PHP Maintainers', 'N'),
            ('debian', '12', 'php8.2-cli', '8.2.34-1~deb12u1', 'Debian PHP Maintainers', 'Y'),
        ]
        for distro, release, name, version, vendor, expected in cases:
            with self.subTest(distro=distro, release=release, version=version, vendor=vendor):
                body = f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n'
                body += 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, version, vendor)))
                self.assertEqual(self.shell(body).strip(), expected)

    def test_jessie_local_backport_requires_exact_reviewed_revision(self):
        version = '5.6.40+dfsg-0+deb8u23+rhphp2shell1'
        cases = [
            ('debian', '8', 'php5-cli', version, 'Debian PHP Maintainers', 'N'),
            ('debian', '8.11', 'libapache2-mod-php5', version, 'Debian PHP Maintainers', 'N'),
            ('debian', '8', 'php5-common', version, 'Debian PHP Maintainers', 'N'),
            ('debian', '8', 'php5-fpm', version, 'Debian PHP Maintainers', 'N'),
            ('debian', '8', 'php5-cli', '5.6.40+dfsg-0+deb8u23', 'Debian PHP Maintainers', '?'),
            ('debian', '8', 'php5-cli', version + '.1', 'Debian PHP Maintainers', '?'),
            ('debian', '8', 'php5-cli', version, 'Other provider', '?'),
            ('debian', '9', 'php5-cli', version, 'Debian PHP Maintainers', '?'),
            ('debian', '80', 'php5-cli', version, 'Debian PHP Maintainers', '?'),
            ('ubuntu', '8', 'php5-cli', version, 'Debian PHP Maintainers', '?'),
            ('debian', '8', 'php5-json', version, 'Debian PHP Maintainers', '?'),
        ]
        for distro, release, name, value, vendor, expected in cases:
            with self.subTest(distro=distro, release=release, name=name, version=value, vendor=vendor):
                body = f'P2S_BACKEND=deb; P2S_DISTRO={distro}; P2S_RELEASE={release}\n'
                body += 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, value, vendor)))
                self.assertEqual(self.shell(body).strip(), expected)

    def test_alma_exact_backports_and_other_rpm(self):
        version = '0:8.0.30-8.el9_8.alma.1'
        for distro, vendor, value, expected in [
            ('almalinux', 'AlmaLinux', version, 'N'),
            ('rocky', 'AlmaLinux', version, '?'),
            ('almalinux', 'Other', version, '?'),
            ('almalinux', 'AlmaLinux', version + '.2', '?'),
            ('rocky', 'Rocky', '8.4.27-1.el9', 'N')]:
            with self.subTest(distro=distro, vendor=vendor, version=value):
                body = f'P2S_BACKEND=rpm; P2S_DISTRO={distro}; P2S_MAJOR=9\n'
                body += 'p2s_version_package_state php-cli ' + shlex.quote(value) + ' ' + shlex.quote(vendor)
                self.assertEqual(self.shell(body).strip(), expected)

    def test_aggregate_states(self):
        for states, expected in [('N N', 'N'), ('N ?', '?'), ('N ? Y', 'Y'), ('', 'N')]:
            with self.subTest(states=states):
                output = self.shell('''
p2s_package_inventory_collect() { :; }; p2s_package_inventory_assess() { for s in ''' + states + '''; do p2s_state_include "$s"; done; }
p2s_panel_inventory_collect() { :; }; p2s_process_inventory_collect() { :; }; p2s_runtime_inventory_collect() { :; }
id() { printf '0\\n'; }
p2s_inventory_collect_and_assess
printf 'STATE=%s\\n' "$P2S_STATE"
''') if states else self.shell('''
p2s_package_inventory_collect() { :; }; p2s_package_inventory_assess() { :; }
p2s_panel_inventory_collect() { :; }; p2s_process_inventory_collect() { :; }; p2s_runtime_inventory_collect() { :; }
id() { printf '0\\n'; }; p2s_inventory_collect_and_assess; printf 'STATE=%s\\n' "$P2S_STATE"
''')
                self.assertIn('STATE=' + expected, output)

    def test_rocky9_exact_vendor_backport(self):
        vendor = 'Rocky Enterprise Software Foundation'
        cases = [(name, '0:8.0.30-8.el9_8.1', vendor, '9', 'N')
                 for name in ('php', 'php-common', 'php-cli', 'php-fpm', 'php-embedded')]
        cases += [('php-cli', version, source, major, '?') for version, source, major in (
            ('0:8.0.30-8.el9_8', vendor, '9'),
            ('0:8.0.30-8.el9_8.1.custom', vendor, '9'),
            ('1:8.0.30-8.el9_8.1', vendor, '9'),
            ('0:8.0.30-8.el9_8.1', 'Other', '9'),
            ('0:8.0.30-8.el9_8.1', vendor, '8'))]
        cases.append(('alt-php80-cli', '0:8.0.30-8.el9_8.1', vendor, '9', '?'))
        for name, version, source, major, expected in cases:
            with self.subTest(name=name, version=version, vendor=source, major=major):
                body = 'P2S_BACKEND=rpm; P2S_DISTRO=rocky; P2S_MAJOR=' + major + '\n'
                body += 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, version, source)))
                self.assertEqual(self.shell(body).strip(), expected)

    def test_centos5_archived_stock_build_is_presumed_vulnerable(self):
        version = '0:5.1.6-44.el5_10'
        cases = [(name, value, 'CentOS', 'centos', '5', 'Y')
                 for name in ('php', 'php-cli', 'php-common')
                 for value in (version, version[2:])]
        cases += [('php-cli', value, vendor, distro, major, '?')
                  for value, vendor, distro, major in (
                      (version + '.custom', 'CentOS', 'centos', '5'),
                      ('1:5.1.6-44.el5_10', 'CentOS', 'centos', '5'),
                      (version, 'Custom provider', 'centos', '5'),
                      (version, 'CentOS', 'centos', '6'),
                      (version, 'CentOS', 'rocky', '5'))]
        cases.append(('alt-php51-cli', version, 'CentOS', 'centos', '5', '?'))
        for name, value, vendor, distro, major, expected in cases:
            with self.subTest(name=name, version=value, vendor=vendor, distro=distro, major=major):
                body = f'P2S_BACKEND=rpm; P2S_DISTRO={distro}; P2S_MAJOR={major}\n'
                body += 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, value, vendor)))
                self.assertEqual(self.shell(body).strip(), expected)

    def test_centos5_presumption_reaches_markers_without_enabling_updates(self):
        for mode in ('check', 'fix'):
            with self.subTest(mode=mode):
                out = self.shell(r'''
p2s_distro_detect() { P2S_DISTRO=centos; P2S_RELEASE=5.11; P2S_MAJOR=5; }
p2s_package_inventory_collect() {
    P2S_BACKEND=rpm
    printf '%s\n' 'php|0:5.1.6-44.el5_10|i386|CentOS' 'php-cli|0:5.1.6-44.el5_10|i386|CentOS' > "$P2S_WORK/packages"
}
p2s_repository_inventory_collect() { :; }; p2s_package_sources_collect() { :; }
p2s_package_backport_evidence_collect() { :; }; p2s_panel_inventory_collect() { :; }
p2s_process_inventory_collect() { :; }; p2s_runtime_inventory_collect() { :; }
p2s_command_run() { case "$2:$3" in rpm:-ql|uname:-a) return 0;; *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97;; esac; }
id() { printf '0\n'; }
# Never create the production lock; fail if the unsupported OS reaches it.
mkdir() { return 97; }
(p2s_main --''' + mode + ')\n', status=0 if mode == 'check' else 1)
                for phase in ('beforefix', 'afterfix'):
                    self.assertIn('dss:isvulnerable:' + phase + ': CVE_2026_109618Y', out)
                self.assertIn('presumed_affected_legacy_vendor_build|upstream=?', out)
                self.assertIn('presumed vulnerable because this stock CentOS 5 PHP package predates the PHP2Shell fixes and has no verified backport.', out)
                self.assertIn('Exploitability has not been tested.', out)
                self.assertIn('No automatic update recipe for centos 5.11 is implemented in this script.', out)
                self.assertNotIn("outside this detector's verified PHP2Shell coverage", out)
                self.assertNotIn('Result: We could not verify', out)
                if mode == 'fix':
                    self.assertIn('package_install_attempted=false|service_restart_attempted=false', out)

    def test_rpm_nothing_to_do_explains_no_candidate_without_install(self):
        for pending in ('false', 'true'):
            with self.subTest(restart_pending=pending):
                out = self.shell('P2S_RESTART_PENDING=' + pending + r'''
printf 'php-cli|8.0.30-8.el9_8.1|x86_64|Rocky\n' > "$P2S_WORK/packages"
p2s_command_exists() { [ "$1" = dnf ]; }
p2s_command_run() {
    case " $* " in
        *' makecache '*) return 0;;
        *' --setopt=tsflags=test '*) printf 'Dependencies resolved.\nNothing to do.\nComplete!\n'; return 0;;
        *) printf 'UNEXPECTED_INSTALL\n'; return 97;;
    esac
}
p2s_package_rpm_update
printf 'RC=%s|INSTALL_ATTEMPTED=%s\n' "$?" "${P2S_TRANSACTION_ATTEMPTED:-false}"
''')
                self.assertIn('RC=' + ('0' if pending == 'true' else '1') + '|INSTALL_ATTEMPTED=false', out)
                self.assertIn('package_update_plan:beforefix|dnf|no_updates', out)
                self.assertNotIn('UNEXPECTED_INSTALL', out)
                self.assertNotIn('transaction_scope', out)
                if pending == 'false':
                    self.assertIn('no newer installed PHP packages', out)
                    self.assertIn('no_candidate', out)

    def test_mixed_php_packages_preserve_worst_state_in_either_order(self):
        patched = [('php8.3-cli', '8.3.36-1', 'N'), ('php8.4-cli', '8.4.27-1', 'N')]
        vulnerable = ('php8.2-cli', '8.2.34-1~deb12u1', 'Y')
        unknown = ('php8.6-cli', '8.6.0-1', '?')
        cases = [(patched, 'N'), ([vulnerable] + patched, 'Y'),
                 (patched + [vulnerable], 'Y'), ([unknown] + patched, '?'),
                 ([vulnerable, unknown] + patched, 'Y'),
                 (patched + [unknown, vulnerable], 'Y')]
        for packages, expected in cases:
            with self.subTest(packages=packages):
                records = '\n'.join(name + '|' + version + '|amd64|Debian PHP Maintainers'
                                    for name, version, _ in packages)
                out = self.shell("printf '%s\\n' " + shlex.quote(records) + r''' > "$P2S_WORK/packages"
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12
p2s_package_inventory_collect() { :; }
p2s_package_backport_evidence_collect() { :; }
p2s_panel_inventory_collect() { :; }; p2s_process_inventory_collect() { :; }; p2s_runtime_inventory_collect() { :; }
p2s_command_run() { case "$2:$3" in dpkg-query:-L|dpkg:-L) return 0;; *) return 97;; esac; }
id() { printf '0\n'; }
p2s_inventory_collect_and_assess
printf 'STATE=%s\n' "$P2S_STATE"
''')
                self.assertIn('STATE=' + expected, out)
                for name, version, state in packages:
                    self.assertIn('dss:manifest:package_state:beforefix|' + name + '|' + state, out)
                    if state == 'N':
                        self.assertIn('PHP ' + version.split('-')[0] + ' (command line): fixes verified', out)


    def test_unlisted_vendor_backports_are_unknown_not_cleared(self):
        cases = [
            ('php7.3-cli', '7.3.33-35+0~20261021.144+debian12~1.gbpecf76f', '?'),
            ('php7.4-cli', '1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428', '?'),
            ('php8.1-cli', '8.1.34-9+0~20261021.82+debian12~1.gbp4e430a', '?'),
            ('php8.2-cli', '8.2.35-1+0~20261021.94+debian12~1.gbp8bff78', 'N'),
            ('php8.2-cli', '8.2.34-1', '?'),
        ]
        for name, version, expected in cases:
            with self.subTest(name=name, version=version):
                out = self.shell('P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=12\n'
                                 'p2s_version_package_state ' + shlex.quote(name) + ' ' + shlex.quote(version)
                                 + " 'Debian PHP Maintainers'")
                self.assertEqual(out.strip(), expected)
        # Similar-looking PPA packages must not inherit Ubuntu's official backport floor.
        out = self.shell("P2S_BACKEND=deb; P2S_DISTRO=ubuntu; P2S_RELEASE=22.04\n"
                         "p2s_version_package_state php8.1-cli 8.1.34-9+0~20261021.82+ubuntu22.04~1 'Ubuntu Developers'")
        self.assertEqual(out.strip(), '?')

    def test_grouped_versions_keep_component_states_and_omit_build_dates(self):
        out = self.shell(r'''
printf '%s\n' '8.4.27|N|command line|Oct 21 2026 08:21:27' \
    '8.4.27|N|command line|Oct 21 2026 08:21:27' \
    '8.4.27|N|PHP-FPM|Oct 21 2026 08:21:27' \
    '8.4.27|?|Apache module|' '8.2.34|Y|CGI|' > "$P2S_WORK/summary-versions"
p2s_summary_print_versions
P2S_MODE=fix
p2s_summary_print_versions
P2S_PHASE=afterfix; P2S_TRANSACTION_ATTEMPTED=true
p2s_summary_print_versions
''')
        rows = out.splitlines()
        self.assertEqual(len(rows), 9)
        for offset, prefix in [(0, ''), (3, 'Initial check: '), (6, 'After update attempt: ')]:
            phase = rows[offset:offset + 3]
            self.assertEqual(sum('8.4.27' in row for row in phase), 2)
            fixed = next(row for row in phase if row.startswith('dss:info:'))
            self.assertIn(prefix + 'PHP 8.4.27', fixed)
            self.assertIn('PHP-FPM, command line', fixed)
            self.assertNotIn('Oct 21 2026 08:21:27', fixed)
            self.assertTrue(any('Apache module): patch status not verified' in row for row in phase))
            self.assertTrue(any('CGI): vulnerable;' in row for row in phase))

    def test_summary_labels_backports_and_only_describes_actual_update_attempts(self):
        records = [
            '7.4.33|N|PHP-FPM|Oct 21 2026 14:22:13|Sury/ondrej PHP (revision hint)|1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1|Y|running_path',
            '8.4.22|?|command line|Jun 10 2026 00:00:00|cPanel internal|0:8.4.22-1.cp130~el10|Y|executable',
        ]
        setup = "printf '%s\\n' " + ' '.join(map(shlex.quote, records)) + ' > "$P2S_WORK/summary-versions"\n'
        for transaction, restart in [(False, False), (True, False), (False, True)]:
            with self.subTest(transaction=transaction, restart=restart):
                out = self.shell(setup + 'P2S_MODE=fix; P2S_INVENTORY_MESSAGES=true\n'
                                 'p2s_summary_print_versions\nP2S_PHASE=afterfix\n'
                                 + 'P2S_TRANSACTION_ATTEMPTED=' + str(transaction).lower() + '\n'
                                 + 'P2S_RESTART_ATTEMPTED=' + str(restart).lower() + '\n'
                                 + 'p2s_summary_print_versions\n'
                                 + 'p2s_manifest_record package "php7.4-fpm|1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1"\n')
                customer = [row for row in out.splitlines() if row.startswith(('dss:info:', 'dss:warn:'))]
                self.assertEqual(len(customer), 4 if transaction or restart else 2)
                self.assertTrue(all('Initial check: PHP ' in row for row in customer[:2]))
                self.assertEqual(sum('After update attempt:' in row for row in customer), 2 if transaction else 0)
                self.assertEqual(sum('After service restart attempt:' in row for row in customer), 2 if restart else 0)
                self.assertIn('Package publisher: Sury/ondrej PHP.', customer[0])
                self.assertIn('Installed package build: 1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1.', customer[0])
                self.assertIn('The PHP package publisher added the security fixes without changing the PHP version.', customer[0])
                self.assertIn('fixes verified for both PHP2Shell vulnerabilities', customer[0])
                self.assertIn('Package publisher: cPanel internal.', customer[1])
                self.assertIn('patch status not verified', customer[1])
                self.assertIn('This script has no verified fix record for the installed build', customer[1])
                for row in customer:
                    for detail in ['revision hint', 'Oct 21', 'Jun 10', 'Before update attempt:']:
                        self.assertNotIn(detail, row)
                self.assertIn('dss:manifest:package:afterfix|php7.4-fpm|1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1', out)

    def test_pre_54_summary_explains_coverage_without_asserting_cve_applicability(self):
        out = self.shell(r'''
printf '%s\n' '4.4.4|?|runtime libraries||unknown|4.4.4-1|?|package' \
    '5.3.29|?|command line||unknown||?|executable' \
    '5.6.33|?|CGI||unknown|5.6.33-1|Y|package' > "$P2S_WORK/summary-versions"
p2s_summary_print_versions
''')
        rows = out.splitlines()
        self.assertEqual(len(rows), 3)
        for row in rows[:2]:
            self.assertIn("outside this detector's verified PHP2Shell coverage", row)
            self.assertIn('review its security support', row)
            self.assertNotIn('does not establish', row)
            self.assertNotIn('fixes verified', row)
            self.assertNotIn('vendor backport has not been verified', row)
        self.assertIn('Checked installed packages; no PHP executable or Apache module was matched.', rows[0])
        self.assertIn('patch status not verified', rows[2])
        self.assertIn('This script has no verified fix record for the installed build', rows[2])

    def test_unknown_summary_names_the_missing_evidence_and_installed_build(self):
        for reason, expected in [
                ('engine_package_assessment', 'This script has no verified fix record for the installed build'),
                ('engine_package_version_mismatch', 'The executable reports a different PHP version from its owning package'),
                ('package_inventory_unavailable', 'Package inventory is unavailable'),
                ('owner_is_not_an_assessed_engine', 'No assessed PHP engine package owns this executable')]:
            with self.subTest(reason=reason):
                record = '8.4.26|?|command line||unverified source|8.4.26-custom1|Y|executable|' + reason
                out = self.shell('printf "%s\\n" ' + shlex.quote(record) + r''' > "$P2S_WORK/summary-versions"
P2S_MODE=fix; P2S_PHASE=afterfix; P2S_TRANSACTION_ATTEMPTED=true
P2S_UPDATE_METHOD='apt-get install --only-upgrade PHP packages'
p2s_summary_print_versions
''')
                self.assertIn(expected, out)
                self.assertIn('Installed package build: 8.4.26-custom1.', out)
                self.assertIn('After update attempt (apt-get install --only-upgrade PHP packages): PHP 8.4.26', out)

    def test_package_detail_stays_in_manifest(self):
        records = '\n'.join(name + '|8.4.27-1|amd64|install ok installed|Debian PHP Maintainers'
                            for name in ['php8.4-cli', 'php8.4-common', 'php8.4-fpm',
                                         'php8.4-odbc', 'php8.4-opcache', 'php8.4-readline',
                                         'php8.4-sqlite3', 'php8.4-xml'])
        out = self.shell("records=" + shlex.quote(records) + r'''
P2S_DISTRO=debian; P2S_RELEASE=12
p2s_command_run() {
    case "$2:$3" in dpkg-query:-W) printf '%s\n' "$records" ;; dpkg-query:-L|dpkg:-L) : ;; *) return 97 ;; esac
}
p2s_package_backport_evidence_collect() { :; }
p2s_package_inventory_collect
p2s_package_inventory_assess
p2s_summary_print_versions
''')
        self.assertEqual(out.count('dss:manifest:package:beforefix|'), 8)
        info = [row for row in out.splitlines() if row.startswith('dss:info:')]
        self.assertEqual(len(info), 1)
        self.assertIn('PHP 8.4.27', info[0])
        self.assertNotIn('php8.4-odbc', info[0])
        self.assertNotIn('PHP package:', out)

    def test_cpanel_library_versions_do_not_become_php_versions_or_migration_targets(self):
        out = self.shell(r'''
P2S_DISTRO=almalinux; P2S_MAJOR=10
p2s_command_exists() { [ "$1" = rpm ]; }
p2s_command_run() {
    case "$2:$3" in
        rpm:-qa) printf '%s\n' \
            'cpanel-php84|0:8.4.27-1.cpanel|x86_64|install ok installed|cPanel' \
            'cpanel-php84-common|0:8.4.27-1.cpanel|x86_64|install ok installed|cPanel' \
            'cpanel-php84-xml-serializer|0:0.21.0-1.cpanel|noarch|install ok installed|cPanel' \
            'cpanel-php84-date-holidays|0:0.21.8-1.cpanel|noarch|install ok installed|cPanel' ;;
        rpm:-ql) : ;; *) return 97 ;;
    esac
}
p2s_package_backport_evidence_collect() { :; }
p2s_package_inventory_collect
p2s_package_inventory_assess
p2s_summary_print_versions
P2S_STATE='?'; p2s_summary_print_result
''')
        self.assertIn('cpanel-php84-xml-serializer|0:0.21.0-1.cpanel', out)
        self.assertIn('cpanel-php84-date-holidays|supporting_or_selector_package', out)
        self.assertNotIn('PHP 0.21.', out)
        self.assertNotIn('PHP versions needing attention:', out)
        warnings = [row for row in out.splitlines() if row.startswith('dss:warn:')]
        self.assertEqual(sum('vendor-specific update and restart procedure' in row for row in warnings), 1)
        self.assertIn('Package publisher: cPanel internal.', out)

    def test_alma_known_affected_build_shows_vendor_update_guidance(self):
        out = self.shell(r'''
P2S_BACKEND=rpm; P2S_DISTRO=almalinux; P2S_MAJOR=10
printf '%s\n' 'php-cli|0:8.3.31-1.el10_2|x86_64|AlmaLinux' \
    'php-common|0:8.3.31-1.el10_2|x86_64|AlmaLinux' > "$P2S_WORK/packages"
p2s_package_backport_evidence_collect() { :; }
p2s_command_run() { [ "$2:$3" = rpm:-ql ]; }
p2s_package_inventory_assess
p2s_summary_print_versions
printf 'VULNERABLE=%s|UNKNOWN=%s\n' "$P2S_VULNERABLE" "$P2S_UNKNOWN"
''')
        self.assertIn('VULNERABLE=true|UNKNOWN=false', out)
        self.assertIn('php-cli|0:8.3.31-1.el10_2|x86_64|AlmaLinux|AlmaLinux|Y|verified_affected_version_rule', out)
        warning = next(row for row in out.splitlines() if row.startswith('dss:warn:'))
        self.assertIn('Package publisher: AlmaLinux.', warning)
        self.assertNotIn('0:8.3.31-1.el10_2', warning)
        self.assertIn('AlmaLinux has published security updates for this PHP stream', warning)
        self.assertNotIn('patch status not verified', warning)

    def test_alma_affected_build_rule_does_not_extend_to_unverified_rebuilds(self):
        for name, version, vendor, major, expected in [
            ('php-cli', '0:8.3.31-1.el10_2', 'AlmaLinux', 10, 'Y'),
            ('php-fpm', '8.3.31-1.el10_2', 'AlmaLinux', 10, 'Y'),
            ('php-cli', '0:8.3.31-1.el10_2.alma.1', 'AlmaLinux', 10, '?'),
            ('php-cli', '0:8.3.31-2.el10_2', 'AlmaLinux', 10, '?'),
            ('php-cli', '1:8.3.31-1.el10_2', 'AlmaLinux', 10, '?'),
            ('php-cli', '0:8.3.31-1.el10_2', 'Other AlmaLinux rebuild', 10, '?'),
            ('php-cli', '0:8.3.31-1.el10_2', 'AlmaLinux', 9, '?'),
            ('custom-php-cli', '0:8.3.31-1.el10_2', 'AlmaLinux', 10, '?'),
            ('php-cli', '0:8.3.33-1.el10_2.alma.1', 'AlmaLinux', 10, 'N'),
            ('php-cli', '0:8.3.36-1.el10_2', 'AlmaLinux', 10, 'N'),
        ]:
            with self.subTest(name=name, version=version, vendor=vendor, major=major):
                out = self.shell(f'P2S_BACKEND=rpm; P2S_DISTRO=almalinux; P2S_MAJOR={major}\n'
                                 'p2s_version_package_state ' + ' '.join(map(shlex.quote, (name, version, vendor))))
                self.assertEqual(out.strip(), expected)

    def test_arch_is_rolling_and_missing_recipe_is_not_an_os_support_claim(self):
        out = self.shell(r'''
p2s_distro_release_value() { [ "$2" = ID ] && printf 'arch\n'; }
p2s_distro_detect
p2s_fix_check_distro_recipe
p2s_package_inventory_collect
printf 'BACKEND=%s|UNKNOWN=%s|BLOCKED=%s\n' "$P2S_BACKEND" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
        self.assertIn('Operating system: Arch Linux (rolling release).', out)
        self.assertIn('Automatic updates are not implemented for Arch Linux.', out)
        self.assertIn('BACKEND=unknown|UNKNOWN=true|BLOCKED=true', out)
        self.assertIn('dss:manifest:inventory_gap:beforefix|pacman|', out)
        self.assertNotIn('unsupported OS', out)
        self.assertNotIn('Custom PHP', out)

    def test_final_results_distinguish_unknown_vulnerable_and_scoped_clearance(self):
        for state, count, phrase in [('Y', 2, 'identified as vulnerable'),
                                      ('?', 2, 'could not verify whether all PHP installations include both PHP2Shell fixes'),
                                      ('N', 2, 'All detected PHP installations include both PHP2Shell fixes'),
                                      ('N', 0, 'No PHP installation was found')]:
            with self.subTest(state=state, count=count):
                out = self.shell('P2S_STATE=' + shlex.quote(state) + '; P2S_COUNT=' + str(count)
                                 + '\np2s_summary_print_result')
                self.assertIn('Result:', out)
                self.assertIn(phrase, out)
                self.assertEqual(out.count('RimuHosting offers a no-cost, no-obligation investigation'),
                                 0 if state == 'N' else 1)
                self.assertEqual(len(out.splitlines()), 1 if state == 'N' else 2)
                if state != 'N':
                    self.assertIn('including for servers hosted elsewhere', out)
                    self.assertIn('Any changes or further work are agreed separately.', out)

    def test_mixed_php_branches_get_conditional_migration_guidance(self):
        cases = [
            ('?', ['7.3.33|?|command line|', '7.3.33|?|Apache module|', '8.4.27|N|PHP-FPM|'], ['PHP 7.3.33']),
            ('Y', ['8.2.34|Y|command line|', '8.4.27|N|PHP-FPM|'], ['PHP 8.2.34']),
            ('?', ['7.3.33|?|command line|', '7.4.33|?|CGI|', '8.4.27|N|PHP-FPM|'], ['PHP 7.3.33', 'PHP 7.4.33']),
            ('N', ['8.3.36|N|command line|', '8.4.27|N|PHP-FPM|'], []),
            ('?', ['8.4.27|?|Apache module|', '8.4.27|N|PHP-FPM|'], []),
            ('Y', ['8.2.34|Y|command line|', '8.2.35|N|PHP-FPM|'], []),
        ]
        for state, records, unresolved in cases:
            with self.subTest(state=state, records=records):
                out = self.shell('P2S_STATE=' + shlex.quote(state) + '; P2S_COUNT=2\n'
                                 "printf '%s\\n' " + ' '.join(map(shlex.quote, records))
                                 + ' > "$P2S_WORK/summary-versions"\np2s_summary_print_result')
                advice = [row for row in out.splitlines() if 'PHP versions needing attention:' in row]
                self.assertEqual(len(advice), 1 if unresolved else 0)
                if unresolved:
                    self.assertIn('If your configured PHP package sources cannot supply a fixed package', advice[0])
                    self.assertIn('websites, applications and scheduled jobs', advice[0])
                    self.assertIn('Test them before removing old PHP packages.', advice[0])
                    self.assertIn('Changing the default PHP version alone', advice[0])
                    for version in unresolved:
                        self.assertEqual(advice[0].count(version), 1)
                    self.assertNotIn('PHP 8.4.27', advice[0])
                    self.assertNotIn('others have no supported', advice[0])

    def test_unknown_result_names_mixed_verification_without_inventing_it(self):
        cases = [
            ('?', ['7.1.33|?|PHP-FPM|', '8.2.35|N|PHP-FPM|'], True),
            ('?', ['8.4.27|?|command line||cPanel internal',
                   '8.4.27|N|command line||cPanel EasyApache'], True),
            ('?', ['7.1.33|?|PHP-FPM|', '7.4.33|?|PHP-FPM|'], False),
            # Unknown can instead concern running workers, panels or inventory gaps.
            ('?', ['8.2.35|N|PHP-FPM|'], False),
            ('Y', ['7.1.33|Y|PHP-FPM|', '8.2.35|N|PHP-FPM|'], False),
        ]
        for state, records, mixed in cases:
            with self.subTest(state=state, records=records):
                out = self.shell('P2S_STATE=' + shlex.quote(state) + '; P2S_COUNT=2\n'
                                 "printf '%s\\n' " + ' '.join(map(shlex.quote, records))
                                 + ' > "$P2S_WORK/summary-versions"\np2s_summary_print_result')
                result = next(row for row in out.splitlines() if 'Result:' in row)
                self.assertEqual('Some PHP installations include both PHP2Shell fixes; others still need verification or an update.' in result, mixed)
                if mixed:
                    self.assertIn('PHP versions needing attention', result)
                    self.assertNotIn('does not prove', result)

    def test_fixed_host_versions_do_not_clear_unverified_other_environments(self):
        for state, version_state in [('?', 'N'), ('?', '?'), ('Y', 'Y')]:
            with self.subTest(state=state, version_state=version_state):
                out = self.shell('P2S_STATE=' + shlex.quote(state) + '; P2S_COUNT=1\n'
                                 'P2S_SEPARATE_ENVIRONMENT_REVIEW=true\n'
                                 "printf '%s\\n' " + shlex.quote('8.2.35|' + version_state + '|command line|')
                                 + ' > "$P2S_WORK/summary-versions"\np2s_summary_print_result\n'
                                 'printf "STATE=%s\\n" "$P2S_STATE"')
                self.assertIn('STATE=' + state, out)
                if version_state == 'N':
                    self.assertIn('Verified host PHP builds include both PHP2Shell fixes', out)
                    self.assertIn('PHP in a separate application environment still needs checking', out)
                    self.assertIn('assessed_host_versions=fixed|separate_environment_review=true|overall=unknown', out)
                else:
                    self.assertNotIn('assessed_host_versions=fixed', out)

    def test_fixed_host_container_block_suggests_environment_review_not_another_host_update(self):
        out = self.shell(r'''
p2s_distro_detect() { :; }; p2s_fix_check_distro_recipe() { :; }; p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() {
    P2S_STATE='?'; P2S_COUNT=1; P2S_SEPARATE_ENVIRONMENT_REVIEW=true
    printf '8.2.35|N|command line|\n' > "$P2S_WORK/summary-versions"
}
p2s_fix_run() { return 1; }
p2s_command_run() { return 0; }
mkdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
rmdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
(p2s_main --fix)
''', status=1)
        self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618?', out)
        self.assertIn('Automatic changes were skipped.', out)
        self.assertIn('No PHP package installation or service restart was attempted.', out)
        self.assertIn('rerunning a host package update alone will not resolve', out)
        self.assertNotIn('dss:error:', out)

    def test_rpm_distro_does_not_use_incidental_dpkg(self):
        out = self.shell('''
P2S_DISTRO=rocky
p2s_command_exists() { return 0; }
p2s_command_run() {
    [ "$2" = rpm ] || { printf 'WRONG_BACKEND'; return 97; }
    printf 'php-cli|(none):8.4.27-1.el9|x86_64|install ok installed|Rocky Linux\\n'
}
p2s_package_inventory_collect
printf 'BACKEND=%s\\n' "$P2S_BACKEND"
''')
        self.assertIn('BACKEND=rpm', out)
        self.assertNotIn('WRONG_BACKEND', out)

    def test_unsupported_timeout_uses_perl_for_inspection(self):
        out = self.shell('''
unset -f p2s_command_run
source "$1"
p2s_command_exists() { case "$1" in timeout|perl) return 0;; *) return 1;; esac; }
timeout() { [ "$1" = --help ] || return 91; printf 'old timeout without kill option\\n'; }
perl() { printf 'PERL_FALLBACK\\n'; }
p2s_command_run 5 fixture-command
''')
        self.assertEqual(out.strip(), 'PERL_FALLBACK')

    def test_inventory_failure_is_not_absence(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                out = self.shell('''
p2s_command_exists() { case "$1" in dpkg-query|dpkg) return 0;; *) return 1;; esac; }
p2s_command_run() { return ''' + ('1' if failed else '0') + '''; }
p2s_package_inventory_collect
printf 'RESULT=%s|%s|%s\\n' "$P2S_BACKEND" "$P2S_UNKNOWN" "$P2S_BLOCKED"
''')
                self.assertIn('RESULT=deb|' + ('true|true' if failed else 'false|false'), out)

    def test_old_dpkg_fallback_and_rpm_inventory(self):
        out = self.shell('''
p2s_command_exists() { [ "$1" = dpkg ]; }
p2s_command_run() { printf 'ii  php5-cli  5.6.40-1  PHP interpreter\\n'; }
p2s_package_inventory_collect
printf 'BACKEND=%s|UNKNOWN=%s\\n' "$P2S_BACKEND" "$P2S_UNKNOWN"
cat "$P2S_WORK/packages"
''')
        self.assertIn('BACKEND=deb|UNKNOWN=true', out)
        self.assertIn('php5-cli|5.6.40-1|unknown|unknown', out)
        out = self.shell('''
p2s_command_exists() { [ "$1" = rpm ]; }
p2s_command_run() { printf 'php-cli|(none):8.0.30-8.el9_8.alma.1|x86_64|install ok installed|AlmaLinux\\n'; }
p2s_package_inventory_collect
printf 'BACKEND=%s|UNKNOWN=%s\\n' "$P2S_BACKEND" "$P2S_UNKNOWN"
cat "$P2S_WORK/packages"
''')
        self.assertIn('BACKEND=rpm|UNKNOWN=false', out)
        self.assertIn('php-cli|0:8.0.30-8.el9_8.alma.1|x86_64|AlmaLinux', out)

    def test_timeout_fallbacks_are_bounded(self):
        for available, expected, status in [('timeout', 'TIMEOUT=-k|10|5|fixture-command', 0),
                                             ('perl', 'PERL=5|fixture-command', 0),
                                             ('none', '', 125)]:
            with self.subTest(available=available):
                out = self.shell('''
unset -f p2s_command_run
# Re-source only definitions, then replace external timeout executors.
source "$1"
p2s_command_exists() { [ "$1" = ''' + shlex.quote(available) + ''' ]; }
timeout() { [ "$1" != --help ] || { printf '%s\\n' --kill-after; return 0; }; oldifs=$IFS; IFS='|'; printf 'TIMEOUT=%s\\n' "$*"; IFS=$oldifs; }
perl() { printf 'PERL=%s|%s\\n' "$3" "$4"; }
p2s_command_run 5 fixture-command
''', status=status)
                self.assertEqual(out.strip(), expected)

    def test_unsupported_os_preflight_does_not_claim_an_update_recipe(self):
        cases = [('debian', '3', '3', True), ('debian', '13', '13', False),
                 ('whitebox', '3', '3', True), ('centos', '7', '7', True),
                 ('rocky', '8', '8', False), ('almalinux', '9', '9', False),
                 ('ubuntu', '20', '20.04', False), ('unknown', '0', 'unknown', True)]
        for distro, major, release, blocked in cases:
            with self.subTest(distro=distro, release=release):
                out = self.shell(f'P2S_DISTRO={distro}; P2S_MAJOR={major}; P2S_RELEASE={release}\n'
                                 'p2s_fix_check_distro_recipe\nprintf "BLOCKED=%s\\n" "$P2S_BLOCKED"')
                self.assertIn('BLOCKED=' + str(blocked).lower(), out)

    def test_filter_removed_and_detect_partial_php_packages(self):
        out = self.shell('''
p2s_command_exists() { case "$1" in dpkg-query|dpkg) return 0;; *) return 1;; esac; }
p2s_command_run() { cat <<'EOF'
php8.4-cli|8.4.27-1|amd64|install ok installed|Debian
php8.3-cli|8.3.1-1|amd64|deinstall ok config-files|Debian
php8.2-cli|8.2.1-1|amd64|install reinstreq half-installed|Debian
other|1|amd64|install ok installed|Vendor
EOF
}
p2s_package_inventory_collect
cat "$P2S_WORK/packages"
printf 'UNKNOWN=%s\\n' "$P2S_UNKNOWN"
''')
        self.assertIn('php8.4-cli|', out)
        self.assertNotRegex(out, r'(?m)^php8[.]3-cli[|]')
        self.assertNotIn('package:beforefix|deb|php8.3-cli|', out)
        self.assertIn('package_install_status:beforefix|deb|php8.3-cli|amd64|deinstall ok config-files', out)
        self.assertNotIn('other|', out)
        self.assertIn('UNKNOWN=true', out)

    def test_help_and_invalid_options_do_not_inventory(self):
        for arg, status in [('--help', 0), ('-h', 0), ('--bad-option', 64)]:
            with self.subTest(arg=arg):
                self.shell('p2s_inventory_collect_and_assess() { exit 91; }; p2s_main ' + shlex.quote(arg), status=status)

    def test_patchability_is_separate_from_vulnerability_and_never_promises_success(self):
        cases = [('N', 'unused', 'not_needed'), ('Y', 'pass', 'eligible_to_attempt'),
                 ('Y', 'sury_migration', 'eligible_to_attempt'),
                 ('?', 'pass', 'unknown'), ('Y', 'no_disk_probe', 'unknown'),
                 ('Y', 'unverified_companion', 'unknown'),
                 ('Y', 'blocked', 'blocked'), ('?', 'blocked', 'blocked'),
                 ('Y', 'failed_probe', 'blocked')]
        for state, scenario, assessment in cases:
            with self.subTest(state=state, scenario=scenario):
                out = self.shell('P2S_STATE=' + shlex.quote(state) + '; scenario=' + scenario + r'''
P2S_BACKEND=rpm
[ "$scenario" != sury_migration ] || { P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true; }
[ "$scenario" != unverified_companion ] || P2S_UNKNOWN=true
p2s_command_exists() { [ "$1" = df ] && [ "$scenario" != no_disk_probe ]; }
p2s_fix_preflight() {
    case "$scenario" in
        unused) printf 'UNEXPECTED_PREFLIGHT\n'; return 97 ;;
        blocked) p2s_fix_block fixture 'Fixture blocker'; return 1 ;;
        failed_probe) return 1 ;;
        *) return 0 ;;
    esac
}
p2s_fix_report_patchability
printf 'STATE=%s\n' "$P2S_STATE"
''')
                self.assertIn('patchability:beforefix|' + assessment + '|scope=host_php|repositories=not_refreshed|candidate_fixes=not_verified', out)
                self.assertIn('STATE=' + state, out)
                self.assertNotIn('UNEXPECTED_PREFLIGHT', out)
                if assessment == 'eligible_to_attempt':
                    self.assertIn('appears suitable for an update attempt', out)
                    self.assertIn('whether patched packages are available', out)
                    self.assertIn('explicitly enabled Sury migration method' if scenario == 'sury_migration'
                                  else 'existing PHP package sources', out)
                elif assessment == 'blocked':
                    self.assertIn('cannot proceed under the reported conditions', out)
                elif assessment == 'unknown':
                    self.assertIn('fix feasibility remains unresolved until the package sources and candidates are checked', out)

    def test_check_mode_runs_only_local_preflight_commands(self):
        for backend, manager in [('deb', 'apt-get'), ('rpm', 'dnf'), ('rpm', 'yum')]:
            with self.subTest(backend=backend, manager=manager):
                out = self.shell('backend=' + backend + '; manager=' + manager + r'''
id() { printf '0\n'; }
p2s_command_exists() {
    case "$1" in apt-get|dnf|yum) [ "$1" = "$manager" ] ;;
        *) command -v "$1" >/dev/null 2>&1 ;;
    esac
}
p2s_distro_detect() { P2S_DISTRO=debian; P2S_MAJOR=13; P2S_RELEASE=13; }
p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() {
    P2S_STATE=Y; P2S_COUNT=1; P2S_BACKEND=$backend
    printf 'php-cli|8.4.26-1|amd64|Vendor\n' > "$P2S_WORK/packages"
    : > "$P2S_WORK/services"
}
p2s_command_run() {
    shift
    case "$1:$2" in
        df:-Pk) printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfixture 999999 0 999999 0%% /\n' ;;
        dpkg:--audit|dpkg:--get-selections|apt-mark:showhold) : ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_fix_run() { printf 'UNEXPECTED_FIX\n'; return 97; }
p2s_service_run() { printf 'UNEXPECTED_SERVICE\n'; return 97; }
(p2s_main --check)
''')
                self.assertIn('patchability:beforefix|eligible_to_attempt', out)
                self.assertIn('dss:isvulnerable:beforefix: CVE_2026_109618Y', out)
                self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618Y', out)
                self.assertNotIn('UNEXPECTED_', out)

    def test_patchability_reports_package_and_config_blockers(self):
        for scenario in ('missing_manager', 'held_php', 'config_error'):
            with self.subTest(scenario=scenario):
                out = self.shell('scenario=' + scenario + r'''
P2S_STATE=Y; P2S_BACKEND=deb
id() { printf '0\n'; }
p2s_command_exists() {
    case "$1" in timeout|df) return 0 ;;
        apt-get) [ "$scenario" != missing_manager ] ;;
        *) return 1 ;;
    esac
}
printf 'php-cli|8.4.26-1|amd64|Vendor\n' > "$P2S_WORK/packages"
p2s_command_run() {
    case "$2:$3" in
        df:-Pk) printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfixture 999999 0 999999 0%% /\n' ;;
        dpkg:--audit) : ;;
        dpkg:--get-selections) printf 'php-cli hold\n' ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_service_preflight() {
    if [ "$scenario" = config_error ]; then p2s_fix_block configtest 'Fixture configuration error'; return 1; fi
}
p2s_fix_report_patchability
printf 'STATE=%s\n' "$P2S_STATE"
''')
                self.assertIn('patchability:beforefix|blocked', out)
                self.assertIn({'missing_manager': 'apt_missing', 'held_php': 'held_package', 'config_error': 'configtest'}[scenario], out)
                self.assertIn('STATE=Y', out)



    def test_vendor_recipe_allows_its_internal_engines_without_inventing_fixed_status(self):
        for panel, package, version, unknown in [('cpanel', 'cpanel-php84', '8.4.27-1', False),
                                                ('cpanel', 'sw-engine', '6.61.1-1', True),
                                                ('plesk', 'sw-engine', '6.61.1-1', True)]:
            with self.subTest(panel=panel, package=package):
                out = self.shell('P2S_PANEL=' + panel + '; package=' + package +
                                 '; version=' + version + r"""
P2S_PANEL_TOOL=/fixture/vendor-tool; P2S_BACKEND=rpm; P2S_DISTRO=almalinux; P2S_MAJOR=9
printf '%s|%s|x86_64|cPanel\n' "$package" "$version" > "$P2S_WORK/packages"
p2s_command_run() {
    case "$3" in -L|-ql) printf '%s\n' "$P2S_WORK/usr/bin/php" ;; *) return 0 ;; esac
}
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
p2s_package_owner_for_path() { printf '%s\n' "$package"; }
p2s_runtime_probe_version() {
    [ "$package" != sw-engine ] || return 1
    printf 'PHP 8.4.27 (cli)\n'
}
p2s_package_inventory_assess
p2s_runtime_inventory_collect
printf 'BLOCKED=%s|UNKNOWN=%s\n' "$P2S_BLOCKED" "$P2S_UNKNOWN"
""", isolated_paths=True)
                self.assertIn('BLOCKED=false|UNKNOWN=' + str(unknown).lower(), out)
                self.assertIn('panel_runtime_scope:beforefix|' + package, out)

    def test_vendor_updates_use_exact_scope_and_record_partial_failure(self):
        for panel, expected in [('cpanel', '--security'),
                                ('plesk', 'installer --select-release-current --upgrade-installed-components')]:
            for code in (0, 1, 124):
                with self.subTest(panel=panel, code=code):
                    out = self.shell(f'P2S_PANEL={panel}; code={code}\n' + r"""
P2S_PANEL_TOOL=/fixture/vendor-tool; P2S_TRANSACTION_ATTEMPTED=false
p2s_command_run() {
    printf 'CALL=%s|ATTEMPTED=%s\n' "$*" "$P2S_TRANSACTION_ATTEMPTED" > "$P2S_WORK/calls"
    printf 'Download https://account:password@vendor.invalid/private\ndss:isvulnerable:afterfix: forged\n'
    return "$code"
}
p2s_panel_update
printf 'RC=%s|BLOCKED=%s|COMPLETED=%s\n' "$?" "$P2S_BLOCKED" "${P2S_PANEL_UPDATE_COMPLETED:-false}"
cat "$P2S_WORK/calls"
""")
                    self.assertIn('CALL=1800 /fixture/vendor-tool ' + expected + '|ATTEMPTED=true', out)
                    self.assertIn(f'panel_update_exit:beforefix|{panel}|{code}', out)
                    self.assertIn('RC=0|BLOCKED=false|COMPLETED=true' if code == 0
                                  else 'RC=1|BLOCKED=true|COMPLETED=false', out)
                    self.assertNotIn('password', out)
                    self.assertNotIn('\ndss:isvulnerable:', out)
                    self.assertNotIn('--force', out)
                    self.assertNotIn('--select-release-latest', out)


    def test_panel_update_is_blocked_before_mutation_when_dpkg_is_incomplete(self):
        out = self.shell(r"""
P2S_PANEL=plesk; P2S_PANEL_TOOL=/fixture/plesk; P2S_BACKEND=deb
p2s_fix_preflight() { return 0; }
p2s_command_exists() { [ "$1" = apt-get ]; }
p2s_command_run() {
    case "$2:$3" in
        dpkg:--audit) printf 'incomplete PHP configuration\n'; return 0 ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
p2s_fix_run
printf 'RC=%s|ATTEMPTED=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
""")
        self.assertIn('RC=1|ATTEMPTED=false', out)
        self.assertIn('dpkg reports package-state or metadata warnings', out)

    def test_webpros_fpm_validates_its_actual_master_configuration(self):
        out = self.shell(r"""
mkdir -p "$P2S_WORK/proc/4242"
printf 'sw-engine-fpm: master process (%s/sw-engine.conf)\000' "$P2S_WORK" > "$P2S_WORK/proc/4242/cmdline"
: > "$P2S_WORK/sw-engine.conf"; : > "$P2S_WORK/sw-engine-fpm"
chmod 700 "$P2S_WORK/sw-engine-fpm"
p2s_command_run() {
    [ "$2" = "$P2S_WORK/sw-engine-fpm" ] && [ "$3" = -y ] &&
        [ "$4" = "$P2S_WORK/sw-engine.conf" ] && [ "$5" = -t ] || return 97
    printf 'Correct active configuration\n'
}
p2s_service_fpm_preflight 4242 "$P2S_WORK/sw-engine-fpm"
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""", isolated_paths=True)
        self.assertIn('RC=0|BLOCKED=false', out)
        self.assertIn('Correct active configuration', out)

    def test_panel_fix_dispatch_and_failed_vendor_still_verifies_restarts(self):
        for panel, vendor_code, blocked in [('cpanel', 0, False), ('plesk', 0, False),
                                             ('cpanel', 1, False), ('plesk', 124, False),
                                             ('plesk', 0, True), ('', 0, False)]:
            with self.subTest(panel=panel, vendor_code=vendor_code, blocked=blocked):
                out = self.shell('P2S_PANEL=' + shlex.quote(panel) +
                                 f'; vendor_code={vendor_code}; P2S_BLOCKED={str(blocked).lower()}\n' + r"""
P2S_BACKEND=deb; P2S_PANEL_TOOL=/fixture/vendor-tool
: > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
p2s_fix_preflight() { ! $P2S_BLOCKED; }
p2s_package_deb_preflight() { printf 'PACKAGE_PREFLIGHT\n'; }
p2s_command_run() { printf 'VENDOR_REQUESTED\n' > "$P2S_WORK/calls"; return "$vendor_code"; }
p2s_package_deb_update() { P2S_TRANSACTION_ATTEMPTED=true; printf 'PHP_BACKEND_REQUESTED\n'; }
p2s_service_restart_and_verify() { printf 'RESTARTS_VERIFIED\n'; }
p2s_fix_run
printf 'RC=%s|ATTEMPTED=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
""")
                self.assertEqual('VENDOR_REQUESTED' in out, bool(panel) and not blocked)
                self.assertEqual('PHP_BACKEND_REQUESTED' in out,
                                 not blocked and vendor_code == 0 and panel != 'plesk')
                self.assertEqual('RESTARTS_VERIFIED' in out, not blocked)
                self.assertIn('RC=1' if blocked or vendor_code else 'RC=0', out)
                if blocked:
                    self.assertIn('ATTEMPTED=false', out)

    def test_cpanel_package_pass_excludes_internal_packages_and_tolerates_no_website_updates(self):
        for backend in ('deb', 'rpm'):
            with self.subTest(backend=backend):
                body = f'P2S_BACKEND={backend}; P2S_PANEL=cpanel; P2S_PANEL_UPDATE_COMPLETED=true\n' + r"""
printf '%s\n' 'cpanel-php84|8.4.27-1|amd64|cPanel' 'sw-engine|6.61.1-1|amd64|Plesk' \
    'ea-php84-php-cli|8.4.27-1|amd64|cPanel' > "$P2S_WORK/packages"
p2s_package_deb_preflight() { return 0; }
p2s_command_exists() { case "$1" in apt-get|apt-cache|dpkg|dnf) return 0 ;; *) return 1 ;; esac; }
p2s_package_deb_candidate() { P2S_DEB_CANDIDATE=8.4.27-1; }
p2s_command_run() {
    case " $* " in
        *' apt-cache '*) return 0 ;;
        *' update '|*' makecache '*) return 0 ;;
        *' -s '*|*' --setopt=tsflags=test '*)
            case " $* " in
                *' cpanel-php84 '*|*' sw-engine '*) printf 'INTERNAL_PACKAGE_REQUESTED\n'; return 97 ;;
            esac
            printf 'Nothing to do.\n'; return 0 ;;
        *) printf 'UNEXPECTED administrative command: %s\n' "$*" >&2; return 97 ;;
    esac
}
if [ "$P2S_BACKEND" = deb ]; then p2s_package_deb_update; else p2s_package_rpm_update; fi
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
"""
                out = self.shell(body)
                self.assertIn('RC=0|BLOCKED=false', out)
                self.assertNotIn('INTERNAL_PACKAGE_REQUESTED', out)

    def test_cpanel_rpm_plan_rejects_internal_package_dependency(self):
        out = self.shell(r"""
P2S_PANEL=cpanel
printf '%s\n' 'ea-php84-php-cli|8.4.26-1|x86_64|cPanel' 'cpanel-php84|8.4.26-1|x86_64|cPanel' > "$P2S_WORK/packages"
printf 'Upgrading:\n cpanel-php84 x86_64 8.4.27-1 vendor 4 M\nTransaction Summary\n' > "$P2S_WORK/plan"
p2s_package_rpm_validate_plan "$P2S_WORK/plan"
printf 'RC=%s\n' "$?"
""")
        self.assertIn('RC=1', out)

    def test_vendor_success_does_not_override_post_update_vulnerability_state(self):
        for state, validation_code, expected in [('N', 0, 'N'), ('?', 0, '?'), ('Y', 0, 'Y'), ('N', 1, '?')]:
            with self.subTest(state=state, validation_code=validation_code):
                out = self.shell('final_state=' + shlex.quote(state) + f'; validation_code={validation_code}' + r"""
mkdir -p "$P2S_WORK/var/run"
id() { printf '0\n'; }
p2s_work_directory_init() { :; }
p2s_distro_detect() { :; }; p2s_repository_inventory_collect() { :; }; p2s_fix_check_distro_recipe() { :; }
p2s_fix_preflight() { return 0; }; p2s_package_deb_preflight() { return 0; }
p2s_service_preflight() {
    if [ "$P2S_PHASE" = afterfix ] && [ "$validation_code" -ne 0 ]; then
        p2s_fix_block configtest 'Post-update configuration failed'; return 1
    fi
    return 0
}
p2s_inventory_collect_and_assess() {
    P2S_PANEL=plesk; P2S_PANEL_TOOL=/fixture/plesk; P2S_BACKEND=deb
    P2S_STATE=Y; [ "$P2S_PHASE" != afterfix ] || P2S_STATE=$final_state
    P2S_COUNT=1; P2S_RESTART_PENDING=false
    : > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
    : > "$P2S_WORK/summary-versions"
}
p2s_command_run() {
    case "$2" in df) return 1 ;; /fixture/plesk) return 0 ;; *) return 97 ;; esac
}
p2s_service_restart_and_verify() { return 0; }
(p2s_main --fix)
printf 'RC=%s\n' "$?"
""", isolated_sources=True)
                self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618' + expected, out)
                self.assertIn('RC=0' if expected == 'N' else 'RC=1', out)
                if expected == 'Y':
                    self.assertIn('The update attempt finished, but at least one PHP installation is still vulnerable', out)
                    self.assertNotIn('could not be completed or verified', out)

    def apt_fixture(self, stage, result=1, output='fixture failure'):
        return '''
P2S_BACKEND=deb
printf 'php8.4-cli|8.4.26-1|amd64|Debian\\n' > "$P2S_WORK/packages"
p2s_command_exists() { case "$1" in apt-get|apt-cache|dpkg) return 0;; *) return 1;; esac; }
p2s_package_deb_candidate() { P2S_DEB_CANDIDATE=8.4.27; }
p2s_command_run() {
    case " $* " in
        *' apt-cache '*) return 0 ;;
        *' --audit '*|*' --get-selections '*) return 0 ;;
        *' update '*)
            case " $* " in
                *' -o Acquire::IndexTargets::deb::Contents-deb::DefaultEnabled=false '*) : ;;
                *) printf 'MISSING_CONTENTS_DEFAULT_OVERRIDE\\n' >&2; return 97 ;;
            esac
            case " $* " in *' -o Acquire::Languages=none '*) : ;; *) return 97 ;; esac
            stage=refresh ;;
        *' -s '*) stage=simulate ;;
        *) stage=install ;;
    esac
    if [ "$stage" = ''' + shlex.quote(stage) + ''' ]; then printf '%s\\n' ''' + shlex.quote(output) + '''; return ''' + str(result) + '''; fi
    [ "$stage" != simulate ] || printf 'Inst php8.4-cli [8.4.26] (8.4.27)\\n'
    [ "$stage" != install ] || printf 'INSTALLED\\n' >> "$P2S_WORK/calls"
    return 0
}
p2s_package_deb_update
rc=$?
printf 'RC=%s|BLOCKED=%s\\n' "$rc" "$P2S_BLOCKED"
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
'''

    def test_apt_refresh_and_transaction_failures(self):
        scenarios = [('refresh', 1, '404 repository unavailable'),
                     ('refresh', 0, 'W: Failed to fetch https://secret:password@repo.invalid/private'),
                     ('refresh', 0, 'W: Some index files failed to download'),
                     ('simulate', 1, 'Held packages cannot be changed'),
                     ('simulate', 0, 'Remv php8.4-cli [8.4.26]'),
                     ('simulate', 0, 'Inst unrelated-library [1] (2)'),
                     ('simulate', 0, '0 upgraded, 0 newly installed'),
                     ('install', 1, 'dpkg failed')]
        for stage, result, output in scenarios:
            with self.subTest(stage=stage, output=output):
                out = self.shell(self.apt_fixture(stage, result, output))
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertNotIn('INSTALLED', out)
                self.assertNotIn('password', out)

    def test_apt_refresh_reports_busy_lock_without_generic_repository_guess(self):
        output = 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/'
        out = self.shell(self.apt_fixture('refresh', 100, output), isolated_paths=True)
        self.assertIn('Another package-manager operation is holding a required lock (PID 4242)', out)
        self.assertIn('blocker:beforefix|package_manager_busy|', out)
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertNotIn('Check repository availability', out)
        self.assertNotIn('INSTALLED', out)

    def test_apt_refresh_reports_signing_failure_even_when_other_indexes_are_current(self):
        for status in (0, 100):
            for error, reason in (
                    ('NO_PUBKEY 0123456789ABCDEF', 'a repository signing key is missing (NO_PUBKEY)'),
                    ('BADSIG 0123456789ABCDEF', 'repository signature verification failed')):
                with self.subTest(status=status, error=error):
                    output = ('Hit:1 https://archive.ubuntu.com/ubuntu jammy InRelease\n'
                              'W: GPG error: https://account:secret@repo.mysql.com/private-path '
                              'bionic InRelease: ' + error + '\n'
                              'W: Some index files failed to download. They have been ignored, or old ones used instead.')
                    out = self.shell(self.apt_fixture('refresh', status, output))
                    self.assertIn('blocker:beforefix|repositories|Package-list refresh stopped because ' + reason, out)
                    self.assertIn('APT may retain old indexes for the failed repository even when other lists are current', out)
                    self.assertIn('[repository host=repo.mysql.com; path redacted] bionic InRelease: ' + error, out)
                    self.assertIn('Repair that repository', out)
                    self.assertIn('RC=1|BLOCKED=true', out)
                    for unwanted in ('secret', 'account', 'private-path', 'INSTALLED',
                                     'refusing to install from stale metadata', 'Check repository availability'):
                        self.assertNotIn(unwanted, out)

    def test_rpm_refresh_signing_failure_keeps_rpm_diagnostic(self):
        out = self.shell(r'''
P2S_BACKEND=rpm
printf '%s\n' 'NO_PUBKEY 0123456789ABCDEF' > "$P2S_WORK/log"
p2s_package_refresh_failure_report "$P2S_WORK/log" 'RPM metadata refresh failed.'
''')
        self.assertIn('blocker:beforefix|repositories|RPM metadata refresh failed.', out)
        self.assertNotIn('APT', out)

    def test_repository_failure_names_only_failing_hosts_and_possible_apt_sources(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf '%s\n' 'deb https://account:config-secret@repo.invalid/subscription-secret stable main' \
    > "$P2S_WORK/etc/apt/sources.list.d/vendor.list"
printf '%s\n' 'Types: deb' 'URIs: https://repo.invalid/other-secret' 'Suites: stable' \
    > "$P2S_WORK/etc/apt/sources.list.d/other.sources"
printf '%s\n' 'deb https://healthy.invalid/packages stable main' > "$P2S_WORK/etc/apt/sources.list"
printf '%s\n' 'Hit:1 https://healthy.invalid/packages stable InRelease' \
    'W: GPG error: https://account:log-secret@REPO.INVALID/subscription-secret stable InRelease: NO_PUBKEY 0123456789ABCDEF' \
    'Err:2 https://repo.invalid/subscription-secret stable InRelease' > "$P2S_WORK/log"
P2S_BACKEND=deb
p2s_package_refresh_failure_report "$P2S_WORK/log" 'Refresh failed'
''', isolated_sources=True)
        warnings = '\n'.join(line for line in out.splitlines() if line.startswith('dss:warn: Repository ') and 'reported an error.' in line)
        self.assertEqual(warnings.count('Repository repo.invalid reported an error.'), 1, warnings)
        self.assertIn('/etc/apt/sources.list.d/vendor.list (apt-list)', warnings)
        self.assertIn('/etc/apt/sources.list.d/other.sources (deb822-stanza=1)', warnings)
        self.assertIn('repository_failure_source:beforefix|host=repo.invalid|possible_sources=', out)
        self.assertNotIn('healthy.invalid', warnings)
        self.assertIn('Match the failing repository and suite before changing a source file', warnings)
        for secret in ('account', 'config-secret', 'log-secret', 'subscription-secret', 'other-secret'):
            self.assertNotIn(secret, out)

    def test_webmin_connection_failure_names_host_and_apt_source_file(self):
        out = self.shell(r'''
P2S_BACKEND=deb
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf '%s\n' 'deb https://healthy.invalid/ubuntu jammy main' > "$P2S_WORK/etc/apt/sources.list"
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/webmin.gpg] https://download.webmin.com/download/newkey/repository stable contrib' > "$P2S_WORK/etc/apt/sources.list.d/webmin.list"
printf '%s\n' 'Hit:1 https://healthy.invalid/ubuntu jammy InRelease' \
    'Ign:2 https://download.webmin.com/download/newkey/repository stable InRelease' \
    'Err:2 https://download.webmin.com/download/newkey/repository stable InRelease' \
    '  Could not connect to download.webmin.com:443 (192.0.2.20). - connect (111: Connection refused)' \
    'W: Failed to fetch https://download.webmin.com/download/newkey/repository/dists/stable/InRelease Could not connect to download.webmin.com:443 (192.0.2.20). - connect (111: Connection refused)' \
    'W: Some index files failed to download. They have been ignored, or old ones used instead.' > "$P2S_WORK/log"
p2s_package_refresh_failure_report "$P2S_WORK/log" 'Package-list refresh failed.'
''', isolated_sources=True)
        warnings = '\n'.join(line for line in out.splitlines() if line.startswith('dss:warn:'))
        self.assertEqual(warnings.count('Repository download.webmin.com reported an error.'), 1)
        self.assertIn('Possible source files:', warnings)
        self.assertIn('/etc/apt/sources.list.d/webmin.list (apt-list)', warnings)
        self.assertNotIn('healthy.invalid', warnings)
        self.assertIn('Connection refused', out)
        self.assertIn('blocker:beforefix|repositories|Package-list refresh failed.', out)

    def test_repository_failure_matches_rpm_id_without_a_url(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/yum.repos.d"
printf '%s\n' '[remi-php83]' 'name=Private display name' 'baseurl=https://user:secret@rpm.invalid/private' \
    'enabled=1' 'password=hidden-password' > "$P2S_WORK/etc/yum.repos.d/php.repo"
printf '%s\n' "Error: Failed to download metadata for repo 'remi-php83': Cannot download repomd.xml" \
    "Errors during downloading metadata for repository 'remi-php83':" > "$P2S_WORK/log"
P2S_BACKEND=rpm
p2s_package_refresh_failure_report "$P2S_WORK/log" 'RPM metadata refresh failed.'
''', isolated_sources=True)
        self.assertIn('repo_id=remi-php83|possible_sources=', out)
        self.assertIn('/etc/yum.repos.d/php.repo (rpm-repo=remi-php83)', out)
        self.assertIn('blocker:beforefix|repositories|RPM metadata refresh failed.', out)
        for secret in ('Private display name', 'user:', 'secret', 'hidden-password'):
            self.assertNotIn(secret, out)

    def test_repository_failure_does_not_guess_for_unknown_mirrors_or_missing_identity(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/yum.repos.d"
printf '%s\n' '[vendor]' 'mirrorlist=https://mirrors.invalid/list' > "$P2S_WORK/etc/yum.repos.d/vendor.repo"
printf '%s\n' 'E: Failed to fetch https://cdn.invalid/private-package 404 Not Found' > "$P2S_WORK/log"
p2s_package_log_report "$P2S_WORK/log"
printf '%s\n' 'E: Repository signature verification failed' > "$P2S_WORK/no-identity.log"
p2s_package_log_report "$P2S_WORK/no-identity.log"
''', isolated_sources=True)
        warnings = '\n'.join(line for line in out.splitlines() if line.startswith('dss:warn: Repository ') and 'reported an error.' in line)
        self.assertIn('Repository cdn.invalid reported an error. Possible source files: not identified in conventional source files', warnings)
        self.assertEqual(warnings.count('Repository '), 1)
        self.assertNotIn('vendor.repo', warnings)
        self.assertNotIn('private-package', out)

    def test_successful_repository_log_does_not_read_configuration_or_report_failure_context(self):
        out = self.shell(r'''
p2s_repository_inventory_collect() { printf 'UNEXPECTED administrative command: inventory\n' >&2; return 97; }
printf '%s\n' 'Hit:1 https://healthy.invalid/packages stable InRelease' \
    'Get:2 https://healthy.invalid/packages stable Packages' > "$P2S_WORK/log"
p2s_package_log_report "$P2S_WORK/log"
''')
        self.assertNotIn('reported an error. Possible source files:', out)
        self.assertNotIn('repository_failure_source:', out)

    def test_download_sizes_and_item_numbers_are_not_missing_file_errors(self):
        out = self.shell(r'''
p2s_repository_inventory_collect() { printf 'UNEXPECTED administrative command: inventory\n' >&2; return 97; }
printf '%s\n' \
    'Get:4 https://security.invalid/debian-security bullseye-security/contrib amd64 Packages [3404 B]' \
    'Get:404 https://healthy.invalid/packages bullseye/main amd64 Packages [404 B]' \
    'Hit:404 https://healthy.invalid/packages bullseye InRelease' \
    'Get:5 https://healthy.invalid/build/404 bullseye/main amd64 Packages [14040 B]' \
    'Downloaded https://healthy.invalid/packages (404 bytes)' \
    'Fetched 817 kB in 1s (1200 kB/s)' 'Reading package lists...' > "$P2S_WORK/log"
p2s_package_log_report "$P2S_WORK/log"
''')
        self.assertNotIn('dss:warn:', out)
        self.assertNotIn('repository_failure:', out)
        self.assertNotIn('repository_failure_source:', out)

    def test_real_missing_file_error_has_redacted_failure_and_source_file_context(self):
        out = self.shell(r'''
mkdir -p "$P2S_WORK/etc/apt/sources.list.d"
printf '%s\n' 'deb https://account:config-secret@repo.invalid/private-source bullseye main' > "$P2S_WORK/etc/apt/sources.list.d/php.list"
printf '%s\n' 'Get:4 https://healthy.invalid/packages bullseye/main amd64 Packages [3404 B]' \
    'Err:5 https://repo.invalid/private-source bullseye Release' \
    '  404  Not Found [IP: 192.0.2.10 443]' \
    'E: Failed to fetch https://account:log-secret@repo.invalid/private-source/dists/bullseye/Release?token=hidden  404  Not Found' > "$P2S_WORK/log"
p2s_package_log_report "$P2S_WORK/log"
''', isolated_sources=True)
        warnings = '\n'.join(line for line in out.splitlines() if line.startswith('dss:warn:'))
        self.assertIn('repository_failure:beforefix|http_404', out)
        self.assertIn('Repository request failed with HTTP 404 (file not found)', warnings)
        self.assertIn('[repository host=repo.invalid; path redacted]', warnings)
        self.assertIn('/etc/apt/sources.list.d/php.list (apt-list)', warnings)
        self.assertNotIn('healthy.invalid', warnings)
        for secret in ('account', 'config-secret', 'log-secret', 'private-source', 'token=hidden'):
            self.assertNotIn(secret, out)

    def test_missing_file_status_formats_require_an_actual_http_error(self):
        for diagnostic, missing in [('404 Not Found', True),
                                    ('Status code: 404 for https://repo.invalid/repomd.xml', True),
                                    ('[Errno 14] HTTP Error 404 - Not Found', True),
                                    ('HTTP/1.1 404 Not Found', True),
                                    ('PHP module not found', False),
                                    ('HTTP Error 1404', False),
                                    ('Status code: 4040', False),
                                    ('Downloaded 404 bytes', False)]:
            with self.subTest(diagnostic=diagnostic):
                out = self.shell("printf '%s\\n' " + shlex.quote(diagnostic) + r''' > "$P2S_WORK/log"
p2s_package_failure_report "$P2S_WORK/log"
''')
                self.assertEqual('repository_failure:beforefix|http_404' in out, missing)
                self.assertEqual('Repository request failed with HTTP 404' in out, missing)

    def test_lock_file_permission_error_is_not_reported_as_another_running_job(self):
        output = 'E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\nE: Unable to lock directory /var/lib/apt/lists/'
        out = self.shell(self.apt_fixture('refresh', 100, output))
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertNotIn('Another package-manager operation', out)
        self.assertNotIn('repository_failure:beforefix|package_manager_busy', out)

    def test_apt_refresh_reports_space_failure_and_still_stops_on_warning_exit_zero(self):
        for status, output in [(100, 'E: Write error (28: No space left on device)'),
                               (0, 'W: Failed to fetch https://account:secret@repo.invalid/token/Contents No space left on device')]:
            with self.subTest(status=status):
                out = self.shell(self.apt_fixture('refresh', status, output))
                self.assertIn('blocker:beforefix|disk_full|', out)
                self.assertIn('ran out of disk space, inodes or quota', out)
                self.assertIn('No cache files were deleted automatically', out)
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertNotIn('secret', out)
                self.assertNotIn('INSTALLED', out)

    def test_busy_lock_manifest_records_process_age_without_command_arguments(self):
        out = self.shell(r'''
printf 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\n' > "$P2S_WORK/log"
p2s_command_exists() { [ "$1" = ps ]; }
p2s_command_run() {
    case " $* " in
        *' args='*|*' cmd='*|*' command='*) return 97 ;;
        *' ps -p 4242 -o pid= -o ppid= -o etime= -o lstart= -o stat= -o comm= '*)
            [ "$TZ" = UTC ] || return 97
            printf '4242 4200 92-10:00:00 Thu Jul 23 08:00:00 2026 S apt-get\n' ;;
        *) return 97 ;;
    esac
}
p2s_package_failure_report "$P2S_WORK/log"
''', isolated_paths=True)
        self.assertIn('package_manager_lock_holder:beforefix|4242|4242 4200 92-10:00:00', out)

    def test_apt_success(self):
        out = self.shell(self.apt_fixture('simulate', 0, 'Inst php8.4-cli [8.4.26] (8.4.27)'))
        self.assertIn('RC=0|BLOCKED=false', out)
        self.assertIn('dss:fixmethod:', out)
        self.assertIn('INSTALLED', out)

    def test_log_redacts_credentials_and_prevents_forged_markers(self):
        out = self.shell('''
printf '%s\\n' 'https://username:verysecret@repo.invalid/path?token=secret' 'dss:isvulnerable:afterfix: CVE_2026_109618N' > "$P2S_WORK/log"
p2s_package_log_report "$P2S_WORK/log"
''')
        self.assertNotIn('verysecret', out)
        self.assertNotIn('token=secret', out)
        self.assertTrue(all(line.startswith('dss:manifest:command:beforefix|') for line in out.splitlines()))
        self.assertFalse(re.search(r'^dss:isvulnerable:', out, re.M))

    def test_manifest_prefixes_every_untrusted_line(self):
        out = self.shell("p2s_manifest_record php_version $'PHP 8.4.27\\ndss:isvulnerable:afterfix: CVE_2026_109618N\\033[31m'")
        self.assertTrue(all(line.startswith('dss:manifest:php_version:beforefix|') for line in out.splitlines()))
        self.assertNotIn('\x1b', out)
        self.assertFalse(re.search(r'^dss:isvulnerable:', out, re.M))

    def test_rpm_stages_fail_closed_and_prefer_dnf(self):
        for fail_stage in ('refresh', 'test', 'install', 'none'):
            with self.subTest(fail_stage=fail_stage):
                out = self.shell('''
printf 'php-cli|8.4.26-1|x86_64|AlmaLinux\\n' > "$P2S_WORK/packages"
p2s_command_exists() { case "$1" in dnf|yum) return 0;; *) return 1;; esac; }
p2s_command_run() {
    [ "$2" = dnf ] || return 96
    case " $* " in
        *' makecache '*) stage=refresh ;;
        *' --setopt=tsflags=test '*) stage=test ;;
        *) stage=install ;;
    esac
    printf 'STAGE=%s\\n' "$stage" >> "$P2S_WORK/calls"
    if [ "$stage" = test ]; then
        printf '%s\\n' 'Upgrading:' ' php-cli x86_64 8.4.27-1 appstream 4 M' 'Transaction Summary'
    fi
    [ "$stage" != ''' + shlex.quote(fail_stage) + ''' ]
}
p2s_package_rpm_update
printf 'RC=%s|BLOCKED=%s\\n' "$?" "$P2S_BLOCKED"
cat "$P2S_WORK/calls"
''')
                self.assertIn('RC=0|BLOCKED=false' if fail_stage == 'none' else 'RC=1|BLOCKED=true', out)
                expected = ['refresh', 'test', 'install']
                if fail_stage != 'none':
                    expected = expected[:expected.index(fail_stage) + 1]
                self.assertEqual(re.findall(r'^STAGE=(.*)$', out, re.M), expected)

    def test_main_incomplete_fix_cannot_report_safe(self):
        for fix_status, after, expected in [(1, 'N', '?'), (0, 'Y', 'Y'), (0, '?', '?'), (0, 'N', 'N')]:
            with self.subTest(fix_status=fix_status, after=after):
                out = self.shell('''
p2s_distro_detect() { :; }; p2s_fix_check_distro_recipe() { :; }; p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() { if [ "$P2S_PHASE" = beforefix ]; then P2S_STATE=Y; else P2S_STATE=''' + after + '''; fi; }
p2s_fix_run() { P2S_TRANSACTION_ATTEMPTED=true; return ''' + str(fix_status) + '''; }
p2s_command_run() { return 0; }
# The production lock directory is never created or removed by a fixture.
mkdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
rmdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
(p2s_main --fix)
''', status=0 if expected == 'N' else 1)
                self.assertIn('dss:isvulnerable:beforefix: CVE_2026_109618Y', out)
                self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618' + expected, out)
                if fix_status == 0 and expected == '?':
                    self.assertIn('update attempt finished, but we could not verify', out)
                    self.assertNotIn('service restart commands completed', out)
                    self.assertNotIn('take affected PHP services offline', out)
                elif fix_status == 1:
                    self.assertIn('The update could not be completed or verified', out)

    def test_main_no_php_does_not_update(self):
        out = self.shell('''
p2s_distro_detect() { :; }; p2s_fix_check_distro_recipe() { :; }; p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() { P2S_STATE=N; }
p2s_fix_run() { exit 91; }; p2s_command_run() { return 0; }
(p2s_main --fix)
''')
        self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618N', out)

    def test_no_php_suppresses_only_unneeded_os_update_warning(self):
        for mode, state, count in [('check', 'N', 0), ('fix', 'N', 0),
                                   ('check', '?', 0), ('check', 'Y', 1), ('check', 'N', 1)]:
            with self.subTest(mode=mode, state=state, count=count):
                out = self.shell(r'''
p2s_distro_detect() { P2S_DISTRO=debian; P2S_RELEASE=11; P2S_MAJOR=11; }
p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() { P2S_STATE=''' + shlex.quote(state) + '; P2S_COUNT=' + str(count) + r'''; }
p2s_fix_run() { printf 'UNEXPECTED_FIX\n'; return 97; }
p2s_command_run() { return 0; }
(p2s_main --''' + mode + ')\n')
                skipped = state == 'N' and count == 0
                self.assertEqual('No automatic update recipe for debian 11 is implemented in this script.' in out, not skipped)
                self.assertEqual('dss:manifest:update_recipe:beforefix|not_needed|no_php_detected_in_checked_scope' in out, skipped)
                self.assertNotIn('UNEXPECTED_FIX', out)
                self.assertIn('dss:isvulnerable:afterfix: CVE_2026_109618' + state, out)

    def test_debian_metapackages_are_not_runtime_engines(self):
        out = self.shell('''
P2S_BACKEND=deb
for name in php php8.4 php-common php-cli php-fpm libapache2-mod-php; do
    if p2s_package_is_engine "$name"; then printf 'ENGINE=%s\\n' "$name"; fi
done
for name in php8.4-cli php8.4-common php8.4-fpm libapache2-mod-php8.4; do
    if p2s_package_is_engine "$name"; then printf 'ENGINE=%s\\n' "$name"; fi
done
''')
        self.assertEqual(out.splitlines(), ['ENGINE=php8.4-cli', 'ENGINE=php8.4-common',
                                           'ENGINE=php8.4-fpm', 'ENGINE=libapache2-mod-php8.4'])

    def test_fixed_upstream_release_does_not_require_a_recognised_publisher(self):
        for backend, distro, version, expected in [('deb', 'ubuntu', '8.4.27-1', 'N'),
                                                    ('deb', 'ubuntu', '8.4.26-1', '?'),
                                                    ('rpm', 'almalinux', '8.4.27-1', 'N'),
                                                    ('rpm', 'almalinux', '8.4.26-1', '?')]:
            with self.subTest(backend=backend, version=version):
                out = self.shell(f'P2S_BACKEND={backend}; P2S_DISTRO={distro}; P2S_MAJOR=9; P2S_RELEASE=24.04\n'
                                 'p2s_version_package_state php8.4-cli ' + shlex.quote(version) + ' Unknown')
                self.assertEqual(out.strip(), expected)

    def test_owner_failure_does_not_turn_error_text_into_owner(self):
        for backend in ('deb', 'rpm'):
            with self.subTest(backend=backend):
                out = self.shell('P2S_BACKEND=' + backend + '''
p2s_command_exists() { [ "$1" = dpkg-query ]; }
p2s_command_run() { printf 'package /missing is not owned\\n'; return 1; }
owner=$(p2s_package_owner_for_path /missing)
printf 'RC=%s|OWNER=%s\\n' "$?" "$owner"
''')
                self.assertIn('RC=1|OWNER=', out)
                self.assertNotIn('not owned', out)

    def test_alternatives_symlink_resolves_to_packaged_target(self):
        out = self.shell('''
: > "$P2S_WORK/php8.4"
ln -s "$P2S_WORK/php8.4" "$P2S_WORK/php"
P2S_BACKEND=deb
p2s_command_exists() { case "$1" in readlink|dpkg-query) return 0;; *) return 1;; esac; }
p2s_command_run() { [ "$4" = "$P2S_WORK/php8.4" ] || return 1; printf 'php8.4-cli: %s\\n' "$4"; }
p2s_package_owner_for_path "$P2S_WORK/php"
''')
        self.assertEqual(out.strip(), 'php8.4-cli')

    def test_failed_refresh_does_not_restart_services(self):
        out = self.shell('''
P2S_BACKEND=deb
id() { printf '0\\n'; }
p2s_command_exists() { case "$1" in timeout|apt-get) return 0;; *) return 1;; esac; }
printf 'php8.4-cli|8.4.26-1|amd64|Debian\\n' > "$P2S_WORK/packages"
: > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
p2s_service_preflight() { return 0; }
p2s_command_run() { case \" $* \" in *' --audit '*|*' --get-selections '*) return 0;; esac; printf 'refresh failed\\n'; return 1; }
p2s_service_restart_and_verify() { printf 'UNEXPECTED_RESTART\\n'; return 91; }
p2s_fix_run
printf 'RC=%s|ATTEMPTED=%s\\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
''')
        self.assertIn('RC=1|ATTEMPTED=false', out)
        self.assertIn('repositories|Package refresh failed', out)
        self.assertNotIn('UNEXPECTED_RESTART', out)

    def test_runtime_package_mismatch_requires_review(self):
        for runtime, expected in [('8.4.26', True), ('8.4.27', False)]:
            with self.subTest(runtime=runtime):
                out = self.shell('''
mkdir -p "$P2S_WORK/usr/bin"
: > "$P2S_WORK/usr/bin/php"; chmod 700 "$P2S_WORK/usr/bin/php"
: > "$P2S_WORK/paths.raw"
printf 'php8.4-cli|8.4.27-1|amd64|Debian\\n' > "$P2S_WORK/packages"
printf 'php8.4-cli|N\\n' > "$P2S_WORK/package-states"
p2s_package_owner_for_path() { printf 'php8.4-cli\\n'; }
p2s_command_run() { printf 'PHP ''' + runtime + ''' (cli) (built: Oct 21 2026)\\n'; }
p2s_runtime_inventory_collect
printf 'UNKNOWN=%s|BLOCKED=%s\\n' "$P2S_UNKNOWN" "$P2S_BLOCKED"
''', isolated_paths=True)
                self.assertIn('UNKNOWN=' + str(expected).lower() + '|BLOCKED=' + str(expected).lower(), out)
                self.assertEqual('runtime_mismatch' in out, expected)

    def test_apache_without_php_is_not_selected_for_restart(self):
        out = self.shell('''
mkdir -p "$P2S_WORK/proc/1" "$P2S_WORK/proc/4242"
printf '1 (init) S\\n' > "$P2S_WORK/proc/1/stat"
printf '4242 (apache2) S 1\\n' > "$P2S_WORK/proc/4242/stat"
: > "$P2S_WORK/proc/4242/maps"
printf '0::/system.slice/apache2.service\\n' > "$P2S_WORK/proc/4242/cgroup"
: > "$P2S_WORK/paths.raw"
p2s_command_exists() { case "$1" in readlink|ps) return 0;; *) return 1;; esac; }
readlink() { case \"$1\" in */1/exe) printf '/sbin/init\\n';; *) printf '/usr/sbin/apache2\\n';; esac; }
p2s_process_check_host_scope() { return 0; }
ps() { [ "$TZ" = UTC ] || { printf 'WRONG_TIMEZONE'; return 1; }; printf 'Oct 22 2026\\n'; }
p2s_process_inventory_collect
printf 'SERVICES=%s|PROCESSES=%s\\n' "$(cat "$P2S_WORK/services")" "$(cat "$P2S_WORK/processes")"
''', isolated_paths=True)
        self.assertIn('SERVICES=|PROCESSES=', out)
        self.assertIn('Apache main process started: Oct 22 2026 UTC (PID 4242; executable /usr/sbin/apache2).', out)
        self.assertNotIn('No deleted PHP executables or modules', out)

    def test_rpm_plan_rejects_dependencies_removals_and_unknown_formats(self):
        selected = 'php-cli|8.4.26-1|x86_64|AlmaLinux'
        plans = [
            ('Upgrading:\n php-cli x86_64 8.4.27-1 appstream 4 M\nTransaction Summary', True),
            ('Updating:\n php-cli.x86_64 8.4.27-1 appstream 4 M\nTransaction Summary', True),
            ('Upgrading:\n other-lib x86_64 2 appstream 4 M\nTransaction Summary', False),
            ('Installing dependencies:\n other-lib x86_64 2 appstream 4 M\nTransaction Summary', False),
            ('Removing:\n php-cli x86_64 1\nTransaction Summary', False),
            ('Downgrading:\n php-cli x86_64 1\nTransaction Summary', False),
            ('Upgrading dependencies:\n other-lib x86_64 2\nTransaction Summary', False),
            ('Upgrading:\n php-cli x86_64 2', False),
            ('Nothing to do.', False), ('unexpected output', False),
        ]
        for plan, valid in plans:
            with self.subTest(plan=plan):
                body = 'printf "%s\\n" ' + shlex.quote(selected) + ' > "$P2S_WORK/packages"\n'
                body += 'printf "%s\\n" ' + shlex.quote(plan) + ' > "$P2S_WORK/plan"\n'
                body += 'p2s_package_rpm_validate_plan "$P2S_WORK/plan"'
                self.shell(body, status=0 if valid else 1)

    def test_restart_only_for_pending_deleted_workers(self):
        out = self.shell('''
P2S_BACKEND=deb; P2S_RESTART_PENDING=true
id() { printf '0\\n'; }
p2s_command_exists() { case "$1" in timeout|apt-get|apt-cache|dpkg) return 0;; *) return 1;; esac; }
p2s_package_deb_candidate() { P2S_DEB_CANDIDATE=8.4.27-1; }
printf 'php8.4-cli|8.4.27-1|amd64|Debian\\n' > "$P2S_WORK/packages"
: > "$P2S_WORK/services"; : > "$P2S_WORK/processes"
p2s_service_preflight() { return 0; }
p2s_command_run() { case " $* " in *' --audit '*|*' --get-selections '*|*' update '*|*' apt-cache '*) return 0;; *' -s '*) printf '0 upgraded\\n'; return 0;; *) return 91;; esac; }
p2s_service_restart_and_verify() { printf 'RESTART_ONLY\\n'; return 0; }
p2s_fix_run
printf 'RC=%s|ATTEMPTED=%s\\n' "$?" "$P2S_TRANSACTION_ATTEMPTED"
''')
        self.assertIn('RESTART_ONLY', out)
        self.assertIn('RC=0|ATTEMPTED=false', out)

    def test_fixed_host_with_container_gap_does_not_retry_package_updates(self):
        out = self.shell(r"""
P2S_SEPARATE_ENVIRONMENT_REVIEW=true
printf '8.4.27|N|command line||Debian|8.4.27-1|N|package\n' > "$P2S_WORK/summary-versions"
p2s_fix_preflight() { printf 'UNEXPECTED_PREFLIGHT\n'; return 97; }
p2s_package_deb_update() { printf 'UNEXPECTED_UPDATE\n'; return 97; }
p2s_fix_run
printf 'RC=%s|INSTALL=%s|RESTART=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED" "$P2S_RESTART_ATTEMPTED"
""")
        self.assertIn('host_update:beforefix|not_needed', out)
        self.assertIn('RC=0|INSTALL=false|RESTART=false', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_dpkg_audit_and_holds_block_before_refresh(self):
        for scenario in ('audit_error', 'audit_incomplete', 'apt_mark_hold', 'dpkg_hold',
                         'apt_mark_error', 'dpkg_selections_error'):
            with self.subTest(scenario=scenario):
                out = self.shell('''
printf 'php8.4-cli|8.4.26-1|amd64|Debian\\n' > "$P2S_WORK/packages"
scenario=''' + scenario + '''
p2s_command_exists() { [ "$1" = apt-get ] || { [ "$1" = apt-mark ] && { [ "$scenario" = apt_mark_hold ] || [ "$scenario" = apt_mark_error ]; }; }; }
p2s_command_run() {
    case " $* " in
        *' --audit '*)
            case "$scenario" in
                audit_error) printf 'dpkg: fixture audit failed for https://account:secret@repo.invalid/private\\n' >&2; return 1 ;;
                audit_incomplete) printf 'php8.4-cli unpacked\\n' ;;
            esac ;;
        *' showhold '*) [ "$scenario" != apt_mark_error ] || return 124; printf 'php8.4-cli\\n' ;;
        *' --get-selections '*) [ "$scenario" != dpkg_selections_error ] || return 1; printf 'php8.4-cli hold\\n' ;;
        *) printf 'UNEXPECTED_REFRESH\\n' >> "$P2S_WORK/calls"; return 91 ;;
    esac
}
p2s_package_deb_update
printf 'RC=%s|BLOCKED=%s\\n' "$?" "$P2S_BLOCKED"
[ ! -f "$P2S_WORK/calls" ] || cat "$P2S_WORK/calls"
''')
                self.assertIn('RC=1|BLOCKED=true', out)
                blocker = ('held_package' if 'hold' in scenario else
                           'package_state' if scenario.startswith('audit_') else 'package_holds')
                self.assertIn(blocker, out)
                self.assertNotIn('UNEXPECTED_REFRESH', out)
                if scenario.startswith('audit_'):
                    self.assertIn('package_audit:beforefix|', out)
                    self.assertIn('fixture audit failed' if scenario == 'audit_error' else 'php8.4-cli unpacked', out)
                    self.assertNotIn('account:secret', out)
                    self.assertNotIn('/private', out)

    def test_low_space_or_failed_space_check_prevents_package_update(self):
        for disk_status, available, blocker in [(1, 900000, 'disk_check'), (0, 100, 'disk_space')]:
            with self.subTest(disk_status=disk_status, available=available):
                out = self.shell('''
P2S_BACKEND=deb
id() { printf '0\\n'; }
p2s_command_exists() { case "$1" in timeout|df) return 0;; *) return 1;; esac; }
p2s_command_run() {
    [ "$2" = df ] || return 97
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/fixture 999999 100 ''' + str(available) + ''' 1%% /\\n'
    return ''' + str(disk_status) + '''
}
p2s_package_deb_update() { printf 'UNEXPECTED_UPDATE\\n'; return 91; }
p2s_fix_run
printf 'RC=%s|BLOCKED=%s\\n' "$?" "$P2S_BLOCKED"
''')
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertIn(blocker, out)
                if disk_status == 0:
                    self.assertIn('/ (/dev/fixture): 100 KiB available', out)
                    self.assertIn('disk_preflight:beforefix|', out)
                    self.assertIn('partition/filesystem grown', out)
                self.assertNotIn('UNEXPECTED_UPDATE', out)

    def test_fpm_preflight_uses_active_master_config_and_preserves_failure(self):
        for exit_status in (1, 124):
            with self.subTest(exit_status=exit_status):
                out = self.shell('exit_status=' + str(exit_status) + '\n' + r"""
mkdir -p "$P2S_WORK/proc/4242"
runtime="$P2S_WORK/php-fpm8.4"; config="$P2S_WORK/custom fpm.conf"
: > "$runtime"; chmod 700 "$runtime"; : > "$config"
printf '%s\0' "php-fpm: master process ($config)" > "$P2S_WORK/proc/4242/cmdline"
printf '4242|%s\n' "$runtime" > "$P2S_WORK/fpm-masters"
printf 'init:php-fpm\n' > "$P2S_WORK/services"
# These installed paths must not be executed by the service validation.
printf '/fixture/php-fpm8.1\n/fixture/php-fpm8.4.8.gz\n' > "$P2S_WORK/paths"
p2s_command_run() {
    [ "$#" -eq 5 ] && [ "$2" = "$runtime" ] && [ "$3" = -y ] && [ "$4" = "$config" ] && [ "$5" = -t ] || return 96
    printf 'ERROR: configuration syntax failure\ndss:isvulnerable:afterfix: forged\n' >&2
    printf 'password=hidden\nSee https://user:hidden@example.test/help\n' >&2
    return "$exit_status"
}
p2s_service_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""", isolated_paths=True)
                self.assertIn('RC=1|BLOCKED=true', out)
                self.assertIn('PHP-FPM (PID 4242) configuration validation failed', out)
                self.assertIn('configtest_exit:beforefix|PHP-FPM (PID 4242)|' + str(exit_status), out)
                self.assertIn('configtest_output:beforefix|ERROR: configuration syntax failure', out)
                self.assertIn('configtest_output:beforefix|dss:isvulnerable:afterfix: forged', out)
                self.assertIn('custom fpm.conf', out)
                self.assertIn('[sensitive diagnostic redacted]', out)
                self.assertIn('[URL redacted]', out)
                self.assertNotIn('hidden', out)
                self.assertNotIn('\ndss:isvulnerable:', out)

    def test_failed_validation_never_enters_package_or_restart_paths(self):
        out = self.shell(r"""
mkdir -p "$P2S_WORK/proc/4242"
runtime="$P2S_WORK/php-fpm"; : > "$runtime"; chmod 700 "$runtime"
printf '%s\0' "$runtime" > "$P2S_WORK/proc/4242/cmdline"
printf '4242|%s\n' "$runtime" > "$P2S_WORK/fpm-masters"
printf 'init:php-fpm\n' > "$P2S_WORK/services"
printf 'php8.4-fpm|8.4.26|amd64|vendor\n' > "$P2S_WORK/packages"
id() { printf '0\n'; }
p2s_command_exists() { [ "$1" != df ]; }
p2s_command_has_timeout() { return 0; }
p2s_command_run() { printf 'Broken config\n'; return 1; }
p2s_package_deb_update() { printf 'UNEXPECTED_UPDATE\n'; return 96; }
p2s_service_restart_and_verify() { printf 'UNEXPECTED_RESTART\n'; return 96; }
P2S_BACKEND=deb
p2s_fix_run
printf 'RC=%s|INSTALL=%s|RESTART=%s\n' "$?" "$P2S_TRANSACTION_ATTEMPTED" "$P2S_RESTART_ATTEMPTED"
""", isolated_paths=True)
        self.assertIn('RC=1|INSTALL=false|RESTART=false', out)
        self.assertNotIn('UNEXPECTED_', out)

    def test_fpm_preflight_ignores_unused_installed_versions(self):
        out = self.shell(r"""
printf 'init:php-fpm\n' > "$P2S_WORK/services"
printf '/fixture/php-fpm8.1\n/fixture/php-fpm8.4.8.gz\n' > "$P2S_WORK/paths"
: > "$P2S_WORK/fpm-masters"
p2s_service_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""")
        self.assertIn('RC=0|BLOCKED=false', out)

    def test_fpm_preflight_preserves_nul_separated_config_arguments(self):
        out = self.shell(r"""
mkdir -p "$P2S_WORK/proc/4242"
runtime="$P2S_WORK/php-fpm"; config="$P2S_WORK/custom fpm.conf"
: > "$runtime"; chmod 700 "$runtime"; : > "$config"
printf '%s\0' "$runtime" -F -y "$config" -n -d 'display_errors=0' > "$P2S_WORK/proc/4242/cmdline"
p2s_command_run() {
    shift
    [ "$#" -eq 7 ] && [ "$1" = "$runtime" ] && [ "$2" = -y ] && [ "$3" = "$P2S_WORK/custom fpm.conf" ] &&
        [ "$4" = -n ] && [ "$5" = -d ] && [ "$6" = display_errors=0 ] && [ "$7" = -t ] || return 96
}
p2s_service_fpm_preflight 4242 "$runtime"
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""", isolated_paths=True)
        self.assertIn('RC=0|BLOCKED=false', out)

    def test_fpm_preflight_blocks_missing_or_unrecognised_startup_data(self):
        for cmdline in ('', 'php-fpm: master process (truncated', '/fixture/php-fpm\0--unsupported\0',
                        '/fixture/php-fpm\0-y\0', '/fixture/php-fpm\0-y\0relative.conf\0',
                        '/fixture/php-fpm\0-yrelative.conf\0', 'php-fpm: master process ()\0',
                        'php-fpm: master process (/missing/config)\0'):
            with self.subTest(cmdline=cmdline):
                out = self.shell('cmdline=' + shlex.quote(cmdline.replace('\0', '\\0')) + '\n' + r"""
mkdir -p "$P2S_WORK/proc/4242"
runtime="$P2S_WORK/php-fpm"; : > "$runtime"; chmod 700 "$runtime"
printf '%b' "$cmdline" > "$P2S_WORK/proc/4242/cmdline"
p2s_service_fpm_preflight 4242 "$runtime"
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""", isolated_paths=True)
                self.assertIn('RC=1|BLOCKED=true', out)

    def test_runtime_paths_exclude_package_manuals(self):
        out = self.shell(r"""
p2s_runtime_path_add /fixture/php-fpm8.4.8.gz
p2s_runtime_path_add /fixture/php-cgi8.4.1.gz
p2s_runtime_path_add /fixture/lsphp84.1.gz
p2s_runtime_path_add /fixture/php-fpm8.4
p2s_runtime_path_add /fixture/php-cgi8.4
cat "$P2S_WORK/paths.raw"
""")
        self.assertEqual(out.splitlines(), ['/fixture/php-fpm8.4', '/fixture/php-cgi8.4'])

    def test_blocked_inventory_hides_only_unchanged_customer_messages(self):
        for attempted in ('false', 'true'):
            with self.subTest(attempted=attempted):
                out = self.shell('P2S_TRANSACTION_ATTEMPTED=' + attempted + '\n' + r"""
P2S_INVENTORY_MESSAGES=true
p2s_message_print info 'Initial check: PHP 8.4.27: fixed.'
p2s_message_print warn 'Same warning.'
p2s_manifest_record package 'php8.4|same'
P2S_PHASE=afterfix
if $P2S_TRANSACTION_ATTEMPTED; then p2s_message_print info 'After update attempt: PHP 8.4.27: fixed.'
else p2s_message_print info 'Initial check: PHP 8.4.27: fixed.'; fi
p2s_message_print warn 'Same warning.'
p2s_message_print warn 'New warning.'
p2s_manifest_record package 'php8.4|same'
""")
                self.assertEqual(out.count('PHP 8.4.27: fixed.'), 1 if attempted == 'false' else 2)
                self.assertEqual(out.count('Same warning.'), 1)
                self.assertIn('New warning.', out)
                self.assertIn('package:beforefix|php8.4|same', out)
                self.assertIn('package:afterfix|php8.4|same', out)

    def test_fix_outcome_does_not_claim_unchanged_after_attempted_mutation(self):
        for transaction, restart in [('false', 'false'), ('true', 'false'), ('false', 'true')]:
            with self.subTest(transaction=transaction, restart=restart):
                out = self.shell(r"""
p2s_distro_detect() { :; }; p2s_fix_check_distro_recipe() { :; }; p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() { P2S_STATE=Y; }
p2s_fix_run() { P2S_TRANSACTION_ATTEMPTED=""" + transaction + '; P2S_RESTART_ATTEMPTED=' + restart + r"""; return 1; }
p2s_command_run() { return 0; }
mkdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
rmdir() { [ "$1" = /var/run/rh-php2shell.lock ]; }
(p2s_main --fix)
""", status=1)
                self.assertEqual(out.count('RimuHosting offers a no-cost, no-obligation investigation'), 1)
                if transaction == restart == 'false':
                    self.assertIn('No PHP package installation or service restart was attempted.', out)
                    self.assertIn('fix_outcome:afterfix|blocked|', out)
                else:
                    self.assertIn('Packages or services may have changed.', out)
                    self.assertNotIn('No PHP package installation', out)
                    self.assertIn('fix_outcome:afterfix|incomplete|', out)

    def test_apache_validation_failure_keeps_diagnostics(self):
        out = self.shell(r"""
printf 'init:apache2\n' > "$P2S_WORK/services"
p2s_command_exists() { [ "$1" = apache2ctl ]; }
p2s_command_run() {
    [ "$2" = apache2ctl ] && [ "$3" = -t ] || return 96
    printf 'Syntax error in Apache config\n' >&2; return 1
}
p2s_service_preflight
printf 'RC=%s|BLOCKED=%s\n' "$?" "$P2S_BLOCKED"
""")
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertIn('configtest_exit:beforefix|Apache|1', out)
        self.assertIn('configtest_output:beforefix|Syntax error in Apache config', out)

    def test_service_command_fallbacks(self):
        cases = [('php8.4-fpm.service', 'restart', True, '120|systemctl|restart|php8.4-fpm.service'),
                 ('php8.4-fpm.service', 'status', True, '30|systemctl|is-active|--quiet|php8.4-fpm.service'),
                 ('init:php-fpm', 'restart', True, '120|service|php-fpm|restart'),
                 ('init:php-fpm', 'status', False, '120|/etc/init.d/php-fpm|status')]
        for unit, action, service_available, expected in cases:
            with self.subTest(unit=unit, action=action, service_available=service_available):
                out = self.shell('''
p2s_command_exists() { [ "$1" = service ] && ''' + str(service_available).lower() + '''; }
p2s_command_run() { oldifs=$IFS; IFS='|'; printf '%s\\n' "$*"; IFS=$oldifs; }
p2s_service_run ''' + shlex.quote(unit) + ' ' + shlex.quote(action))
                self.assertEqual(out.strip(), expected)

    def test_restart_failure(self):
        out = self.shell('''
printf 'php8.4-fpm.service\\n' > "$P2S_WORK/services.before"
: > "$P2S_WORK/processes.before"
p2s_command_run() { return 1; }
p2s_service_restart_and_verify
printf 'RC=%s|BLOCKED=%s\\n' "$?" "$P2S_BLOCKED"
''')
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertNotIn('dss:fixmethod:', out)

    def test_no_php_fix_is_blocked(self):
        out = self.shell('''
id() { printf '0\\n'; }; : > "$P2S_WORK/packages"
p2s_command_run() { [ "$2" = df ] || return 97; printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/fixture 999999 100 900000 1%% /\\n'; }
p2s_fix_run
printf 'RC=%s|BLOCKED=%s\\n' "$?" "$P2S_BLOCKED"
''')
        self.assertIn('RC=1|BLOCKED=true', out)
        self.assertIn('no_packages', out)

    def test_main_check_emits_contract_markers_without_fix(self):
        for state in ('Y', 'N', '?'):
            with self.subTest(state=state):
                out = self.shell('''
p2s_distro_detect() { :; }; p2s_fix_check_distro_recipe() { :; }; p2s_repository_inventory_collect() { :; }
p2s_inventory_collect_and_assess() { P2S_STATE=''' + shlex.quote(state) + '''; }
p2s_fix_run() { exit 91; }
# Disk output is informational; fixture avoids invoking any unmocked p2s_command_run.
p2s_command_run() { return 0; }
(p2s_main --check)
''')
                markers = re.findall(r'^dss:isvulnerable:(beforefix|afterfix): CVE_2026_109618([YN?])$', out, re.M)
                self.assertEqual(markers, [('beforefix', state), ('afterfix', state)])
                self.assertRegex(out, r'(?m)^dss:manifest:function_checksum:beforefix\|[0-9]+ +[0-9]+$')


if __name__ == '__main__':
    unittest.main(verbosity=2)
