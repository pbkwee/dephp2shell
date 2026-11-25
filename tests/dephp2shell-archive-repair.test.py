"""Offline fixtures for automatic same-release repair of retired APT mirrors."""

from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).with_name('dephp2shell.test.py')))


class AptArchiveRepairTest(unittest.TestCase):
    shell = HELPERS['PHP2ShellTest'].shell

    def refresh(self, setup):
        return self.shell(r'''
P2S_BACKEND=deb; P2S_DISTRO=debian; P2S_RELEASE=10; P2S_PANEL=none
P2S_MODE=fix; P2S_NOVEMBER=true
retry_ok=true
mkdir -p "$P2S_WORK/etc/apt/sources.list.d" "$P2S_WORK/usr/lib/apt/methods"
touch "$P2S_WORK/usr/lib/apt/methods/https"
chmod +x "$P2S_WORK/usr/lib/apt/methods/https"
sources="$P2S_WORK/etc/apt/sources.list"
sourceparts="$P2S_WORK/etc/apt/sources.list.d"
p2s_package_deb_sury_trust_preflight() { return 0; }
p2s_command_run() {
    [ "$2" = apt-get ] || { printf 'UNEXPECTED administrative command: %s\n' "$*"; return 97; }
    printf '%s\n' "$*" >> "$P2S_WORK/calls"
    case "$*" in *Check-Valid-Until=false*|*AllowInsecureRepositories=true*|*AllowUnauthenticated=true*) return 97 ;; esac
    if [ -e "$P2S_WORK/first-refresh-attempt" ]; then
        if $retry_ok; then echo 'Reading package lists...'; return 0; fi
        echo 'W: GPG error: https://archive.debian.org/debian buster Release: NO_PUBKEY 12345'
        return 0
    fi
    touch "$P2S_WORK/first-refresh-attempt"
    cat "$P2S_WORK/first-refresh.log"
    return 100
}
''' + setup + r'''
p2s_package_deb_refresh_indexes
printf 'STATUS=%s|REFRESH=%s|BLOCKED=%s\n' "$?" "$P2S_REPOSITORY_REFRESH" "$P2S_BLOCKED"
printf 'CALLS=%s\n' "$(wc -l < "$P2S_WORK/calls")"
printf 'PERMISSIONS=%s\n' "$(stat -c '%a' "$sources")"
printf '%s\n' 'FINAL SOURCES'
cat "$sources"
for file in "$sourceparts"/*.sources; do [ ! -f "$file" ] || cat "$file"; done
if find "$P2S_WORK/etc/apt" -name '.dephp2shell-archive-*' | grep -q .; then
    printf 'TEMPORARY FILES REMAIN\n'
fi
''', isolated_paths=True, isolated_sources=True)

    def test_repairs_exact_mirror_and_keeps_options_and_other_entries(self):
        out = self.refresh(r'''
cat > "$sources" <<'SOURCES'
# Keep this https://deb.debian.org/debian buster comment.
  deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/   buster main contrib # keep
deb-src http://deb.debian.org/debian buster main
deb http://deb.debian.org/debian bullseye main
deb https://vendor.example/php buster main
SOURCES
chmod 640 "$sources"
cat > "$P2S_WORK/first-refresh.log" <<'LOG'
Err:5 http://deb.debian.org/debian buster Release
  404  Not Found [IP: 192.0.2.1 80]
E: The repository 'http://deb.debian.org/debian buster Release' does not have a Release file.
LOG
''')
        self.assertIn('retained|files=1|authenticated_refresh=complete', out)
        self.assertIn('STATUS=0|REFRESH=refreshed|BLOCKED=false', out)
        self.assertIn('CALLS=2', out)
        self.assertIn('PERMISSIONS=640', out)
        final = out.split('FINAL SOURCES\n', 1)[1]
        self.assertIn('  deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://archive.debian.org/debian/   buster main contrib # keep', final)
        self.assertIn('deb-src https://archive.debian.org/debian buster main', final)
        self.assertIn('# Keep this https://deb.debian.org/debian buster comment.', final)
        self.assertIn('deb http://deb.debian.org/debian bullseye main', final)
        self.assertIn('deb https://vendor.example/php buster main', final)
        self.assertNotIn('TEMPORARY FILES REMAIN', out)

    def test_repairs_deb822_multiple_suites_and_security_pocket(self):
        out = self.refresh(r'''
cat > "$sources" <<'SOURCES'
deb https://security.debian.org/debian-security buster/updates main
SOURCES
cat > "$sourceparts/native.sources" <<'SOURCES'
Types: deb deb-src
URIs: https://ftp.nz.debian.org/debian
Suites: buster
 buster-updates
Components: main contrib
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://ftp.nz.debian.org/debian
Suites: buster
Components: main
Enabled: no
SOURCES
cat > "$P2S_WORK/first-refresh.log" <<'LOG'
E: The repository 'https://ftp.nz.debian.org/debian buster Release' no longer has a Release file.
E: The repository 'https://ftp.nz.debian.org/debian buster-updates Release' does not have a Release file.
E: Failed to fetch https://security.debian.org/debian-security/dists/buster/updates/Release 404 Not Found
LOG
''')
        self.assertIn('retained|files=2|authenticated_refresh=complete', out)
        final = out.split('FINAL SOURCES\n', 1)[1]
        self.assertIn('deb https://archive.debian.org/debian-security buster/updates main', final)
        self.assertIn('URIs: https://archive.debian.org/debian\nSuites: buster\n buster-updates', final)
        self.assertIn('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg', final)
        self.assertIn('URIs: https://ftp.nz.debian.org/debian\nSuites: buster\nComponents: main\nEnabled: no', final)

    def test_failed_authenticated_retry_restores_every_file(self):
        out = self.refresh(r'''
retry_ok=false
printf 'deb https://deb.debian.org/debian buster main\n' > "$sources"
printf 'Types: deb\nURIs: https://security.debian.org/debian-security\nSuites: buster/updates\nComponents: main\n' > "$sourceparts/security.sources"
cat > "$P2S_WORK/first-refresh.log" <<'LOG'
E: The repository 'https://deb.debian.org/debian buster Release' does not have a Release file.
E: The repository 'https://security.debian.org/debian-security buster/updates Release' does not have a Release file.
LOG
''')
        self.assertEqual(out.count('|restored|file='), 2)
        self.assertIn('NO_PUBKEY', out)
        self.assertIn('STATUS=1|REFRESH=failed|BLOCKED=true', out)
        final = out.split('FINAL SOURCES\n', 1)[1]
        self.assertIn('deb https://deb.debian.org/debian buster main', final)
        self.assertIn('URIs: https://security.debian.org/debian-security', final)
        self.assertNotIn('TEMPORARY FILES REMAIN', out)

    def test_ubuntu_archived_release_only_and_http_when_transport_is_missing(self):
        for release, suite, eligible in [('18.10', 'cosmic', True), ('16.04', 'xenial', False)]:
            with self.subTest(release=release):
                out = self.refresh(f"P2S_DISTRO=ubuntu; P2S_RELEASE={release}; suite={suite}\n" + r'''
rm -f "$P2S_WORK/usr/lib/apt/methods/https"
printf 'deb http://nz.archive.ubuntu.com/ubuntu %s main restricted\n' "$suite" > "$sources"
printf "E: The repository 'http://nz.archive.ubuntu.com/ubuntu %s Release' does not have a Release file.\n" "$suite" > "$P2S_WORK/first-refresh.log"
''')
                host = 'old-releases.ubuntu.com' if eligible else 'nz.archive.ubuntu.com'
                self.assertIn(f'deb http://{host}/ubuntu {suite} main restricted', out)
                self.assertIn(f'CALLS={2 if eligible else 1}', out)

    def test_no_edits_in_check_october_panels_or_on_unmatched_failures(self):
        for prefix, failure in [
            ('P2S_MODE=check', 'missing_release'),
            ('P2S_NOVEMBER=false', 'missing_release'),
            ('P2S_PANEL=plesk', 'missing_release'),
            ('', 'signature_only'),
            ('', 'package_404_only'),
            ('', 'third_party_missing_release'),
        ]:
            with self.subTest(prefix=prefix, failure=failure):
                out = self.refresh(prefix + f'\nfailure={failure}\n' + r'''
printf 'deb http://deb.debian.org/debian buster main\n' > "$sources"
case "$failure" in
    missing_release) error="E: The repository 'http://deb.debian.org/debian buster Release' does not have a Release file." ;;
    signature_only) error='W: GPG error: http://deb.debian.org/debian buster Release: NO_PUBKEY 12345' ;;
    package_404_only) error='E: Failed to fetch http://deb.debian.org/debian/dists/buster/main/binary-amd64/Packages 404 Not Found' ;;
    third_party_missing_release) error="E: The repository 'https://vendor.example/debian buster Release' does not have a Release file." ;;
esac
printf '%s\n' "$error" > "$P2S_WORK/first-refresh.log"
''')
                self.assertIn('CALLS=1', out)
                self.assertIn('STATUS=1|REFRESH=failed|BLOCKED=true', out)
                self.assertIn('FINAL SOURCES\ndeb http://deb.debian.org/debian buster main', out)
                self.assertNotIn('|retained|', out)


if __name__ == '__main__':
    unittest.main()
