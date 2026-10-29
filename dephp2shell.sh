#!/bin/bash
# Copyright (c) 2026 RimuHosting
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# DePHP2Shell: both PHP2Shell CVEs share the aggregate result key CVE_2026_109618.
# Standalone Bash 2-era syntax; check mode never updates packages or restarts services.
# Integrations must run extra inventory scripts separately and preserve this script's exit status.
# Usage and maintenance: docs/usage.md and docs/maintainer-reference.md.
# When changing supported checks or update actions, also review descriptions used by integrations.
# P2S-MUTATION marks package/cache writes, service changes and their callers.
# Routine work files, logs, locks and supervision of our own subprocesses are not marked.
# Preserve PHP package sources: switching publishers or repositories requires explicit operator choice.
# See the source-preservation policy and evidence limits in the maintainer reference.

# Output and manifest records

p2s_manifest_record() {
    local key="$1" value="$2" line
    # Prefix every line, including output supplied by packages, to prevent marker injection.
    printf '%s\n' "$value" | LC_ALL=C tr -d '\000-\010\013-\037\177' |
        while IFS= read -r line; do printf 'dss:manifest:%s:%s|%s\n' "$key" "$P2S_PHASE" "$line"; done
}

# Inspect file metadata only; never execute panel tools or read their configuration here.
p2s_manifest_path_record() {
    local key=$1 path=$2 owner=${3:-not_queried} kind=missing_or_inaccessible readable=false executable=false target=none resolved=unavailable output
    if [ -L "$path" ]; then
        kind=symlink
        [ -e "$path" ] || kind=dangling_or_inaccessible_symlink
        target=unavailable
        if p2s_command_exists readlink; then
            output=$(readlink "$path" 2>/dev/null)
            [ -z "$output" ] || target=$output
        fi
    elif [ -f "$path" ]; then kind=regular_file
    elif [ -d "$path" ]; then kind=directory
    elif [ -e "$path" ]; then kind=other
    fi
    [ ! -r "$path" ] || readable=true
    [ ! -x "$path" ] || executable=true
    if p2s_command_exists readlink; then
        output=$(readlink -f "$path" 2>/dev/null)
        [ -z "$output" ] || resolved=$output
    fi
    p2s_manifest_record "$key" "$path|type=$kind|readable=$readable|executable=$executable|link_target=$target|resolved=$resolved|package_owner=$owner"
}

# Keep hosts, not URL paths: subscription credentials can occur in paths as well as userinfo.
# This filter is also used before saving cached package-manager output in the manifest.
# AWK whitespace is explicit because old mawk lacks POSIX named character classes.
p2s_manifest_redact_repository_urls() {
    awk '
        function safeurl(url, authority) {
            sub(/^[^:]+:\/\//, "", url)
            sub(/[\/?#].*$/, "", url); sub(/^.*@/, "", url)
            authority=url
            if (authority !~ /^[a-zA-Z0-9.:[\]_-]+$/) return "[repository URL redacted]"
            return "[repository host=" authority "; path redacted]"
        }
        {
            line=$0; result=""
            while (match(line, /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^ \t\r\n\014\013]+/)) {
                result=result substr(line,1,RSTART-1) safeurl(substr(line,RSTART,RLENGTH))
                line=substr(line,RSTART+RLENGTH)
            }
            print result line
        }'
}

p2s_message_print() {
    local level="$1" record="$2"
    record="$level: $record"
    # Keep every raw inventory; repeat customer text only when the observation or phase changes.
    if [ "${P2S_INVENTORY_MESSAGES:-false}" = true ]; then
        if grep -Fx -e "$record" "$P2S_WORK/messages.inventory" >/dev/null 2>&1; then
            return 0
        fi
        printf '%s\n' "$record" >> "$P2S_WORK/messages.inventory"
    fi
    printf '%s\n' "$2" | LC_ALL=C tr -d '\000-\010\013-\037\177' |
        while IFS= read -r line; do printf 'dss:%s: %s\n' "$level" "$line"; done
}

# Command deadlines and private work directories

p2s_command_exists() { command -v "$1" >/dev/null 2>&1; }

p2s_command_has_timeout() {
    p2s_command_exists timeout && timeout --help 2>&1 | grep -e '--kill-after' -e '\-k ' >/dev/null
}

p2s_command_has_shell_watchdog() {
    p2s_command_exists sleep && (set -m 2>/dev/null)
}

p2s_command_run_watchdog() (
    # Bash job control isolates the command's process group from the calling SSH shell.
    local seconds="$1" worker timer result directory
    shift
    directory=$(p2s_work_directory_create) || return 125
    if ! set -m; then rm -rf "$directory"; return 125; fi
    "$@" &
    worker=$!
    (
        sleep "$seconds"
        # Record expiry before signalling: TERM handlers can return a misleading zero.
        if ! : > "$directory/expired"; then kill -KILL -- "-$worker" 2>/dev/null; exit 1; fi
        kill -TERM -- "-$worker" 2>/dev/null
        sleep 10
        : > "$directory/kill_phase"
        kill -KILL -- "-$worker" 2>/dev/null
    ) &
    timer=$!
    trap 'kill -TERM -- "-$worker" "-$timer" 2>/dev/null; sleep 1; kill -KILL -- "-$worker" "-$timer" 2>/dev/null; wait "$worker" "$timer" 2>/dev/null; rm -rf "$directory"; exit 143' TERM
    trap 'kill -TERM -- "-$worker" "-$timer" 2>/dev/null; sleep 1; kill -KILL -- "-$worker" "-$timer" 2>/dev/null; wait "$worker" "$timer" 2>/dev/null; rm -rf "$directory"; exit 130' INT
    wait "$worker" 2>/dev/null
    result=$?
    kill -TERM -- "-$timer" 2>/dev/null
    wait "$timer" 2>/dev/null
    if [ -f "$directory/expired" ]; then
        if kill -0 -- "-$worker" 2>/dev/null; then
            kill -TERM -- "-$worker" 2>/dev/null
            [ -f "$directory/kill_phase" ] || sleep 10
            kill -KILL -- "-$worker" 2>/dev/null
        fi
        result=124
    fi
    rm -rf "$directory"
    return "$result"
)

p2s_command_run() {
    local seconds="$1"
    shift
    if p2s_command_has_timeout; then
        timeout -k 10 "$seconds" "$@"
    elif p2s_command_has_shell_watchdog; then
        p2s_command_run_watchdog "$seconds" "$@"
    elif p2s_command_exists perl; then
        # Inspection-only last resort; mutation requires process-group supervision.
        perl -e 'alarm shift; exec @ARGV; die "Cannot execute command: $!\n";' "$seconds" "$@"
    else
        return 125
    fi
}

p2s_work_directory_create() {
    local attempt=0 candidate prefix="${1:-/tmp/rh-dephp2shell.}"
    umask 077
    if p2s_command_exists mktemp; then
        mktemp -d "${prefix}XXXXXXXX" 2>/dev/null && return 0
    fi
    # Atomic mkdir under umask 077 rejects existing directories and symlinks.
    while [ "$attempt" -lt 20 ]; do
        candidate="${prefix}$$.$RANDOM.$attempt"
        if mkdir "$candidate" 2>/dev/null; then printf '%s\n' "$candidate"; return 0; fi
        attempt=$((attempt + 1))
    done
    p2s_message_print error "Could not create a private work directory." >&2
    return 1
}

p2s_work_directory_init() {
    P2S_WORK=$(p2s_work_directory_create)
}

# Distribution identification

p2s_distro_release_value() {
    # /etc/os-release: ID="debian". Read data, never source release files as shell code.
    [ -r "$1" ] || return 1
    LC_ALL=C awk -F= -v key="$2" '$1 == key { sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); gsub(/^\047|\047$/, ""); print; exit }' "$1"
}

p2s_distro_detect() {
    local release_file=/etc/redhat-release release
    P2S_DISTRO=$(p2s_distro_release_value /etc/os-release ID)
    P2S_RELEASE=$(p2s_distro_release_value /etc/os-release VERSION_ID)
    if [ -z "$P2S_DISTRO" ] && [ -r /etc/lsb-release ]; then
        P2S_DISTRO=$(p2s_distro_release_value /etc/lsb-release DISTRIB_ID | tr '[:upper:]' '[:lower:]')
        P2S_RELEASE=$(p2s_distro_release_value /etc/lsb-release DISTRIB_RELEASE)
    fi
    if [ -z "$P2S_DISTRO" ] && [ -r /etc/debian_version ]; then
        P2S_DISTRO=debian
        IFS= read -r P2S_RELEASE < /etc/debian_version
    fi
    # Old Fedora: /etc/fedora-release (or redhat-release) contains "Fedora Core release 6 (Zod)".
    if [ -r /etc/fedora-release ]; then
        release_file=/etc/fedora-release
    fi
    if [ -z "$P2S_DISTRO" ] && [ -r "$release_file" ]; then
        IFS= read -r release < "$release_file"
        case "$release" in
            *Fedora*) P2S_DISTRO=fedora ;;
            *AlmaLinux*) P2S_DISTRO=almalinux ;;
            *Rocky*) P2S_DISTRO=rocky ;;
            *CentOS*) P2S_DISTRO=centos ;;
            *White*Box*|*Whitebox*) P2S_DISTRO=whitebox ;;
            *Red\ Hat*) P2S_DISTRO=rhel ;;
            *) P2S_DISTRO=unknown ;;
        esac
        P2S_RELEASE=$(printf '%s\n' "$release" | sed 's/[^0-9]*\([0-9][0-9.]*\).*/\1/')
    fi
    P2S_MAJOR=${P2S_RELEASE%%.*}
    case "$P2S_MAJOR" in ''|*[!0-9]*) P2S_MAJOR=0 ;; esac
    P2S_DISTRO=${P2S_DISTRO:-unknown}
    P2S_RELEASE=${P2S_RELEASE:-unknown}
    p2s_manifest_record distro "$P2S_DISTRO|$P2S_RELEASE|$(uname -m 2>/dev/null)"
    if [ "$P2S_DISTRO" = arch ]; then p2s_message_print info "Operating system: Arch Linux (rolling release)."
    else p2s_message_print info "Operating system: $P2S_DISTRO $P2S_RELEASE."
    fi
    printf 'RET:DISTROINFO: %s %s\n' "$P2S_DISTRO" "$P2S_RELEASE"
    printf 'dss:distroinfo: %s %s\n' "$P2S_DISTRO" "$P2S_RELEASE"
}

# PHP version rules and aggregate state

p2s_version_upstream_state() {
    # Return data, not status: Y=affected upstream, N=fixed upstream, ?=unrecognised.
    # Build dates are evidence only, never a patch test. RC/dev builds are not releases.
    local version="$1" major minor patch rest floor
    case "$version" in *:*)
        case "${version%%:*}" in ''|*[!0-9]*) printf '?\n'; return ;; esac
        version=${version#*:} ;;
    esac
    case "$version" in *.*.*) ;; *) printf '?\n'; return ;; esac
    case "$version" in *[Rr][Cc]*|*dev*|*alpha*|*beta*) printf '?\n'; return ;; esac
    major=${version%%.*}; rest=${version#*.}
    minor=${rest%%.*}; rest=${rest#*.}; patch=${rest%%[!0-9]*}
    case "$major:$minor:$patch" in *[!0-9:]*|::*|*::|:*|*:) printf '?\n'; return ;; esac
    if [ "$major" -eq 8 ]; then
        case "$minor" in 0|1) printf 'Y\n'; return ;; 2) floor=35 ;; 3) floor=36 ;; 4) floor=27 ;; 5) floor=12 ;; *) printf '?\n'; return ;; esac
        if [ "$patch" -ge "$floor" ]; then printf 'N\n'; else printf 'Y\n'; fi
    elif [ "$major" -eq 7 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 4 ]; }; then
        printf 'Y\n'
    else
        printf '?\n'
    fi
}

p2s_version_deb_fixed_floor() {
    # A backport applies security fixes without adopting the newer upstream version number.
    # Compare the full vendor package revision, not just the number printed by php -v.
    # USN-8948-1/-2 and both Debian trackers, checked 2026-10-22. Match OS AND family.
    case "$P2S_DISTRO:$P2S_RELEASE:$1" in
        debian:12*:php8.2-*|debian:12*:libapache2-mod-php8.2) printf '%s\n' '8.2.35-1~deb12u1' ;;
        debian:13*:php8.4-*|debian:13*:libapache2-mod-php8.4) printf '%s\n' '8.4.27-1~deb13u1' ;;
        ubuntu:26.10:php8.5-*|ubuntu:26.10:libapache2-mod-php8.5) printf '%s\n' '8.5.9-0ubuntu2.1' ;;
        ubuntu:26.04:php8.5-*|ubuntu:26.04:libapache2-mod-php8.5) printf '%s\n' '8.5.4-0ubuntu1.5' ;;
        ubuntu:24.04:php8.3-*|ubuntu:24.04:libapache2-mod-php8.3) printf '%s\n' '8.3.6-0ubuntu0.24.04.13' ;;
        ubuntu:22.04:php8.1-*|ubuntu:22.04:libapache2-mod-php8.1) printf '%s\n' '8.1.2-1ubuntu2.28' ;;
        ubuntu:20.04:php7.4-*|ubuntu:20.04:libapache2-mod-php7.4) printf '%s\n' '7.4.3-4ubuntu2.29+esm5' ;;
        ubuntu:18.04:php7.2-*|ubuntu:18.04:libapache2-mod-php7.2) printf '%s\n' '7.2.24-0ubuntu0.18.04.17+esm14' ;;
        ubuntu:16.04:php7.0-*|ubuntu:16.04:libapache2-mod-php7.0) printf '%s\n' '7.0.33-0ubuntu0.16.04.16+esm22' ;;
        ubuntu:14.04:php5-*|ubuntu:14.04:libapache2-mod-php5) printf '%s\n' '5.5.9+dfsg-1ubuntu4.29+esm18' ;;
    esac
}

p2s_version_sury_fixed_build_output() {
    local name="$1" arch="$2" revision suffix release
    [ "$arch" = amd64 ] || return 1
    # Exact signed source/binary builds reviewed in docs/sury-backport-evidence.md.
    # Do not turn these into >= floors: later EOL backports require another review.
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*) suffix='debian11~1' ;;
        debian:12|debian:12.*) suffix='debian12~1' ;;
        debian:13|debian:13.*) suffix='debian13~1' ;;
        ubuntu:22.04|ubuntu:24.04) suffix="ubuntu$P2S_RELEASE.1+deb.sury.org+1" ;;
        *) return 1 ;;
    esac
    case "$name" in
        php5.6-*|libapache2-mod-php5.6) revision='5.6.40-105+0~20261022.135'; release=37a17e ;;
        php7.0-*|libapache2-mod-php7.0) revision='7.0.33-93+0~20261022.119'; release=952195 ;;
        php7.1-*|libapache2-mod-php7.1) revision='7.1.33-81+0~20261022.128'; release=a88ccf ;;
        php7.2-*|libapache2-mod-php7.2) revision='7.2.34-66+0~20261021.122'; release=e0bcd4 ;;
        php7.3-*|libapache2-mod-php7.3) revision='7.3.33-35+0~20261021.144'; release=ecf76f ;;
        php7.4-*|libapache2-mod-php7.4) revision='1:7.4.33-31+0~20261021.121'; release=e9c428 ;;
        php8.0-*|libapache2-mod-php8.0) revision='1:8.0.30-25+0~20261021.88'; release=abebea ;;
        php8.1-*|libapache2-mod-php8.1) revision='8.1.34-9+0~20261021.82'; release=4e430a ;;
        *) return 1 ;;
    esac
    p2s_package_is_engine "$name" || return 1
    if [ "$P2S_DISTRO" = debian ]; then
        printf '%s\n' "$revision+$suffix.gbp$release"
    else
        revision=${revision%%+0~*}
        case "$name" in php7.0-*|libapache2-mod-php7.0) revision=7.0.33-92 ;; php7.1-*|libapache2-mod-php7.1) revision=7.1.33-80 ;; esac
        printf '%s\n' "$revision+$suffix"
    fi
}

p2s_version_sury_backport_fixed() {
    local fixed source=${1#libapache2-mod-}
    source=${source%%-*}
    fixed=$(p2s_version_sury_fixed_build_output "$1" "$3") || return 1
    [ "$4" = "$source" ] && [ "$5" = "$2" ] && [ "$2" = "$fixed" ]
}

p2s_version_package_state() {
    local name="$1" version="$2" vendor="$3" arch="${4:-unknown}" state floor release
    state=$(p2s_version_upstream_state "$version")
    if [ "$P2S_BACKEND" = deb ]; then
        if p2s_version_sury_backport_fixed "$name" "$version" "$arch" "$5" "$6"; then printf 'N\n'; return; fi
        # This exact native Jessie build includes the reviewed Sury mitigation for both CVEs.
        # Keep later local revisions unknown until their source and build evidence is reviewed.
        case "$P2S_DISTRO:$P2S_RELEASE:$vendor:$version" in
            debian:8:*Debian*:5.6.40+dfsg-0+deb8u23+rhphp2shell1|debian:8.*:*Debian*:5.6.40+dfsg-0+deb8u23+rhphp2shell1)
                case "$name" in
                    php5-common|php5-cli|php5-cgi|php5-fpm|php5-phpdbg|libapache2-mod-php5|libapache2-mod-php5filter|libphp5-embed)
                        printf 'N\n'; return ;;
                esac ;;
        esac
        # Vendor packages can retain older upstream numbers; assess the full package revision and backport rule.
        [ "$state" = Y ] && state='?'
        floor=$(p2s_version_deb_fixed_floor "$name")
        # Sury/PPA revisions can retain Debian/Ubuntu maintainer names; official backport floors do not apply.
        case "$version" in
            *sury*|*ppa*|*+0~*) floor= ;;
            *plesk*|*cpanel*) floor= ;;
        esac
        case "$P2S_DISTRO:$vendor:$version" in
            ubuntu:*Ubuntu*:*ubuntu*|debian:*Debian*:*deb12u*|debian:*Debian*:*deb13u*)
                if [ -n "$floor" ] && p2s_command_exists dpkg; then
                    if dpkg --compare-versions "$version" ge "$floor"; then state=N; else state=Y; fi
                fi ;;
            *)
                [ "$state" = N ] || state='?' ;;
        esac
    elif [ "$P2S_BACKEND" = rpm ] && { [ "$name" = cpanel-php81 ] || [ "$name" = cpanel-php84 ]; }; then
        [ "$state" = N ] || state='?'
        # Exact stock RPMs in cPanel's advisory and repositories; custom revisions remain unverified.
        # https://www.cpanel.net/blog/security/php-cve-2026-109618-and-cve-2026-109619-cpanel-response/
        case "$name:${version#0:}:$arch" in
            cpanel-php81:8.1.34-2.cp110~el[789]:x86_64) state=N ;;
            cpanel-php81:8.1.34-1.cp110~el[789]:x86_64|cpanel-php84:8.4.22-1.cp130~el[89]:x86_64|cpanel-php84:8.4.22-1.cp130~el10:x86_64) state=Y ;;
        esac
    elif [ "$P2S_DISTRO" = almalinux ] && [ "${vendor#*AlmaLinux}" != "$vendor" ]; then
        release=${version#*:}
        # Exact vendor builds: do not compare RPM EVRs with lexical or Debian ordering.
        # Later backports not listed here stay unknown until their errata are verified.
        case "$P2S_MAJOR:$release" in
            10:8.3.31-1.el10_2)
                # This exact stock build predates Alma's published PHP2Shell fix; other rebuilds remain unverified.
                # https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/
                state='?'
                case "$version" in 8.3.31-1.el10_2|0:8.3.31-1.el10_2)
                    case "$P2S_BACKEND:$vendor:$name" in
                        rpm:AlmaLinux:php|rpm:AlmaLinux:php-cli|rpm:AlmaLinux:php-common|rpm:AlmaLinux:php-fpm|rpm:AlmaLinux:php-embedded) state=Y ;;
                    esac ;;
                esac ;;
            8:7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1|8:7.3.20-1.module_el8.10.0+4316+90ea5fe5.alma.1|8:7.4.33-8.module_el8.10.0+4321+cf5fd4bb|8:8.0.30-1.module_el8.10.0+4319+26f10322.alma.1|8:8.2.33-1.module_el8.10.0+4320+c30d6dbb.alma.1|9:8.0.30-8.el9_8.alma.1|9:8.1.32-1.module_el9.8.0+326+528679fc.alma.1|9:8.2.33-1.module_el9.8.0+327+37dfd4b4.alma.1|9:8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1|10:8.3.33-1.el10_2.alma.1|10:8.4.24-1.el10_2.alma.1) state=N ;;
            *) [ "$state" = N ] || state='?' ;;
        esac
    elif [ "$P2S_BACKEND" = rpm ] && [ "$P2S_DISTRO" = rocky ] && [ "$vendor" = 'Rocky Enterprise Software Foundation' ]; then
        [ "$state" = N ] || state='?'
        # RLSA-2026:87151 fixes both CVEs without changing upstream PHP 8.0.30.
        # https://errata.rockylinux.org/RLSA-2026:87151 (exact build, not an RPM ordering rule).
        # Rocky 8 RLSA-2026:87080 supplies both fixes in the vendor-supported PHP 7.4 stream.
        case "$P2S_MAJOR:${version#0:}:$arch" in 8:7.4.33-8.module+el8.10.0+40393+c071e357:x86_64)
            case "$name" in php|php-cli|php-common|php-fpm|php-embedded) state=N ;; esac ;;
        esac
        case "$P2S_MAJOR:${version#0:}" in 9:8.0.30-8.el9_8.1)
            case "$name" in php|php-cli|php-common|php-fpm|php-embedded) state=N ;; esac ;;
        esac
    elif [ "$P2S_BACKEND" = rpm ] && [ "$P2S_DISTRO" = centos ] && [ "$P2S_MAJOR" = 5 ] && [ "$vendor" = CentOS ]; then
        [ "$state" = N ] || state='?'
        # Presume this archived stock build affected: it predates the fixes; exact pre-5.4 exploitability is untested.
        # https://cert.europa.eu/publications/security-advisories/2026-018/
        case "$name:${version#0:}" in
            php:5.1.6-44.el5_10|php-cli:5.1.6-44.el5_10|php-common:5.1.6-44.el5_10) state=Y ;;
        esac
    elif [ "$P2S_BACKEND" = rpm ]; then
        # Vendor backports below the upstream floors need vendor/stream-specific evidence.
        [ "$state" = N ] || state='?'
    fi
    # A recognised fixed upstream release does not need a separate publisher whitelist.
    # Older versions still require a verified vendor backport rule above.
    printf '%s\n' "$state"
}

p2s_state_include() {
    # These flags are sticky across all installations in one inventory pass.
    # A fixed version must never clear an earlier vulnerable or unknown result.
    case "$1" in Y) P2S_VULNERABLE=true ;; '?') P2S_UNKNOWN=true ;; esac
    P2S_COUNT=$((P2S_COUNT + 1))
}

p2s_state_has_only_fixed_versions() {
    # This covers assessed versions only; process and inventory gaps can still require an unknown result.
    [ -s "$P2S_WORK/summary-versions" ] || return 1
    awk -F'|' '$2 != "N" { unverified=1 } END { exit unverified }' "$P2S_WORK/summary-versions"
}

# Package inventory, ownership and publisher evidence

p2s_package_family_for_distro() {
    case "$P2S_DISTRO" in
        debian|ubuntu) printf 'deb\n' ;;
        almalinux|rocky|rhel|centos|whitebox|ol|fedora) printf 'rpm\n' ;;
        *) printf 'unknown\n' ;;
    esac
}

p2s_package_is_php() {
    # ea-php is cPanel EasyApache; alt-php is CloudLinux's parallel PHP; lsphp is LiteSpeed PHP.
    # WebPros sw-engine embeds PHP for Plesk or cPanel WP Toolkit, separately from website PHP.
    case "$1" in
        php|php[0-9]*|php-*|libapache*-mod-php*|ea-php*|alt-php*|plesk-php*|rh-php*|lsphp*|cpanel-php*|sw-engine*|frankenphp*) return 0 ;;
    esac
    return 1
}

p2s_package_is_engine() {
    local stem="$1" number
    # Debian's unversioned php/php-cli/php-fpm packages select a version; they are not the engine.
    if [ "$P2S_BACKEND" = deb ]; then
        case "$1" in php|php[0-9]|php[0-9].[0-9]|php-common|php-cli|php-cgi|php-fpm|php-phpdbg|libapache*-mod-php) return 1 ;; esac
    fi
    # EasyApache's unversioned CLI selector has its own version (for example 1.0.0).
    case "$1" in ea-php-cli|ea-php[0-9]|ea-php[0-9][0-9]) return 1 ;; esac
    # EasyApache's LiteSpeed SAPI package owns lsphp and versions the PHP engine.
    case "$1" in ea-php[0-9][0-9]-php-litespeed) return 0 ;; esac
    # cpanel-php84-xml-serializer 0.21.0 versions a library, not PHP itself.
    # Strip only engine-role suffixes; the remaining panel/LiteSpeed stem must end in digits.
    case "$stem" in
        cpanel-php*|lsphp*)
            case "$stem" in
                *-common|*-cli|*-cgi|*-fpm|*-phpdbg|*-embedded) stem=${stem%-*} ;;
            esac
            case "$stem" in cpanel-php*) number=${stem#cpanel-php} ;; lsphp*) number=${stem#lsphp} ;; esac
            case "$number" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac ;;
    esac
    case "$1" in
        php|php[0-9]|php[0-9].[0-9]|*-php|*-common|*-cli|*-cgi|*-fpm|*-phpdbg|*-embedded|libapache*-mod-php*|sw-engine|frankenphp) return 0 ;;
    esac
    return 1
}

p2s_package_provider() {
    # Namespace takes precedence: a panel package can retain its distribution's vendor metadata.
    case "$1" in
        cpanel-php*) printf 'cPanel internal\n' ;; ea-php*) printf 'cPanel EasyApache\n' ;;
        alt-php*) printf 'CloudLinux/TuxCare alt-PHP (namespace hint)\n' ;; plesk-php*) printf 'Plesk\n' ;;
        sw-engine*) printf 'WebPros sw-engine (Plesk/WP Toolkit)\n' ;;
        lsphp*) printf 'LiteSpeed\n' ;; frankenphp*) printf 'FrankenPHP\n' ;;
        *)
            # Maintainer is not origin: Sury builds can retain Debian PHP Maintainers.
            # Revision signatures identify a packaging family, not the download repository.
            case "$3" in
                *+rhphp2shell*) printf 'RimuHosting PHP2Shell backport (revision hint)\n'; return ;;
                *freexian*) printf 'Freexian PHP LTS (revision hint)\n'; return ;;
                *.remi*) printf 'Remi (revision hint)\n'; return ;;
                *sury*|*+0~*) printf 'Sury/ondrej PHP (revision hint)\n'; return ;;
                *ppa*) printf 'Ubuntu PPA (package publisher unverified)\n'; return ;;
            esac
            case "$2" in
                *Freexian*) printf 'Freexian PHP LTS\n' ;;
                *Sury*|*Surý*|*sury.org*) printf 'Sury/ondrej PHP\n' ;;
                *CloudLinux*) printf 'CloudLinux\n' ;; *TuxCare*) printf 'TuxCare\n' ;;
                *AlmaLinux*) printf 'AlmaLinux\n' ;; *Debian*) printf 'Debian\n' ;;
                *Ubuntu*) printf 'Ubuntu\n' ;; *Rocky*) printf 'Rocky Linux\n' ;;
                *Red\ Hat*) printf 'Red Hat\n' ;; *Remi*) printf 'Remi\n' ;;
                *) printf '%s\n' "${2:-unverified source}" ;;
            esac ;;
    esac
}

p2s_package_provider_website() {
    # Static public links only: repository URLs may contain subscription credentials.
    case "$1" in
        Sury/*) printf 'https://sury.org/\n' ;;
        Freexian*) printf 'https://www.freexian.com/lts/php/\n' ;;
        Remi*) printf 'https://rpms.remirepo.net/\n' ;;
        CloudLinux/TuxCare*) printf 'https://docs.tuxcare.com/els-for-runtimes/php/\n' ;;
        CloudLinux*) printf 'https://www.cloudlinux.com/\n' ;;
        TuxCare*) printf 'https://docs.tuxcare.com/els-for-runtimes/php/\n' ;;
        cPanel*) printf 'https://docs.cpanel.net/ea4/php/\n' ;;
        Plesk) printf 'https://docs.plesk.com/\n' ;;
        WebPros*) printf 'https://support.cpanel.net/hc/en-us/articles/1500011785822-How-To-Enable-Debug-Level-Logging-In-sw-engine\n' ;;
        LiteSpeed) printf 'https://www.litespeedtech.com/open-source/litespeed-php\n' ;;
        FrankenPHP) printf 'https://frankenphp.dev/\n' ;;
        Debian) printf 'https://www.debian.org/security/\n' ;;
        Ubuntu) printf 'https://ubuntu.com/security/notices\n' ;;
        AlmaLinux) printf 'https://errata.almalinux.org/\n' ;;
        'Rocky Linux') printf 'https://errata.rockylinux.org/\n' ;;
        'Red Hat') printf 'https://access.redhat.com/security/\n' ;;
    esac
}

p2s_package_owner_for_path() {
    local path="$1" output
    # Alternatives such as /usr/bin/php are often unowned links to a packaged executable.
    if [ -L "$path" ] && p2s_command_exists readlink; then
        output=$(readlink -f "$path" 2>/dev/null)
        [ -n "$output" ] && path="$output"
    fi
    if [ "$P2S_BACKEND" = deb ]; then
        if p2s_command_exists dpkg-query; then
            output=$(p2s_command_run 30 dpkg-query -S "$path" 2>/dev/null) || return 1
        else
            output=$(p2s_command_run 30 dpkg -S "$path" 2>/dev/null) || return 1
        fi
        printf '%s\n' "$output" | sed -n 's/: \/.*//p' | head -n 1
    elif [ "$P2S_BACKEND" = rpm ]; then
        p2s_command_run 30 rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null > "$P2S_WORK/owner" || return 1
        cat "$P2S_WORK/owner"
    fi
}

p2s_package_inventory_collect() {
    local raw="$P2S_WORK/packages.raw" name version arch status vendor
    : > "$P2S_WORK/packages"
    P2S_BACKEND=unknown
    # An auxiliary dpkg/rpm installation on Arch cannot inventory the host's pacman packages.
    if [ "$P2S_DISTRO" = arch ]; then
        P2S_UNKNOWN=true
        p2s_manifest_record package_backend unknown
        p2s_manifest_record inventory_gap 'pacman|package inventory and ownership are not implemented'
        p2s_fix_block package_manager "Arch Linux package inventory is not implemented in this script. PHP executable versions are checked, but package ownership and vendor patches need manual verification."
        return
    elif [ "$(p2s_package_family_for_distro)" != rpm ] && { p2s_command_exists dpkg-query || p2s_command_exists dpkg; }; then
        P2S_BACKEND=deb
        if p2s_command_exists dpkg-query; then
            # Old dpkg supports Package, Version, Architecture, Status and Maintainer.
            if ! p2s_command_run 60 dpkg-query -W '-f=${Package}|${Version}|${Architecture}|${Status}|${Maintainer}\n' > "$raw" 2> "$P2S_WORK/query.err"; then
                p2s_fix_block package_query "The Debian package inventory failed; installed PHP packages remain unknown."
                P2S_UNKNOWN=true
                return
            fi
        elif ! p2s_command_run 60 dpkg -l > "$raw.list" 2> "$P2S_WORK/query.err"; then
            p2s_fix_block package_query "The dpkg package inventory failed."
            P2S_UNKNOWN=true
            return
        else
            # ii php5-cli 5.6.40-... amd64 ... (older dpkg may omit architecture).
            awk '$1 == "ii" { print $2 "|" $3 "|unknown|install ok installed|unknown" }' "$raw.list" > "$raw"
            P2S_UNKNOWN=true
            p2s_message_print warn "Using the limited dpkg -l fallback; package provenance is unverified."
        fi
    elif p2s_command_exists rpm; then
        P2S_BACKEND=rpm
        if ! p2s_command_run 60 rpm -qa --qf '%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}|%{ARCH}|install ok installed|%{VENDOR}\n' > "$raw" 2> "$P2S_WORK/query.err"; then
            p2s_fix_block package_query "The RPM package inventory failed; installed PHP packages remain unknown."
            P2S_UNKNOWN=true
            return
        fi
    else
        p2s_manifest_record package_backend unknown
        p2s_manifest_record inventory_gap 'package inventory unavailable|ownership and vendor patches unverified'
        p2s_fix_block package_manager "Package inventory is unavailable. PHP executable versions are checked, but package ownership and vendor patches need manual verification."
        P2S_UNKNOWN=true
        return
    fi
    while IFS='|' read -r name version arch status vendor; do
        p2s_package_is_php "$name" || continue
        p2s_manifest_record package_install_status "$P2S_BACKEND|$name|$arch|$status"
        if [ "$status" != 'install ok installed' ]; then
            case "$status" in *'not-installed'*|*'config-files'*) continue ;; esac
            p2s_fix_block package_state "PHP package $name is not fully installed: $status."
            P2S_UNKNOWN=true
        fi
        # Package names become command arguments; reject unexpected query output.
        case "$name" in ''|*[!a-zA-Z0-9.+:_-]*) P2S_UNKNOWN=true; continue ;; esac
        case "$version" in '(none):'*) version="0:${version#*:}" ;; esac
        printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/packages"
        p2s_manifest_record package "$P2S_BACKEND|$name|$version|$arch|$vendor"
    done < "$raw"
    p2s_manifest_record package_backend "$P2S_BACKEND"
}

p2s_package_backport_evidence_collect() {
    local name="$1" file evidence="$P2S_WORK/backport-evidence"
    : > "$evidence"
    if [ "$P2S_BACKEND" = rpm ]; then
        p2s_command_run 30 rpm -q --changelog "$name" > "$evidence" 2>/dev/null || return 0
    else
        for file in /usr/share/doc/"$name"/changelog.Debian /usr/share/doc/"$name"/changelog.Debian.gz; do
            [ -r "$file" ] || continue
            case "$file" in
                *.gz)
                    if p2s_command_exists gzip; then p2s_command_run 15 gzip -cd "$file" > "$evidence" 2>/dev/null || return 0
                    elif p2s_command_exists zcat; then p2s_command_run 15 zcat "$file" > "$evidence" 2>/dev/null || return 0
                    fi ;;
                *) cat "$file" > "$evidence" ;;
            esac
            break
        done
    fi
    # A mention can describe an unfixed or reverted patch. It is supporting evidence only.
    LC_ALL=C awk '/CVE-2026-109618|CVE-2026-109619/ { print; count++; if (count==20) exit }' "$evidence" |
        while IFS= read -r file; do p2s_manifest_record backport_mention "$name|$file"; done
}

p2s_package_inventory_assess() {
    local name version arch vendor state path upstream role provider reason upstream_state source_record source_name source_version required
    local fixed_build comparison summary_reason
    : > "$P2S_WORK/package-states"
    : > "$P2S_WORK/summary-versions"
    : > "$P2S_WORK/bundled-providers"
    : > "$P2S_WORK/embedded-pending"
    : > "$P2S_WORK/embedded-assessed"
    while IFS='|' read -r name version arch vendor; do
        if p2s_package_is_engine "$name"; then
            provider=$(p2s_package_provider "$name" "$vendor" "$version")
            case "$name" in
                cpanel-php*|sw-engine*|lsphp*|frankenphp*)
                    if ! grep -Fx -e "$provider" "$P2S_WORK/bundled-providers" >/dev/null; then
                        printf '%s\n' "$provider" >> "$P2S_WORK/bundled-providers"
                        case "${P2S_PANEL:-}:$name" in
                            cpanel:cpanel-php*|cpanel:sw-engine*|plesk:sw-engine*)
                                if [ -n "$P2S_PANEL_TOOL" ]; then
                                    if [ "$name" = cpanel-php84 ] || [ "$name" = cpanel-php81 ]; then
                                        p2s_message_print info "cPanel includes its own PHP software for panel features. Update mode runs $P2S_PANEL_TOOL --security to request cPanel's security fixes."
                                    else
                                        p2s_message_print info "$provider includes its own PHP software. Update mode uses the installed $P2S_PANEL updater for it."
                                    fi
                                    p2s_manifest_record panel_runtime_scope "$name|vendor_update_available|PHP_fixes_assessed_separately"
                                else p2s_fix_block bundled_php "$provider PHP requires a vendor-specific update and restart procedure."; fi ;;
                            *) p2s_fix_block bundled_php "$provider PHP requires a vendor-specific update and restart procedure." ;;
                        esac
                    fi ;;
            esac
            p2s_package_backport_evidence_collect "$name"
            # sw-engine and FrankenPHP version their containing product, not the embedded PHP engine.
            case "$name" in sw-engine|frankenphp*) state='?'; upstream_state='?' ;;
                *) source_record=
                   if [ -r "$P2S_WORK/deb-source-records" ]; then
                       source_record=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4 FS $5]++ {print $4 "|" $5}' "$P2S_WORK/deb-source-records")
                   fi
                   source_name=${source_record%%|*}; source_version=${source_record#*|}
                   state=$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$source_name" "$source_version")
                   upstream_state=$(p2s_version_upstream_state "$version") ;;
            esac
            case "$name" in
                sw-engine|frankenphp*)
                    # The executable, not the product package version, determines embedded PHP's state.
                    printf '%s\n' "$name" >> "$P2S_WORK/embedded-pending"
                    P2S_COUNT=$((P2S_COUNT + 1)) ;;
                *) p2s_state_include "$state" ;;
            esac
            p2s_manifest_record package_state "$name|$state"
            reason=verified_version_rule
            if [ "$state" = Y ]; then reason=verified_affected_version_rule; fi
            if [ "$state" = Y ] && [ "$upstream_state" = '?' ]; then reason=presumed_affected_legacy_vendor_build; fi
            if [ "$state" = '?' ]; then reason=no_verified_vendor_rule_or_unrecognised_version; fi
            p2s_manifest_record package_assessment "$name|$version|$arch|$vendor|$provider|$state|$reason|upstream=$upstream_state"
            summary_reason=$reason; fixed_build=
            case "$P2S_BACKEND:$provider" in deb:Sury/*)
                fixed_build=$(p2s_version_sury_fixed_build_output "$name" "$arch")
                comparison=not_compared
                if [ -n "$fixed_build" ]; then comparison=tool_unavailable; fi
                if [ -n "$fixed_build" ] && p2s_command_exists dpkg; then
                    comparison=failed
                    if dpkg --compare-versions "$version" lt "$fixed_build" 2>/dev/null; then comparison=older
                    elif dpkg --compare-versions "$version" gt "$fixed_build" 2>/dev/null; then comparison=newer
                    elif dpkg --compare-versions "$version" eq "$fixed_build" 2>/dev/null; then comparison=equal
                    fi
                fi
                p2s_manifest_record package_fix_reference "$name|installed=$version|reviewed_fixed=${fixed_build:-unavailable}|comparison=$comparison"
                if [ "$state" = '?' ]; then summary_reason=sury_build_$comparison; fi ;;
            esac
            printf '%s|%s\n' "$name" "$state" >> "$P2S_WORK/package-states"
            upstream=$(printf '%s\n' "${version#*:}" | sed 's/[^0-9.].*//')
            [ -n "$upstream" ] || upstream="unrecognised version ($name)"
            if [ "$P2S_PHASE" = afterfix ] && ${P2S_PANEL_UPDATE_COMPLETED:-false} && [ "$state" != N ]; then
                case "$P2S_PANEL:$name" in
                    cpanel:cpanel-php84|cpanel:cpanel-php81)
                        required='8.4.27 or later in the PHP 8.4 branch'
                        if [ "$name" = cpanel-php81 ]; then required='cPanel PHP 8.1.34-2.cp110'; fi
                        p2s_manifest_record panel_update_verification "$name|$version|$state|required=$required"
                        p2s_message_print warn "cPanel's security updater returned success, but $name still lacks a verified fix (installed package: $version; required: $required). Review WHM's Update Preferences (/etc/cpupdate.conf) and /var/cpanel/updatelogs. The security updater can skip updates without an error or log; see the reported update settings."
                        p2s_cpanel_last_update_report ;;
                esac
            fi
            case "$name" in
                libapache*-mod-php*) role='Apache module' ;;
                *-cli) role='command line' ;; *-cgi) role=CGI ;; *-fpm) role=PHP-FPM ;;
                *-common) role='runtime libraries' ;; *-phpdbg) role=debugger ;;
                *) role="$name" ;;
            esac
            # Only executable output identifies the embedded PHP version in these product packages.
            case "$name" in
                sw-engine|frankenphp*) p2s_manifest_record embedded_runtime_package "$name|$version|PHP_version=requires_executable_probe" ;;
                *) printf '%s|%s|%s||%s|%s|%s|package|%s|%s|%s\n' "$upstream" "$state" "$role" "$provider" "$version" "$upstream_state" "$summary_reason" "$name" "$fixed_build" >> "$P2S_WORK/summary-versions" ;;
            esac
        else
            p2s_manifest_record package_classification "$name|supporting_or_selector_package|version_is_not_a_PHP_engine_version"
        fi
        if [ "$P2S_BACKEND" = deb ]; then
            if p2s_command_exists dpkg-query; then
                p2s_command_run 30 dpkg-query -L "$name" > "$P2S_WORK/files" 2>/dev/null
            else
                p2s_command_run 30 dpkg -L "$name" > "$P2S_WORK/files" 2>/dev/null
            fi
        else
            p2s_command_run 30 rpm -ql "$name" > "$P2S_WORK/files" 2>/dev/null
        fi
        if [ "$?" -ne 0 ]; then
            P2S_UNKNOWN=true
            p2s_manifest_record inventory_gap "package_files|$name|file_list_failed"
            p2s_message_print warn "Could not list runtime files for PHP package $name; its installation could not be fully checked."
            continue
        fi
        while IFS= read -r path; do p2s_runtime_path_add "$path"; done < "$P2S_WORK/files"
    done < "$P2S_WORK/packages"
}

# Package sources, policies and failure diagnostics

# Policy files are evidence, not a reimplementation of the package manager's precedence rules.
# Include global/wildcard rules: a restriction need not contain the word "php" to affect PHP.
p2s_package_policy_collect() {
    local file kind count=0 record base
    local files
    case "$P2S_BACKEND" in
        deb) files=(/etc/apt/preferences /etc/apt/preferences.d/*) ;;
        rpm) files=(/etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo
            /etc/yum/pluginconf.d/versionlock.conf /etc/yum/pluginconf.d/versionlock.list /etc/yum/pluginconf.d/priorities.conf
            /etc/dnf/plugins/versionlock.conf /etc/dnf/plugins/versionlock.list /etc/dnf/modules.d/*.module) ;;
        *) return 0 ;;
    esac
    for file in "${files[@]}"; do
        [ -f "$file" ] || continue
        count=$((count + 1))
        if [ "$count" -gt 64 ]; then p2s_manifest_record package_policy_gap 'file_limit=64|remaining_files_not_inspected'; break; fi
        if [ "$P2S_BACKEND" = deb ] && [ "$file" != /etc/apt/preferences ]; then
            base=${file##*/}
            # APT ignores fragments with unsupported names or extensions, such as foo.disabled.
            case "$base" in *[!a-zA-Z0-9._-]*|.*) p2s_manifest_record package_policy_gap "$file|ignored_fragment_name"; continue ;; esac
            case "$base" in *.*) case "$base" in *.pref) ;; *) p2s_manifest_record package_policy_gap "$file|ignored_fragment_extension"; continue ;; esac ;; esac
        fi
        p2s_manifest_record package_policy_file "$P2S_BACKEND|$file|observed_configuration_only"
        if [ ! -r "$file" ]; then p2s_manifest_record package_policy_gap "$file|unreadable"; continue; fi
        case "$P2S_BACKEND:$file" in
            deb:*) kind=apt_pin ;;
            rpm:*.list) kind=rpm_versionlock ;;
            *) kind=rpm_policy ;;
        esac
        # Whitelist policy keys; omit passwords, proxy settings and arbitrary comments.
        # Drop oversized lines whole: cutting a URL before its @ could expose partial credentials.
        if ! awk -v kind="$kind" '
            NR>200 { print "scope|truncated_after_200_lines"; exit }
            /^[ \t\r\n\014\013]*[#;]/ { next }
            /^[ \t\r\n\014\013]*$/ { key=""; stanza++; next }
            {
                line=$0; sub(/^[ \t\r\n\014\013]*/, "", line)
                sub(/[ \t\r\n\014\013]+[#;].*$/, "", line)
                if (length(line)>512) { print "scope|line=" NR "|omitted_over_512_characters"; key=""; next }
                if (kind=="apt_pin") {
                    if (line ~ /^[A-Za-z-]+:/) {
                        key=tolower(line); sub(/:.*/, "", key)
                    } else if ($0 !~ /^[ \t\r\n\014\013]/) key=""
                    if (key ~ /^(package|pin|pin-priority)$/)
                        print "stanza=" stanza+1 "|line=" NR "|" line
                } else if (kind=="rpm_versionlock") {
                    # YUM: 0:php-8.2.1-1.el9.* ; DNF: php-0:8.2.1-1.el9.* or ! exclusions.
                    lock=line; gsub(/[][]/, "", lock)
                    if (lock ~ /^[!a-zA-Z0-9*?_.:+-]+$/) print "line=" NR "|" line
                    else print "scope|line=" NR "|unsupported_lock_entry"
                } else {
                    if (line ~ /^\[/) { section=line; next }
                    if (line ~ /^(exclude|excludepkgs|includepkgs|priority|enabled|locklist|plugins|pluginconfpath|reposdir|module_hotfixes|name|stream|state|profiles)[ \t\r\n\014\013]*=/)
                        print section "|line=" NR "|" line
                }
            }' "$file" > "$P2S_WORK/policy-excerpt"; then
            p2s_manifest_record package_policy_gap "$file|read_failed"
            continue
        fi
        while IFS= read -r record; do
            p2s_manifest_record "$kind" "$file|$(printf '%s\n' "$record" | p2s_manifest_redact_repository_urls)"
        done < "$P2S_WORK/policy-excerpt"
    done
    p2s_manifest_record package_policy_scope 'standard_paths_only|custom_paths_and_full_precedence_not_evaluated|no_policy_changes|RPM_plugins_not_invoked|versionlock_can_affect_transactions_but_not_info_queries'
}

p2s_package_deb_policy_collect() {
    local record kind missing note=''
    if ! p2s_command_exists apt-cache || ! p2s_command_run 60 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$@" > "$P2S_WORK/apt-policy" 2> "$P2S_WORK/apt-policy.err"; then
        p2s_manifest_record source_gap 'APT package policy unavailable|repository matches unverified'
        if [ -s "$P2S_WORK/apt-policy.err" ]; then p2s_manifest_record apt_policy_error "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/apt-policy.err")"; fi
        return 0
    fi
    # Keep effective priorities as well as repository matches. A repository row's 500 does not
    # override a pinned version row of -1; the latter can make an installed package uninstallable.
    awk '
        function candidate() {
            if (name=="") return
            print "candidate|" name "|installed=" installed "|candidate=" proposed "|negative_priority_seen=" negative
            if (installed!="" && installed!="(none)" && proposed=="(none)") print "missing|" name "|" negative
        }
        /^[^ \t\r\n\014\013][^ \t\r\n\014\013]*:$/ {
            candidate(); name=$0; sub(/:$/, "", name); version=""; installed=""; proposed=""; negative=0; next
        }
        $1=="Installed:" { installed=$2; next }
        $1=="Candidate:" { proposed=$2; next }
        $1=="***" || (NF==2 && $2 ~ /^-?[0-9]+$/) {
            if ($1=="***") { version=$2; priority=$3 } else { version=$1; priority=$2 }
            if (priority ~ /^-?[0-9]+$/) {
                print "priority|" name "|" version "|" priority
                if (priority+0<0) negative=1
            }
            next
        }
        version!="" && $1 ~ /^-?[0-9]+$/ && $2 ~ /:\/\// {
            role="other_available"
            if (version==installed) role="installed_version_match"
            if (version==proposed) role=role=="installed_version_match" ? "installed_and_candidate_match" : "candidate_match"
            print "repository_match|" name "|" version "|" role "|" $0
        }
        END { candidate() }' "$P2S_WORK/apt-policy" | p2s_manifest_redact_repository_urls > "$P2S_WORK/apt-policy-records"
    while IFS='|' read -r kind record; do
        case "$kind" in
            candidate) p2s_manifest_record apt_package_candidate "$record" ;;
            priority) p2s_manifest_record apt_version_priority "$record" ;;
            repository_match) p2s_manifest_record package_repository_match "$record" ;;
        esac
    done < "$P2S_WORK/apt-policy-records"
    missing=$(awk -F'|' '$1=="missing" { printf "%s%s", separator, $2; separator=", " }' "$P2S_WORK/apt-policy-records")
    if [ -n "$missing" ]; then
        P2S_PACKAGE_POLICY_REVIEW=true
        if grep '^missing|.*|1$' "$P2S_WORK/apt-policy-records" >/dev/null; then
            note=' Negative APT priorities were reported for at least one of these packages; they prohibit matching versions and can also block dependent PHP components.'
        fi
        if [ -f /etc/apt/preferences.d/debian-virtualmin-restricted-packages ]; then
            note="$note Review /etc/apt/preferences.d/debian-virtualmin-restricted-packages as well as other APT preferences."
        fi
        p2s_message_print warn "APT currently reports no allowed installation candidate for these installed PHP packages: $missing.$note Check package pins and configured sources. The metadata may be stale; a fix attempt refreshes it before simulation. This diagnostic does not change pin files or website PHP handlers."
        p2s_manifest_record package_policy_effect "APT|installed_without_candidate|$missing|cached_metadata_only"
    fi
    p2s_manifest_record package_source_scope 'APT matches report versions available in cached indexes. Historical download origin is unverified. Missing matches can follow stale/removed sources or local package installation.'
}

p2s_package_sources_collect() {
    local name version arch vendor provider record file revision manager website
    local packages
    packages=()
    p2s_package_policy_collect
    while IFS='|' read -r name version arch vendor; do
        packages[${#packages[@]}]="$name"
        provider=$(p2s_package_provider "$name" "$vendor" "$version")
        website=$(p2s_package_provider_website "$provider")
        p2s_manifest_record package_provider "$name|$version|$arch|$provider|evidence=namespace_revision_or_vendor|historical_download_origin=unverified|provider_website=$website"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    case "$P2S_BACKEND" in
        deb)
            : > "$P2S_WORK/deb-source-records"
            # dpkg's Source field: "php8.2 (8.2.29-1)" keeps a source revision distinct from a +b1 binary rebuild.
            # "php8.2" shares the binary version; an omitted Source falls back to binary name/version.
            if p2s_command_exists dpkg-query; then
                if p2s_command_run 60 dpkg-query -W '-f=${Package}|${Version}|${Architecture}|${Source}\n' "${packages[@]}" > "$P2S_WORK/deb-sources" 2>/dev/null; then
                    awk -F'|' '{
                        source=$4; revision=$2; evidence="source_field"
                        if (source=="") {
                            source=$1; sub(/:[^:]+$/, "", source); evidence="binary_name_version_fallback"
                        } else if (source ~ / \([^()]+\)$/) {
                            revision=source; sub(/^.* \(/, "", revision); sub(/\)$/, "", revision)
                            sub(/ \([^()]+\)$/, "", source)
                        }
                        print $1 "|" $2 "|" $3 "|" source "|" revision "|" evidence
                    }' "$P2S_WORK/deb-sources" > "$P2S_WORK/deb-source-records"
                    while IFS= read -r record; do p2s_manifest_record deb_source_package "$record"; done < "$P2S_WORK/deb-source-records"
                else p2s_manifest_record source_gap 'Debian source-package metadata unavailable'; fi
            else p2s_manifest_record source_gap 'dpkg-query unavailable|Debian source-package identity unverified'; fi
            if ! p2s_command_exists apt-cache; then p2s_manifest_record source_gap 'apt-cache unavailable|repository matches unverified'; return 0; fi
            # APT policy is offline. Empty cache paths avoid implicitly writing persistent binary caches.
            # No arguments shows release Origin/Label/Suite/Codename; package arguments show version matches.
            if p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/apt-origins" 2> "$P2S_WORK/apt-origins.err"; then
                p2s_manifest_record apt_repository_cache "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/apt-origins")"
            else
                p2s_manifest_record source_gap 'APT cached release metadata unavailable'
                p2s_manifest_record apt_policy_error "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/apt-origins.err")"
            fi
            p2s_package_deb_policy_collect "${packages[@]}" ;;

        rpm)
            # Header metadata survives removal of a repository; it is not yum/DNF transaction history.
            if p2s_command_run 60 rpm -q --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{BUILDTIME}|%{INSTALLTIME}\n' "${packages[@]}" > "$P2S_WORK/rpm-sources" 2>/dev/null; then
                p2s_manifest_record rpm_package_build "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/rpm-sources")"
            else p2s_manifest_record source_gap 'RPM build metadata unavailable'; fi
            while IFS='|' read -r name version arch vendor; do
                revision=${version#*:}
                # Old YUM stores a per-package from_repo record. Read it as data, without running yum or plugins.
                for file in /var/lib/yum/yumdb/*/*-"$name"-"$revision"-"$arch"/from_repo; do
                    [ -r "$file" ] || continue
                    record=$(p2s_manifest_redact_repository_urls < "$file")
                    p2s_manifest_record package_repository_record "$name|$version|$arch|yumdb|$file|$record"
                done
            done < "$P2S_WORK/packages"
            # Cache-only info can retain DNF/YUM From repo records. Disable optional plugins so this
            # reporting path does not invoke subscription/network helpers; redirect manager logs privately.
            manager=
            if p2s_command_exists dnf; then manager=dnf; elif p2s_command_exists yum; then manager=yum; fi
            if [ -n "$manager" ]; then
                if [ "$manager" = dnf ]; then record=--installed; else record=installed; fi
                if p2s_command_run 60 "$manager" -C '--disableplugin=*' "--setopt=logfile=$P2S_WORK/source-manager.log" "--setopt=logdir=$P2S_WORK" info "$record" "${packages[@]}" > "$P2S_WORK/rpm-origin-info" 2>/dev/null; then
                    # Keep identity and From repo only; descriptions and arbitrary URLs are not needed.
                    awk '/^(Name|Arch|Architecture|Version|Release|Repository|Repo|From repo)[ \t\r\n\014\013]*:/ { print }' "$P2S_WORK/rpm-origin-info" |
                        p2s_manifest_redact_repository_urls | while IFS= read -r record; do p2s_manifest_record rpm_repository_cache "$manager|$record"; done
                else p2s_manifest_record source_gap "$manager cached installed-package origins unavailable"; fi
            else p2s_manifest_record source_gap 'Neither DNF nor YUM is available to read retained repository origins'; fi
            p2s_manifest_record package_source_scope 'RPM metadata records vendor and build details. Retained YUM from_repo records supply repository history; installation method remains unknown where history is missing.' ;;
    esac
}

# Report retained build-release labels across Debian/Ubuntu too; PHP branch age cannot identify its OS release.
p2s_package_release_report() {
    local source_records=/dev/null name version arch family target evidence revision details
    : > "$P2S_WORK/package-release-mismatches"
    case "$P2S_BACKEND:$P2S_DISTRO" in
        deb:debian|deb:ubuntu|rpm:almalinux|rpm:rocky|rpm:rhel|rpm:ol|rpm:centos) ;;
        *) return 0 ;;
    esac
    [ -r "$P2S_WORK/packages" ] || return 0
    if [ "$P2S_BACKEND" = deb ] && [ -r "$P2S_WORK/deb-source-records" ]; then source_records="$P2S_WORK/deb-source-records"; fi
    # dpkg versions: 5.6.40+dfsg-0+deb8u12 -> Debian 8; +debian12~1 -> Debian 12.
    # ~bpo12+1 targets Debian 12 even if the base names Debian 13; legacy ~bpo70+1 means Debian 7.
    # +debian12~1 identifies Debian 12 even on an Ubuntu host; do not compare their release numbers.
    # Ubuntu: 8.3.6-0ubuntu0.24.04.13 -> Ubuntu 24.04; RPM: 8.1.34-2.cp110~el8 -> EL 8.
    if ! LC_ALL=C awk -F'|' -v distro="$P2S_DISTRO" -v current="$P2S_RELEASE" '
        function release(version, label) {
            if (distro=="debian" || distro=="ubuntu") {
                family="Debian"
                if (match(version, /~bpo[0-9]+[+]/)) {
                    label=substr(version,RSTART,RLENGTH); sub(/^~bpo/,"",label); sub(/[+]$/,"",label)
                    if (label=="60" || label=="70") label=substr(label,1,1)
                } else if (match(version, /[+~]deb[0-9]+u[0-9]+([+.~]|$)/)) {
                    label=substr(version,RSTART,RLENGTH); sub(/^[+~]deb/,"",label); sub(/u.*/,"",label)
                } else if (match(version, /[+]debian[0-9]+~/)) {
                    label=substr(version,RSTART,RLENGTH); sub(/^[+]debian/,"",label); sub(/~$/,"",label)
                }
                if (label=="") {
                    family="Ubuntu"
                    if (match(version, /ubuntu0[.][0-9][0-9][.][0-9][0-9]([.+~]|$)/)) {
                        label=substr(version,RSTART,RLENGTH); sub(/^ubuntu0[.]/,"",label); sub(/[.+~]$/,"",label)
                    } else if (match(version, /[+]ubuntu[0-9][0-9][.][0-9][0-9]([.+~]|$)/)) {
                        label=substr(version,RSTART,RLENGTH); sub(/^[+]ubuntu/,"",label); sub(/[.+~]$/,"",label)
                    }
                }
            } else {
                family="Enterprise Linux"
                if (match(version, /[.~]el[0-9]+([_.+~]|$)/)) {
                    label=substr(version,RSTART,RLENGTH); sub(/^[.~]el/,"",label); sub(/[_.+~]$/,"",label)
                }
            }
            return label
        }
        FILENAME==ARGV[1] {source[$1 FS $2 FS $3]=$5; next}
        {
            # Numeric VERSION_ID is required; codenames or unknown releases cannot prove age.
            if (current !~ /^[0-9]+([.][0-9]+)*$/) next
            revision=$2; target=release(revision); evidence="binary_version_marker"
            if (target=="" && ($1 FS $2 FS $3) in source) {
                revision=source[$1 FS $2 FS $3]; target=release(revision); evidence="source_version_marker"
            }
            installed=current
            if (family!="Ubuntu") sub(/[.].*/,"",installed)
            if (target!="" && ((family=="Debian" && distro=="ubuntu") ||
                (family=="Ubuntu" && distro=="debian") || target+0<installed+0))
                print $1 FS $2 FS $3 FS family FS target FS evidence FS revision
        }' "$source_records" "$P2S_WORK/packages" > "$P2S_WORK/package-release-mismatches"; then
        p2s_manifest_record source_gap 'package build-release assessment failed'
        return 0
    fi
    while IFS='|' read -r name version arch family target evidence revision; do
        p2s_manifest_record package_release_mismatch "$name|$version|$arch|target=$family $target|host=$P2S_DISTRO $P2S_RELEASE|evidence=$evidence|revision=$revision"
    done < "$P2S_WORK/package-release-mismatches"
    # Group packages by target release so a retained PHP build produces one customer warning.
    awk -F'|' '{
        key=$4 FS $5
        if (!(key in packages)) order[++count]=key
        detail=$1 " (" $2
        if ($6=="source_version_marker") detail=detail "; source " $7
        packages[key]=packages[key] separator[key] detail ")"; separator[key]=", "
    } END {for (i=1;i<=count;i++) print order[i] FS packages[order[i]]}' "$P2S_WORK/package-release-mismatches" |
        while IFS='|' read -r family target details; do
            case "$P2S_DISTRO:$family" in
                debian:Ubuntu|ubuntu:Debian)
                    p2s_message_print warn "PHP packages built for another distribution are installed: $details. Their build labels identify $family $target; this server runs $P2S_DISTRO $P2S_RELEASE. Review replacements built for this server's distribution and release; changing the repository alone does not replace these installed packages." ;;
                *) p2s_message_print warn "PHP packages from an older OS release are still installed: $details. Their build labels identify $family $target; this server runs $P2S_DISTRO $P2S_RELEASE. Review these packages and the PHP installations using them before choosing an update or migration." ;;
            esac
        done
    return 0
}

# A process snapshot can show use, but cannot prove that websites or future jobs no longer need PHP.
p2s_package_release_usage_report() {
    local path name family target installation usage references packages label qualifier complete=false
    [ -s "$P2S_WORK/package-release-mismatches" ] || return 0
    : > "$P2S_WORK/release-usage-observations"
    if [ -r "$P2S_WORK/runtime-package-observations" ]; then
        cat "$P2S_WORK/runtime-package-observations" > "$P2S_WORK/release-usage-observations"
        case "${P2S_PANEL:-}" in ''|none)
            if ${P2S_PROCESS_USAGE_COMPLETE:-false} && ! ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} &&
                ! ${P2S_RESTART_PENDING:-false} && ! ${P2S_BLOCKED:-false}; then complete=true; fi ;;
        esac
    fi
    # Enabled links count as configured use even when Apache is stopped or the link is broken.
    for path in /etc/apache2/mods-enabled/php*.load /etc/apache2/conf-enabled/php*-fpm.conf; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        name=${path##*/}; name=${name%.load}; name=${name%-fpm.conf}
        printf '%s|enabled_configuration|%s\n' "$name" "$path" >> "$P2S_WORK/release-usage-observations"
    done
    # php5-cli/php5-fpm/libapache2-mod-php5 share php5; keep php8.2, ea-php82 and alt-php82 separate.
    # A running FPM sibling protects the CLI, common files and extensions from an unused-package suggestion.
    LC_ALL=C awk -F'|' -v complete="$complete" '
        function installation(name) {
            sub(/:.*/,"",name); sub(/^libapache[^-]*-mod-/,"",name)
            if (match(name, /^(ea-|alt-|rh-|plesk-|cpanel-)?php[0-9]*([.][0-9]+)?/)) return substr(name,RSTART,RLENGTH)
            if (match(name, /^(lsphp[0-9]*|sw-engine|frankenphp)/)) return substr(name,RSTART,RLENGTH)
            return ""
        }
        FILENAME==ARGV[1] {
            if ($1=="") incomplete=1
            key=installation($1); if (key=="") next
            if ($2=="enabled_configuration") {
                configured[key]=1
                if (!seen[key FS $3]++) config[key]=config[key] config_separator[key] $3
                config_separator[key]=", "
            } else {
                observed[key]=1
                if ($2=="running_path") {
                    running[key]=1; reference=$1 " (" $3 ")"
                    if (!seen[key FS reference]++) references[key]=references[key] separator[key] reference
                    separator[key]=", "
                }
            }
            next
        }
        {
            stem=installation($1); key=$4 FS $5 FS (stem!="" ? stem : $1)
            if (!(key in packages)) order[++count]=key
            known[key]=(stem!=""); group[key]=stem
            packages[key]=packages[key] package_separator[key] $1; package_separator[key]=", "
        }
        END {for (i=1;i<=count;i++) {
            key=order[i]; stem=group[key]; use="unverified"; evidence="none"
            if (running[stem]) {use="running"; evidence=references[stem]}
            else if (configured[stem]) {use="configured"; evidence=config[stem]}
            else if (complete=="true" && !incomplete && known[key] && observed[stem]) use="no_running_use_observed"
            print key FS use FS evidence FS packages[key]
        }}' "$P2S_WORK/release-usage-observations" "$P2S_WORK/package-release-mismatches" |
        while IFS='|' read -r family target installation usage references packages; do
            p2s_manifest_record package_release_usage "installation=$installation|target=$family $target|usage=$usage|packages=$packages|evidence=$references|usage_assessment_complete=$complete"
            label=Older-release; qualifier=older-release
            case "$P2S_DISTRO:$family" in debian:Ubuntu|ubuntu:Debian) label=Mismatched; qualifier=mismatched ;; esac
            case "$usage" in
                running) p2s_message_print warn "$label PHP installation $installation ($family $target packages: $packages) is in use by running processes. Observed runtime packages: $references. Move the applications using it to maintained PHP before considering removal." ;;
                configured) p2s_message_print warn "$label PHP installation $installation ($family $target packages: $packages) has enabled Apache configuration: $references. Review its website assignments before considering removal." ;;
                no_running_use_observed) p2s_message_print info "No running use was found for $qualifier PHP installation $installation ($family $target packages: $packages). If websites, scheduled tasks and other installed packages no longer need it, consider removing these packages. Review the package manager's proposed removals first." ;;
                *) p2s_message_print warn "Use of $qualifier PHP installation $installation ($family $target packages: $packages) could not be established from the available process and package-file information. Check its websites, scheduled tasks and dependencies before considering removal." ;;
            esac
        done
}

p2s_package_repository_failure_report() {
    local kind identity sources
    # APT: "W: GPG error: https://user:secret@repo.invalid/private suite ..."
    # -> host=repo.invalid. RPM: "Failed to download metadata for repo 'remi'" -> repo_id=remi.
    LC_ALL=C p2s_manifest_redact_repository_urls < "$1" | LC_ALL=C awk '
        /^(Hit|Get|Ign)(:|[ \t])/ {next}
        {
            line=tolower($0)
            if ($0 ~ /(^Err[ :]|^E:|^[Ee]rrors?[: ]|GPG error|[Ff]ailed to|[Cc]annot |[Uu]nable to|[Cc]ould not|[Cc]ouldn.t |NO_PUBKEY|BADSIG|EXPKEYSIG|certificate.*(fail|error|problem|expired))/ ||
                line ~ /(^|[^0-9])404[ \t]+not[ \t]+found([^a-z]|$)/ ||
                line ~ /(http([\/][0-9.]+)?([ \t]+error)?|status([ \t]+code)?|error([ \t]+code)?)[ :\t]+404([^0-9]|$)/) print
        }
    ' > "$P2S_WORK/repository-errors"
    [ -s "$P2S_WORK/repository-errors" ] || return 0
    # Reuse the current, redacted inventory, including sources added during this fix.
    p2s_repository_inventory_collect | LC_ALL=C awk '
        function hosts(line, source, authority, key) {
            while (match(line, /\[repository host=[^;]+; path redacted\]/)) {
                authority=substr(line,RSTART,RLENGTH)
                sub(/^\[repository host=/, "", authority); sub(/; path redacted\]$/, "", authority)
                authority=tolower(authority)
                if (source=="") failed_hosts[authority]=1
                else {
                    key=authority SUBSEP source
                    if (!seen[key]++) host_sources[authority]=host_sources[authority] (host_sources[authority]=="" ? "" : ", ") source
                }
                line=substr(line,RSTART+RLENGTH)
            }
        }
        FILENAME=="-" {
            if ($0 !~ /^dss:manifest:repository_definition:[^|]+\|/) next
            split($0, fields, "|")
            source=fields[2] " (" fields[3] ")"
            hosts($0, source)
            if (fields[3] ~ /^rpm-repo=/) {
                repo=fields[3]; sub(/^rpm-repo=/, "", repo)
                key=repo SUBSEP source
                if (!seen_repos[key]++) repo_sources[repo]=repo_sources[repo] (repo_sources[repo]=="" ? "" : ", ") source
            }
            next
        }
        {
            hosts($0, "")
            # RPM diagnostics quote an ID, not the repository display name or its credentials.
            if (match($0, /repo(sitory)? [\047"][A-Za-z0-9_.:-]+[\047"]/)) {
                repo=substr($0,RSTART,RLENGTH)
                sub(/^[^ ]+ [\047"]/, "", repo); sub(/[\047"]$/, "", repo)
                failed_repos[repo]=1
            }
        }
        END {
            for (authority in failed_hosts) print "host|" authority "|" (host_sources[authority]=="" ? "not identified in conventional source files" : host_sources[authority])
            for (repo in failed_repos) print "repo_id|" repo "|" (repo_sources[repo]=="" ? "not identified in conventional source files" : repo_sources[repo])
        }
    ' - "$P2S_WORK/repository-errors" |
        while IFS='|' read -r kind identity sources; do
            p2s_manifest_record repository_failure_source "$kind=$identity|possible_sources=$sources|match=review_required"
            p2s_message_print warn "Repository $identity reported an error. Possible source files: $sources. Match the failing repository and suite before changing a source file."
        done
}

p2s_package_log_report() {
    # Package-manager failures can contain authenticated URLs. Never print those verbatim.
    LC_ALL=C p2s_manifest_redact_repository_urls < "$1" |
        while IFS= read -r line; do p2s_manifest_record command "$line"; done
    p2s_package_failure_report "$1"
    p2s_package_repository_failure_report "$1"
}

p2s_package_failure_report() {
    local pid details unit
    P2S_PACKAGE_FAILURE=
    if LC_ALL=C grep -Ei 'Could not get lock|Resource temporarily unavailable.*lock|held by process|another (app|copy).*lock|Existing lock' "$1" >/dev/null; then
        P2S_PACKAGE_FAILURE=package_manager_busy
        pid=$(sed -n 's/.*held by process \([0-9][0-9]*\).*/\1/p' "$1" | head -n 1)
        p2s_manifest_record repository_failure package_manager_busy
        p2s_message_print warn "Another package-manager operation is holding a required lock${pid:+ (PID $pid)}. Wait for it to finish; investigate the owning process if the job appears stuck. This script will not terminate that job or remove lock files."
        if [ -n "$pid" ]; then
            # Include age and parent identity, not command arguments, which can contain credentials.
            if p2s_command_exists ps && details=$(TZ=UTC p2s_command_run 10 ps -p "$pid" -o pid= -o ppid= -o etime= -o lstart= -o stat= -o comm= 2>/dev/null); then
                p2s_manifest_record package_manager_lock_holder "$pid|$details|start_time_zone=UTC"
            fi
            if [ -r "/proc/$pid/cgroup" ]; then
                unit=$(sed -n 's@.*/\([^/]*\.service\)$@\1@p' "/proc/$pid/cgroup" | head -n 1)
                p2s_manifest_record package_manager_lock_service "$pid|${unit:-unidentified}"
            fi
        fi
    fi
    if LC_ALL=C grep -Ei 'No space left on device|Disk quota exceeded|not enough (free )?(disk )?space|insufficient (free )?(disk )?space' "$1" >/dev/null; then
        P2S_PACKAGE_FAILURE=disk_full
        p2s_manifest_record repository_failure disk_full
        p2s_message_print warn "The package operation ran out of disk space, inodes or quota. Check the affected filesystem and package-manager cache, free space or grow the filesystem, then retry. No cache files were deleted automatically."
    fi
    if LC_ALL=C grep -Ei 'unmet dependencies|not installable|conflicting requests|nothing provides|cannot install.*(candidate|update)|filtered out by|excluded by|Packages need to be removed but remove is disabled' "$1" >/dev/null; then
        p2s_manifest_record package_resolution_failure 'dependency_or_policy|see_package_policy_and_candidate_manifest'
        p2s_message_print warn "The package manager could not find an allowed, compatible update. Package pins, version locks, exclusions, missing dependencies or repository/module settings may be involved. Review the policy and candidate details in the run manifest. Restrictions and package-removal protection were not bypassed."
    fi
    # Panel maintenance also logs successful certificate/TLS housekeeping; require a failure indication.
    if LC_ALL=C grep -Ei '(certificate|SSL|TLS|handshake).*(fail(ed|ure)?|error|problem|not trusted|not recognized|has expired)|(fail(ed|ure)?|error|unable to|could not).*(certificate|SSL|TLS|handshake)' "$1" >/dev/null; then
        p2s_manifest_record repository_failure tls
        p2s_message_print warn "The package or panel updater reported a TLS/certificate failure. Review the update log and repair trusted repository access. Certificate verification was not disabled."
    fi
    # APT: "Get:4 ... Packages [3404 B]" is success, not HTTP 404.
    # Failures: "404 Not Found", "HTTP Error 404", "Status code: 404 for https://...".
    LC_ALL=C awk '
        /^(Hit|Get|Ign)(:|[ \t])/ {next}
        {
            line=tolower($0)
            if (line ~ /(^|[^0-9])404[ \t]+not[ \t]+found([^a-z]|$)/ ||
                line ~ /(http([\/][0-9.]+)?([ \t]+error)?|status([ \t]+code)?|error([ \t]+code)?)[ :\t]+404([^0-9]|$)/) print
        }' "$1" | p2s_manifest_redact_repository_urls > "$P2S_WORK/repository-missing-files"
    if [ -s "$P2S_WORK/repository-missing-files" ]; then
        p2s_manifest_record repository_failure http_404
        LC_ALL=C sort -u "$P2S_WORK/repository-missing-files" | head -n 3 |
            while IFS= read -r details; do
                p2s_message_print warn "Repository request failed with HTTP 404 (file not found): $details. Check this request against the configured source; the repository may have moved or the package index may be stale."
            done
    fi
    if LC_ALL=C grep -Ei 'Could not resolve|Couldn.t resolve|Name or service not known|Temporary failure resolving' "$1" >/dev/null; then
        p2s_manifest_record repository_failure dns
        p2s_message_print warn "Package-source name resolution failed; check the server DNS and network configuration."
    fi
    if LC_ALL=C grep -Ei 'NO_PUBKEY|GPG error|not signed|signature.*(fail|invalid)|unsigned package' "$1" >/dev/null; then
        # Keep lock and disk failures primary when the same log also contains signing errors.
        P2S_PACKAGE_FAILURE=${P2S_PACKAGE_FAILURE:-authentication}
        p2s_manifest_record repository_failure authentication
        p2s_message_print warn "Package authentication failed. Check the vendor signing keys and repository configuration; signature checks were not disabled."
    fi
}

p2s_package_refresh_failure_report() {
    local reason
    p2s_package_log_report "$1"
    case "$P2S_PACKAGE_FAILURE:${P2S_BACKEND:-}" in
        package_manager_busy:*|disk_full:*)
            P2S_BLOCKED=true
            p2s_manifest_record blocker "$P2S_PACKAGE_FAILURE|Package metadata could not be refreshed; see the specific diagnostic above." ;;
        authentication:deb)
            reason="repository signature verification failed"
            if LC_ALL=C grep -F NO_PUBKEY "$1" >/dev/null; then
                reason="a repository signing key is missing (NO_PUBKEY)"
            fi
            p2s_fix_block repositories "Package-list refresh stopped because $reason. APT may retain old indexes for the failed repository even when other lists are current. See the affected repository and possible source files above, and the signing error in the package update log. Repair that repository's signing configuration, or disable it if no longer needed, then retry." ;;
        *) p2s_fix_block repositories "$2" ;;
    esac
}

# Guarded Debian and RPM package updates

p2s_package_deb_is_sury() {
    # Revision families, not generic +0~/PPA hints or Debian maintainer names.
    printf '%s\n' "$1" | LC_ALL=C awk '
        /\+deb[.]sury[.]org\+[0-9]+$/ {ok=1}
        /\+0~[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][.][0-9]+\+debian[0-9]+~[0-9]+[.]gbp[0-9a-f]+$/ {ok=1}
        END {exit !ok}'
}

p2s_package_deb_sury_trust_preflight() {
    local file
    # APT normally verifies repository signatures. Explicit trust overrides defeat that guarantee.
    p2s_command_exists apt-config && p2s_command_run 30 apt-config dump > "$P2S_WORK/apt-config" 2>/dev/null || {
        p2s_fix_block source_authentication "APT authentication settings could not be inspected; the Sury update needs manual review."; return 1;
    }
    # apt-config dump: APT::Get::AllowUnauthenticated "true";
    if ! awk '{
        key=tolower($1); value=tolower($2); gsub(/[";\r]/,"",value)
        if (key ~ /(allowunauthenticated|allowinsecurerepositories|allowweakrepositories|allowdowngradetoinsecurerepositories)$/ && value ~ /^(1|true|yes|on|enable)$/) bad=1
        if (key ~ /verify-(peer|host)$/ && value ~ /^(0|false|no|off|disable)$/) bad=1
        if (key=="dir" && value!="/") bad=1
        if (key=="dir::etc" && value!="etc/apt" && value!="/etc/apt") bad=1
        if (key=="dir::etc::sourcelist" && value!="sources.list" && value!="/etc/apt/sources.list") bad=1
        if (key=="dir::etc::sourceparts" && value!="sources.list.d" && value!="/etc/apt/sources.list.d") bad=1
        }
        END {exit bad}' "$P2S_WORK/apt-config"; then
        p2s_fix_block source_authentication "Insecure or custom APT source settings require review before a Sury update; no trust settings were changed."
        return 1
    fi
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        # sources.list: deb [trusted=yes] https://packages.sury.org/php bookworm main
        # Deb822 php.sources can also fold "Trusted:" onto a following indented "yes".
        # Reject overrides without copying source contents or credentials into diagnostics.
        if ! awk '
            /^[ \t]*#/ {next}
            /^[ \t]*$/ {key=""; next}
            {
                line=tolower($0); sub(/\r$/,"",line)
                if (line ~ /(^|[ \t\[])(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)[ \t]*=[ \t]*(yes|true|1|on|enable)([ \t\]]|$)/) bad=1
                if (line ~ /^[a-z-]+:/) {
                    key=line; sub(/:.*/,"",key); sub(/^[^:]*:[ \t]*/,"",line)
                } else if (line !~ /^[ \t]/) key=""
                sub(/^[ \t]*/,"",line)
                if (key ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)$/ && line ~ /^(yes|true|1|on|enable)([ \t]|$)/) bad=1
            }
            END {exit bad}' "$file"; then
            p2s_fix_block source_authentication "A source-local APT trust override or unreadable source file prevents a verified Sury update. Review the existing source settings."
            return 1
        fi
    done
}

p2s_package_deb_candidate() {
    local name="$1" installed="$2" arch="$3" sury="$4" target candidate observed matches other seen record metadata source source_version expected suite branch old_branch rest installed_source provider query_status=0
    target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/candidate-policy" 2> "$P2S_WORK/candidate-query.err" || query_status=$?
    if [ "$query_status" -ne 0 ]; then
        p2s_manifest_record apt_candidate_error "$name|operation=policy|exit=$query_status
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-query.err")"
        p2s_fix_block candidate_provider "Could not read the normal APT candidate for $name; no alternative source was selected."; return 1
    fi
    p2s_manifest_record apt_candidate_policy "$name|installed=$installed|architecture=$arch
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-policy")"
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*) suite=bullseye ;;
        debian:12|debian:12.*) suite=bookworm ;; debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        ubuntu:26.04) suite=resolute ;; *) suite=unsupported ;;
    esac
    # Global policy binds repository rows to their release identity. Check EVERY source of the
    # candidate version: inspect every origin of the exact selected version for duplicate sources.
    # apt-cache policy: 500 https://packages.sury.org/php bookworm/main amd64 Packages
    #                  release o=deb.sury.org,a=bookworm,n=bookworm,l=deb.sury.org,c=main,b=amd64
    # A per-package duplicate can be: 500 file:/local/repo bookworm/main amd64 Packages
    record=$(awk -v suite="$suite" '
        function uri_kind(uri) {
            if (uri ~ /^https?:\/\/packages[.]sury[.]org\/php\/?$/) return 1
            if (uri ~ /^https?:\/\/ppa[.]launchpad(content)?[.]net\/ondrej\/php\/ubuntu\/?$/) return 2
            return 0
        }
        NR==FNR {
            if ($1 ~ /^-?[0-9]+$/ && $2 ~ /:\/\// && $5=="Packages") {key=$2 "|" $3 "|" $4; kind=uri_kind($2); next}
            if ($1=="release" && key!="") {
                line="," $2 ","
                if (kind && index(line,",n=" suite ",") &&
                    ((kind==1 && index(line,",o=deb.sury.org,")) || (kind==2 && index(line,",o=LP-PPA-ondrej-php,")))) approved[key]=1
                key=""
            }
            next
        }
        $1=="Installed:" {installed=$2; next}
        $1=="Candidate:" {candidate=$2; next}
        $1=="***" {version=$2; next}
        NF==2 && $2 ~ /^-?[0-9]+$/ {version=$1; next}
        version==candidate && $1 ~ /^-?[0-9]+$/ && NF>=2 {
            if ($2=="/var/lib/dpkg/status") next
            if (uri_kind($2)) seen++
            if ($5=="Packages" && approved[$2 "|" $3 "|" $4]) matches++; else other++
        }
        END {print candidate "|" installed "|" matches+0 "|" other+0 "|" seen+0}
    ' "$P2S_WORK/candidate-origins" "$P2S_WORK/candidate-policy") || return 1
    candidate=${record%%|*}; record=${record#*|}; observed=${record%%|*}; record=${record#*|}
    matches=${record%%|*}; record=${record#*|}; other=${record%%|*}; seen=${record#*|}
    case "$candidate" in ''|'(none)'|*[!a-zA-Z0-9.+:~_-]*) p2s_fix_block no_candidate "No usable APT candidate was found for $name."; return 1 ;; esac
    [ "$observed" = "$installed" ] || { p2s_fix_block candidate_provider "Installed package state changed or could not be matched for $name."; return 1; }
    if [ "$sury" = true ]; then
        if ! p2s_package_deb_is_sury "$candidate" || [ "$matches" -eq 0 ] || [ "$other" -ne 0 ]; then
            p2s_fix_block candidate_provider "The normal candidate for $name is not exclusively from the existing Sury PHP source for this OS suite; refusing a PHP package source change or ambiguous origin."
            return 1
        fi
    else
        provider=$(p2s_package_provider "$name" '' "$candidate")
        case "$provider" in Sury*) seen=1 ;; esac
        if [ "$seen" -gt 0 ] && ! ${P2S_SURY_MIGRATION_ACTIVE:-false}; then
            p2s_fix_block candidate_provider "The normal candidate would replace non-Sury package $name with a Sury package; an explicit migration is required."
            return 1
        fi
        if [ "$seen" -gt 0 ]; then
            # Opt-in changes the permitted package publisher, never the identity of the package being replaced.
            if ! p2s_package_deb_is_sury "$candidate" || [ "$matches" -eq 0 ] || [ "$other" -ne 0 ]; then
                p2s_fix_block candidate_provider "The migration candidate for $name is not exclusively from the matching official Sury source."
                return 1
            fi
            sury=true
        fi
    fi
    # Never override an APT pin by choosing an older or alternative version explicitly.
    dpkg --compare-versions "$candidate" ge "$installed" || { p2s_fix_block package_downgrade "The normal candidate for $name is older than the installed version; refusing a downgrade."; return 1; }
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$candidate" > "$P2S_WORK/candidate-metadata" 2> "$P2S_WORK/candidate-query.err" || query_status=$?
    if [ "$query_status" -ne 0 ]; then
        p2s_manifest_record apt_candidate_error "$name|operation=metadata|exit=$query_status
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-query.err")"
        p2s_fix_block candidate_provider "Candidate package metadata is unavailable for $name."; return 1
    fi
    # apt-cache show can include long descriptions; retain only identity and dependency fields, including folded lines.
    record=$(awk '
        /^[^ \t]/ {keep=($0 ~ /^(Package|Version|Architecture|Source|Provides|Depends|Pre-Depends|Breaks|Conflicts|Replaces|Multi-Arch):/)}
        keep {print}' "$P2S_WORK/candidate-metadata" | p2s_manifest_redact_repository_urls)
    p2s_manifest_record apt_candidate_metadata "$name|candidate=$candidate
$record"
    # apt-cache show: Package: php7.4-cli; Source: php7.4 (source-version).
    # An omitted Source version shares the binary Version; omitted Source shares its Package.
    metadata=$(awk -v n="${name%:*}" -v v="$candidate" -v a="$arch" '
        function emit() {
            if (package=="") return
            if (package!=n || version!=v || arch!=a) bad=1
            if (source=="") source=package
            if (source_version=="") source_version=version
            if (!seen[source "|" source_version]++) print source "|" source_version
        }
        /^Package:/ {emit(); package=$2; version=""; arch=""; source=""; source_version=""}
        /^Version:/ {version=$2}
        /^Architecture:/ {arch=$2}
        /^Source:/ {source=$2; source_version=$3; gsub(/[()]/,"",source_version)}
        END {emit(); if (bad || package=="") exit 1}' "$P2S_WORK/candidate-metadata") || {
        p2s_fix_block candidate_provider "Candidate package name, version or architecture could not be verified for $name."; return 1;
    }
    if [ "$sury" = true ]; then
        installed_source=
        if [ -r "$P2S_WORK/deb-source-records" ]; then
            installed_source=$(awk -F'|' -v n="$name" -v v="$installed" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4]++ {print $4}' "$P2S_WORK/deb-source-records")
        fi
        source=${metadata%%|*}
        if [ -z "$installed_source" ] || [ "$source" != "$installed_source" ]; then
            p2s_fix_block candidate_provider "Installed and proposed source-package identity could not be matched for Sury package $name."
            return 1
        fi
    fi
    if [ "$sury" = true ] && p2s_package_is_engine "$name"; then
        expected=${name#libapache2-mod-}; expected=${expected%%-*}
        source=${metadata%%|*}; source_version=${metadata#*|}
        if [ "$source" != "$expected" ] || [ "$(p2s_version_package_state "$name" "$candidate" '' "$arch" "$source" "$source_version")" != N ]; then
            p2s_fix_block candidate_fix "The Sury candidate for $name has no reviewed fix for both CVEs on this branch, suite and architecture."
            return 1
        fi
        [ "$(p2s_version_upstream_state "$candidate")" != '?' ] || { p2s_fix_block candidate_fix "The Sury candidate's PHP branch could not be identified for $name."; return 1; }
        rest=${installed#*:}; old_branch=${rest%%.*}; rest=${rest#*.}; old_branch="$old_branch.${rest%%.*}"
        rest=${candidate#*:}; branch=${rest%%.*}; rest=${rest#*.}; branch="$branch.${rest%%.*}"
        [ "$old_branch" = "$branch" ] || {
            p2s_fix_block candidate_branch "The candidate for $name changes PHP branches; migration review is required."; return 1;
        }
    fi
    if ${P2S_SURY_MIGRATION_ACTIVE:-false}; then
        case "${name%:*}" in php[0-9].[0-9]-cli|php[0-9].[0-9]-fpm|php[0-9].[0-9]-cgi|php[0-9].[0-9]-phpdbg|libapache2-mod-php[0-9].[0-9])
            # SAPI packages Provide phpapi-20220829 (8.2); -common does not. Retained PECL modules need the same API.
            record=$(p2s_command_run 30 dpkg-query -W '-f=${Provides}\n' "$name" 2> "$P2S_WORK/candidate-query.err") || query_status=$?
            if [ "$query_status" -ne 0 ]; then
                p2s_manifest_record apt_candidate_error "$name|operation=installed_API|exit=$query_status
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-query.err")"
                p2s_fix_block candidate_abi "The installed PHP extension API could not be read for $name."; return 1
            fi
            installed_source=$(printf '%s\n' "$record" | grep -o 'phpapi-[0-9][0-9]*' | sort -u)
            source=$(sed -n '/^Provides:/p' "$P2S_WORK/candidate-metadata" | grep -o 'phpapi-[0-9][0-9]*' | sort -u)
            p2s_manifest_record apt_candidate_api "$name|installed=$installed_source|candidate=$source"
            if [ -z "$installed_source" ] || [ "$installed_source" != "$source" ]; then
                p2s_fix_block candidate_abi "The proposed PHP extension API differs or could not be verified for $name; retained extensions need a migration review."
                return 1
            fi
            branch=${name#libapache2-mod-}; branch=${branch%%-*}
            printf '%s\n' "$branch" >> "$P2S_WORK/migration-api-branches" ;;
        esac
    fi
    P2S_DEB_CANDIDATE=$candidate
    p2s_manifest_record candidate_selection "$name|$installed|$candidate|$arch|sury_only=$sury|normal_APT_candidate|exact_version_required"
}

# Explicit Sury migration methods keep exact binary names, versioned branches and architectures.
# Unversioned selectors and third-party native extensions remain at their installed versions.
p2s_disruptive_sury_validate_equivalents() {
    local name version arch vendor source branch engines=0
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*|debian:12|debian:12.*|debian:13|debian:13.*|ubuntu:22.04|ubuntu:24.04) ;;
        *) p2s_fix_block provider_migration "No equivalent-package Sury migration is implemented for $P2S_DISTRO $P2S_RELEASE. Upgrade or migrate the OS rather than using another release's repository."; return 1 ;;
    esac
    case "${P2S_PANEL:-}" in ''|none) ;;
        cpanel) p2s_fix_block provider_migration "Sury/ondrej packages do not replace cPanel's EasyApache or internal PHP. Update the affected PHP packages through cPanel; this script does not switch them to Sury."; return 1 ;;
        plesk) p2s_fix_block provider_migration "Custom Sury/ondrej PHP on Plesk requires separate PHP handler registration and website settings. This script does not migrate Plesk PHP to Sury/ondrej. Update Plesk-provided PHP through Plesk."; return 1 ;;
        *) p2s_fix_block provider_migration "Switching PHP package sources to Sury is not implemented for this control panel; its package and PHP handler settings need a separate procedure."; return 1 ;;
    esac
    p2s_package_deb_sury_trust_preflight || return 1
    while IFS='|' read -r name version arch vendor; do
        case "${name%:*}" in
            php|php[0-9]|php[0-9].[0-9]|php-common|php-pear|php-cli|php-cgi|php-fpm|php-phpdbg|libapache2-mod-php) continue ;;
            php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9])
                [ "$arch" = amd64 ] || { p2s_fix_block provider_migration "Sury package equivalence is reviewed only for amd64; $name uses $arch."; return 1; }
                source=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4]++ {print $4}' "$P2S_WORK/deb-source-records")
                branch=${name#libapache2-mod-}; branch=${branch%%-*}
                if p2s_package_is_engine "$name"; then engines=$((engines + 1)); fi
                if p2s_package_deb_is_sury "$version"; then continue; fi
                if [ "$source" != "$branch" ]; then
                    if p2s_package_is_engine "$name"; then
                        p2s_fix_block provider_migration "The installed source-package identity could not be verified for PHP engine $name."; return 1
                    fi
                    continue
                fi
                case "$version" in *sury*|*ppa*|*+0~*|*freexian*|*rhphp2shell*)
                    p2s_fix_block provider_migration "Package $name is not a recognised native PHP build; switching to Sury PHP packages needs a separate review."; return 1 ;;
                esac
                case "$P2S_DISTRO:$vendor" in debian:*Debian*|ubuntu:*Ubuntu*) ;;
                    *) p2s_fix_block provider_migration "The distribution package publisher could not be verified for $name."; return 1 ;;
                esac ;;
            *)
                if p2s_package_is_engine "$name"; then
                    p2s_fix_block provider_migration "Package $name has no reviewed same-name Sury equivalent; this method does not rename PHP engines or switch branches."; return 1
                fi ;;
        esac
    done < "$P2S_WORK/packages"
    [ "$engines" -gt 0 ] || { p2s_fix_block provider_migration "No versioned PHP engines with reviewed Sury equivalents were found."; return 1; }
}

# P2S-MUTATION: Removes only this run's opted-in source/key before any PHP installation attempt.
p2s_disruptive_sury_cleanup_added_repository() {
    # Retain an opted-in source after an installation attempt, including a partial failure, for recovery.
    if ${P2S_TRANSACTION_ATTEMPTED:-false}; then return 0; fi
    if ${P2S_SURY_REPOSITORY_CREATED:-false}; then
        rm -f /etc/apt/sources.list.d/dephp2shell-sury-php.list
        p2s_manifest_record repository_change 'Sury|new_source_removed|no_PHP_installation_attempt'
    fi
    if ${P2S_SURY_KEY_CREATED:-false}; then rm -f /etc/apt/keyrings/dephp2shell-sury-php.gpg; fi
}

# Treat disabled Deb822 definitions as present too; creating a duplicate does not repair them.
p2s_repository_sury_source_present() {
    local file
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        [ -r "$file" ] || return 2
        sed 's/[[:space:]]*#.*$//' "$file" > "$P2S_WORK/sury-source-lines" || return 2
        if grep -Eq 'packages[.]sury[.]org/php|ppa[.]launchpad(content)?[.]net/ondrej/php' "$P2S_WORK/sury-source-lines"; then return 0
        elif [ "$?" -ne 1 ]; then return 2
        fi
    done
    return 1
}

# P2S-MUTATION: Only the separately enabled migration may add this dedicated source/key pair.
p2s_disruptive_sury_add_repository() {
    local suite uri key_url fingerprint file observed keyring=/etc/apt/keyrings/dephp2shell-sury-php.gpg
    local source_file=/etc/apt/sources.list.d/dephp2shell-sury-php.list
    if [ "${P2S_MODE:-check}" != fix ] || ! ${P2S_DISRUPTIVE:-false} ||
        ! ${P2S_ALLOW_SURY_MIGRATION:-false} || ! ${P2S_ALLOW_SURY_REPOSITORY:-false}; then
        p2s_fix_block provider_migration "Adding a PHP source requires fix mode and both explicitly enabled Sury migration options."
        return 1
    fi
    case "${P2S_PANEL:-}" in ''|none) ;;
        *) p2s_fix_block provider_migration "Adding Sury/ondrej repositories is disabled for $P2S_PANEL-managed PHP. Use the panel's PHP update procedure."; return 1 ;;
    esac
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*) suite=bullseye ;; debian:12|debian:12.*) suite=bookworm ;; debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        *) p2s_fix_block provider_migration "No matching Sury repository is reviewed for this OS release."; return 1 ;;
    esac
    if [ "$P2S_DISTRO" = debian ]; then
        uri=https://packages.sury.org/php
        key_url=https://packages.sury.org/php/apt.gpg
        fingerprint=15058500A0235D97F5D10063B188E2B695BD4743
    else
        uri=https://ppa.launchpadcontent.net/ondrej/php/ubuntu
        fingerprint=B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6
        key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$fingerprint"
    fi
    # Do not create duplicate entries when the matching source is already configured.
    if ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/source-origins" 2>/dev/null; then
        p2s_fix_block source_authentication "Existing APT sources could not be checked before adding a PHP source."; return 1
    fi
    if awk -v uri="$uri" -v suite="$suite/main" '$2==uri && $3==suite && $4=="amd64" && $5=="Packages" {found=1} END {exit !found}' "$P2S_WORK/source-origins"; then
        p2s_manifest_record repository_change 'Sury|matching_source_already_available|no_source_added'
        return 0
    fi
    if p2s_repository_sury_source_present; then
        p2s_manifest_record repository_change 'Sury|existing_source_definition_retained|no_source_added|fresh_APT_validation_required'
        return 0
    elif [ "$?" -ne 1 ]; then
        p2s_fix_block source_authentication 'Existing source definitions could not be inspected; no duplicate PHP source was added.'; return 1
    fi
    for file in "$keyring" "$source_file"; do
        if [ -e "$file" ] || [ -L "$file" ]; then
            p2s_fix_block source_authentication "The dedicated DePHP2Shell source or key file already exists but its repository is unavailable. Review it before retrying; no file was overwritten."; return 1
        fi
    done
    if ! p2s_command_exists gpg; then
        p2s_fix_block source_authentication "Adding the Sury source requires an existing gpg command to verify its public key; no verification tool was installed."; return 1
    fi
    p2s_message_print warn "Explicit source change requested: add the official $suite PHP source and migrate only equivalent installed PHP packages. The source remains configured after a package installation attempt, even if that attempt fails. This does not restore support for the operating system."
    if p2s_command_exists curl; then
        if ! p2s_command_run 90 curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 60 --output "$P2S_WORK/sury.key" "$key_url" > "$P2S_WORK/key-download.log" 2>&1; then
            p2s_fix_block source_authentication "The Sury signing key could not be downloaded over verified HTTPS."; return 1
        fi
    elif p2s_command_exists wget; then
        if ! p2s_command_run 90 wget --timeout=20 --tries=1 --max-redirect=0 -O "$P2S_WORK/sury.key" "$key_url" > "$P2S_WORK/key-download.log" 2>&1; then
            p2s_fix_block source_authentication "The Sury signing key could not be downloaded over verified HTTPS without a redirect."; return 1
        fi
    else
        p2s_fix_block source_authentication "Adding the Sury source requires an existing curl or wget command; no download tool was installed."; return 1
    fi
    mkdir "$P2S_WORK/key-inspection" || return 1
    if ! p2s_command_run 30 gpg --no-options --homedir "$P2S_WORK/key-inspection" --batch --with-colons --show-keys "$P2S_WORK/sury.key" > "$P2S_WORK/key-details" 2>/dev/null; then
        p2s_fix_block source_authentication "The downloaded PHP repository key could not be inspected."; return 1
    fi
    # pub/fpr/sub/fpr: compare PRIMARY fingerprints only; unreviewed extra primary keys are refused.
    observed=$(awk -F: '$1=="pub" {primary=1} $1=="sub" {primary=0} $1=="fpr" && primary {print $10; primary=0}' "$P2S_WORK/key-details")
    if [ "$observed" != "$fingerprint" ]; then
        p2s_fix_block source_authentication "The PHP repository signing key does not match the reviewed fingerprint; no source was added."; return 1
    fi
    if ! p2s_command_run 30 gpg --no-options --homedir "$P2S_WORK/key-inspection" --batch --dearmor < "$P2S_WORK/sury.key" > "$P2S_WORK/sury.gpg" 2>/dev/null; then
        p2s_fix_block source_authentication "The verified PHP signing key could not be prepared for APT."; return 1
    fi
    # --dearmor also accepts a binary keyring. Dedicated Signed-By never expands global APT trust.
    if ! (umask 022; mkdir -p /etc/apt/keyrings /etc/apt/sources.list.d); then return 1; fi
    if ! (umask 022; set -C; : > "$keyring"); then
        p2s_fix_block source_authentication "The dedicated PHP key file could not be created without replacing another file."; return 1
    fi
    P2S_SURY_KEY_CREATED=true
    if ! cat "$P2S_WORK/sury.gpg" > "$keyring"; then
        p2s_fix_block source_authentication "The dedicated PHP key file could not be written; the new file will be removed."; return 1
    fi
    if ! (umask 022; set -C; : > "$source_file"); then
        p2s_fix_block source_authentication "The dedicated PHP source file could not be created without replacing another file."; return 1
    fi
    P2S_SURY_REPOSITORY_CREATED=true
    if ! printf 'deb [arch=amd64 signed-by=%s] %s %s main\n' "$keyring" "$uri" "$suite" > "$source_file"; then
        p2s_fix_block source_authentication "The dedicated PHP source file could not be written; the new source and key will be removed."; return 1
    fi
    p2s_manifest_record repository_change "Sury|added|suite=$suite|architecture=amd64|Signed-By=$keyring|primary_fingerprint=$fingerprint"
}

p2s_package_deb_audit_context_collect() {
    local name version arch status base list checksum query_status=0
    : > "$P2S_WORK/audit-selected"
    if ! p2s_command_exists dpkg-query; then
        p2s_manifest_record package_audit_gap 'dpkg-query unavailable|package states not collected'
        return 0
    fi
    # dpkg --audit: " libdb4.2  Berkeley ..." -> libdb4.2; headers are not package names.
    if ! awk '/^[ \t]+[a-z0-9][a-z0-9+.:_-]*[ \t]/ {print $1}' "$P2S_WORK/audit" > "$P2S_WORK/audit-names.raw" ||
        ! sort -u "$P2S_WORK/audit-names.raw" > "$P2S_WORK/audit-names"; then
        p2s_manifest_record package_audit_gap 'audit package names could not be collected'; return 0
    fi
    p2s_command_run 30 dpkg-query -W '-f=${Package}|${Version}|${Architecture}|${Status}\n' > "$P2S_WORK/audit-status" 2> "$P2S_WORK/audit-status.err" || query_status=$?
    if [ "$query_status" -ne 0 ]; then
        p2s_manifest_record package_audit_gap "status_query_exit=$query_status
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/audit-status.err")"
        return 0
    fi
    # Package|version|arch|install ok unpacked -> pending; also include audited fully installed packages.
    if ! awk -F'|' '
        FILENAME==ARGV[1] {named[$1]=1; next}
        NF!=4 {bad=1; next}
        {
            base=$1; sub(/:.*/,"",base); split($4,state," ")
            if (named[$1] || named[base] || state[2]!="ok" ||
                (state[3]!="installed" && state[3]!="not-installed" && state[3]!="config-files")) print
        }
        END {exit bad}' "$P2S_WORK/audit-names" "$P2S_WORK/audit-status" > "$P2S_WORK/audit-selected"; then
        p2s_manifest_record package_audit_gap 'package status output could not be fully parsed'
        : > "$P2S_WORK/audit-selected"; return 0
    fi
    while IFS='|' read -r name version arch status; do
        case "$name" in ''|*[!a-zA-Z0-9.+:_-]*) continue ;; esac
        case "$arch" in ''|*[!a-zA-Z0-9_-]*) continue ;; esac
        p2s_manifest_record package_audit_status "$name|$version|$arch|$status"
        base=${name%:*}; list=missing_or_unreadable; checksum=missing_or_unreadable
        if [ -r "/var/lib/dpkg/info/$base.list" ] || [ -r "/var/lib/dpkg/info/$base:$arch.list" ]; then list=readable; fi
        if [ -r "/var/lib/dpkg/info/$base.md5sums" ] || [ -r "/var/lib/dpkg/info/$base:$arch.md5sums" ]; then checksum=readable; fi
        p2s_manifest_record package_audit_metadata "$name|list=$list|md5sums=$checksum"
    done < "$P2S_WORK/audit-selected"
    p2s_manifest_record package_audit_scope 'audit_named_and_nonconfigured_packages|read_only|no_repair_attempt'
}

# Check current source text as well as cached metadata: the cache can predate an edited source.
p2s_repository_native_suites_verified() {
    awk -v suite="$2" -v distro="$3" '
        function native_uri(uri) {
            return (distro=="debian" && uri ~ /^https?:\/\/(deb[.]debian[.]org|ftp[.]debian[.]org|security[.]debian[.]org)\/(debian|debian-security)\/?$/) ||
                   (distro=="ubuntu" && uri ~ /^https?:\/\/(archive[.]ubuntu[.]com|security[.]ubuntu[.]com)\/ubuntu\/?$/)
        }
        function valid_suites(value, n,a,i,seen) {
            n=split(value,a,/[ \t]+/); if(value=="") return 0
            for(i=1;i<=n;i++) if(a[i]!="") {seen=1; if(a[i]!=suite && a[i]!=suite "-security" && a[i]!=suite "-updates" && a[i]!=suite "-backports") return 0}
            return seen
        }
        function stanza_check(n,a,i,has_native) {
            n=split(uris,a,/[ \t]+/); has_native=0
            for(i=1;i<=n;i++) if(native_uri(a[i])) has_native=1
            if(has_native && !valid_suites(suites)) bad=1
            uris=""; suites=""; key=""
        }
        {
            sub(/[ \t]*#.*/,""); sub(/\r$/,"")
            if($0 ~ /^[ \t]*$/) {stanza_check(); next}
            line=$0; sub(/^[ \t]*/,"",line)
            if(line ~ /^deb(-src)?[ \t]/) {
                sub(/^deb(-src)?[ \t]+/,"",line); sub(/^\[[^]]*\][ \t]*/,"",line)
                split(line,entry,/[ \t]+/); if(native_uri(entry[1]) && !valid_suites(entry[2])) bad=1
                next
            }
            if($0 !~ /^[ \t]/ && line ~ /^[A-Za-z-]+:/) {
                key=tolower(line); sub(/:.*/,"",key); sub(/^[^:]*:[ \t]*/,"",line)
            } else if($0 !~ /^[ \t]/) key=""
            if(key=="uris") uris=uris " " line
            if(key=="suites") suites=suites " " line
        }
        END {stanza_check(); exit bad}' "$1"
}

# Emit classifications and suite labels, never repository URLs or inline signing keys.
p2s_repository_source_layouts_output() {
    local file=$1 suite=''
    case "${P2S_DISTRO:-}:${P2S_RELEASE:-}" in
        debian:9|debian:9.*) suite=stretch ;; debian:10|debian:10.*) suite=buster ;;
        debian:11|debian:11.*) suite=bullseye ;; debian:12|debian:12.*) suite=bookworm ;;
        debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
    esac
    # deb [signed-by=/key] URI suite main; Deb822 fields can continue on indented lines.
    # extrepo_sury.sources + /var/lib/extrepo/keys/sury.asc identify the managed PHP source.
    LC_ALL=C awk -v file="$file" -v suite="$suite" -v distro="${P2S_DISTRO:-}" -v active_arch="${2:-}" \
        -v standard_key=/usr/share/keyrings/debsuryorg-archive-keyring.gpg \
        -v extrepo_key=/var/lib/extrepo/keys/sury.asc '
        function trim(value) {gsub(/^[ \t]+|[ \t]+$/,"",value); return value}
        function contains(value,item) {gsub(/[, \t]+/," ",value); return index(" " trim(value) " "," " item " ")>0}
        function emit(n,a,i,uri,host,path,layout,matching,provider,family,reported_suites) {
            if(types !~ /(^|[ \t])(deb|deb-src|rpm)([ \t]|$)/) return
            n=split(uris,a,/[ \t]+/)
            for(i=1;i<=n;i++) {
                uri=a[i]; if(uri !~ /^https?:\/\//) continue
                host=uri; sub(/^https?:\/\//,"",host); sub(/[\/?#].*$/,"",host); sub(/^.*@/,"",host)
                path=uri; sub(/^https?:\/\/[^\/]+/,"",path); sub(/[?#].*$/,"",path)
                if(active_arch!="") {
                    if(enabled=="yes" && contains(types,"deb") && suite!="" && contains(suites,suite) &&
                       (active_arch=="all" || ((architectures=="" || contains(architectures,active_arch) || contains(added_architectures,active_arch)) && !contains(excluded_architectures,active_arch))) &&
                       ((distro=="debian" && host=="packages.sury.org" && path ~ /^\/php\/?$/) ||
                        (distro=="ubuntu" && host ~ /^ppa[.]launchpad(content)?[.]net$/ && path ~ /^\/ondrej\/php\/ubuntu\/?$/))) print "active"
                    continue
                }
                provider=""; family=""
                if(host=="packages.sury.org" && path ~ /^\/php\/?$/ && types!="rpm") {
                    provider="sury"; family="Debian"
                    layout="standard"
                    if(file ~ /\/extrepo_sury[.]sources$/ || signing==extrepo_key) {
                        layout="extrepo"
                        if(signing!=extrepo_key || uri !~ /^https:\/\//) layout="extrepo_custom"
                    } else if(signing!=standard_key || uri !~ /^https:\/\//) layout="legacy_or_custom"
                } else if(host ~ /^ppa[.]launchpad(content)?[.]net$/ && path ~ /^\/ondrej\/php\/ubuntu\/?$/ && types!="rpm") {
                    provider="ondrej"; family="Ubuntu"; layout="ppa"
                }
                if(provider!="") {
                    matching="unreviewed"
                    if(suite!="") {matching="different"; if(trim(suites)==suite) matching="matching"}
                    if((distro=="debian" && family!="Debian") || (distro=="ubuntu" && family!="Ubuntu")) matching="different"
                    reported_suites=trim(suites); gsub(/[ \t]+/," ",reported_suites)
                    if(reported_suites !~ /^[a-zA-Z0-9_.+~\/-]+( [a-zA-Z0-9_.+~\/-]+)*$/) reported_suites="unrecognised"
                    print provider "|" layout "|" enabled "|" matching "|" family "|" reported_suites "|" suite
                } else if(host=="software.virtualmin.com") print "virtualmin|legacy|" enabled "|unreviewed"
                else if(host=="download.virtualmin.com") print "virtualmin|current|" enabled "|unreviewed"
            }
        }
        function reset() {types=""; uris=""; suites=""; signing=""; enabled="yes"; key=""; architectures=""; added_architectures=""; excluded_architectures=""}
        BEGIN {apt=(file ~ /[.](list|sources)$/); reset()}
        {
            if($0 ~ /^[ \t]*#/) next
            sub(/\r$/,""); sub(/[ \t]*#.*/,"")
            if($0 ~ /^[ \t]*$/) {if(apt) {emit(); reset()}; next}
            line=trim($0)
            if(line ~ /^deb(-src)?[ \t]+/) {
                emit(); reset(); types=line; sub(/[ \t].*$/,"",types)
                sub(/^deb(-src)?[ \t]+/,"",line)
                if(line ~ /^\[/) {
                    end=index(line,"]"); if(!end) next
                    options=substr(line,2,end-2); line=trim(substr(line,end+1))
                    count=split(options,option,/[ \t]+/)
                    for(j=1;j<=count;j++) {
                        if(option[j] ~ /^signed-by=/) signing=substr(option[j],11)
                        if(option[j] ~ /^arch=/) architectures=substr(option[j],6)
                        if(option[j] ~ /^arch\+=/) added_architectures=substr(option[j],7)
                        if(option[j] ~ /^arch-=/) excluded_architectures=substr(option[j],7)
                    }
                }
                split(line,entry,/[ \t]+/); uris=entry[1]; suites=entry[2]
                emit(); reset(); next
            }
            if(file ~ /[.]sources$/) {
                if($0 !~ /^[ \t]/ && line ~ /^[A-Za-z-]+:/) {key=tolower(line); sub(/:.*/,"",key); sub(/^[^:]*:[ \t]*/,"",line)}
                else if($0 !~ /^[ \t]/) key=""
                if(key=="types") types=types " " line
                if(key=="uris") uris=uris " " line
                if(key=="suites") suites=suites " " line
                if(key=="signed-by") signing=trim(signing " " line)
                if(key=="enabled") enabled=(tolower(line)=="no" ? "no" : tolower(line)=="yes" ? "yes" : "unknown")
                if(key=="architectures") architectures=architectures " " line
                if(key=="architectures-add") added_architectures=added_architectures " " line
                if(key=="architectures-remove") excluded_architectures=excluded_architectures " " line
            } else if(file !~ /[.]list$/ && file !~ /\/sources[.]list$/) {
                if(line ~ /^\[/) {emit(); reset(); next}
                if(line ~ /^baseurl[ \t]*=/) {sub(/^[^=]*=[ \t]*/,"",line); types="rpm"; uris=line}
                if(line ~ /^enabled[ \t]*=/) {sub(/^[^=]*=[ \t]*/,"",line); enabled=(line=="0" ? "no" : line=="1" ? "yes" : "unknown")}
            }
        }
        END {emit()}' "$file"
}

p2s_repository_sury_installed_source_report() {
    local name version arch vendor provider file active inspected advice
    [ "${P2S_BACKEND:-}" = deb ] || return 0
    while IFS='|' read -r name version arch vendor; do
        provider=$(p2s_package_provider "$name" "$vendor" "$version")
        case "$provider" in Sury/*) ;; *) continue ;; esac
        # Read current definitions: cached APT indexes can survive a source being disabled.
        active=false; inspected=true
        for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
            [ -f "$file" ] || continue
            if [ ! -r "$file" ] || ! p2s_repository_source_layouts_output "$file" "$arch" > "$P2S_WORK/sury-active-source"; then
                inspected=false; continue
            fi
            if [ -s "$P2S_WORK/sury-active-source" ]; then active=true; break; fi
        done
        if ! $active; then
            if $inspected; then
                case "${P2S_PANEL:-}" in
                    ''|none) advice='Automatic Sury/ondrej updates need an active matching source. Review missing, commented-out or disabled sources and their release and architecture settings.' ;;
                    *) advice="This server also uses $P2S_PANEL-managed PHP. Review the mixed package sources with the panel administrator before enabling a repository; Sury packages do not replace the panel's own PHP packages." ;;
                esac
                p2s_message_print warn "Sury/ondrej PHP packages are installed, but no active matching Sury/ondrej source was recognised in /etc/apt/sources.list or /etc/apt/sources.list.d (OS release $P2S_RELEASE; architecture $arch). $advice"
                p2s_manifest_record repository_guidance "Sury|installed_packages_without_matching_active_source|architecture=$arch"
            else
                p2s_manifest_record source_gap 'Sury|active_source_check_incomplete|unreadable_or_unparsed_source'
            fi
            return 0
        fi
    done < "$P2S_WORK/packages"
}

p2s_repository_maintenance_report() {
    local file=$1 provider layout enabled matching family suites expected advice
    if ! p2s_repository_source_layouts_output "$file" > "$P2S_WORK/repository-layouts"; then
        p2s_manifest_record source_gap "$file|repository_layout_assessment_failed"; return 0
    fi
    while IFS='|' read -r provider layout enabled matching family suites expected; do
        p2s_manifest_record repository_layout "$file|$provider|$layout|enabled=$enabled|suite=$matching"
        if [ "$enabled" != yes ]; then
            p2s_manifest_record repository_guidance "$file|$provider|inactive_or_unknown_state|review_intended_state_before_repair_or_activation"
            continue
        fi
        case "$provider:$matching" in sury:different|ondrej:different)
            case "$P2S_DISTRO" in
                ubuntu) advice="Ubuntu PHP packages use the ondrej/php PPA for ${expected:-the installed Ubuntu release}." ;;
                debian) advice="Debian PHP packages use packages.sury.org/php for ${expected:-the installed Debian release}." ;;
                *) advice='Check the PHP publisher support for this distribution and release.' ;;
            esac
            p2s_message_print warn "PHP repository mismatch in $file: the source supplies $family packages for suite '$suites', but this server runs $P2S_DISTRO $P2S_RELEASE. $advice Review the installed PHP packages before replacing the source; a repository change alone does not replace packages already installed."
            p2s_manifest_record repository_guidance "$file|$provider|different_suite|manual_review=match_installed_OS_and_provider_support|configured=$family $suites|host=$P2S_DISTRO $P2S_RELEASE|expected_suite=$expected|not_executed"
            continue ;;
        esac
        case "$provider:$layout" in
            sury:extrepo*)
                p2s_message_print info "Sury PHP source in $file uses an extrepo-managed layout. If repository repair is needed, review 'extrepo update sury' and reconcile duplicate definitions first. Do not use --refresh-sury-signing-key for this layout."
                p2s_manifest_record repository_guidance "$file|sury|extrepo_managed|manual_review=extrepo update sury|not_executed" ;;
            sury:legacy_or_custom)
                p2s_message_print warn "Legacy or custom Sury PHP source in $file. Review https://packages.sury.org/php/README.txt for the supported OS suite and debsuryorg-archive-keyring package. Correct the existing definition after review instead of adding a duplicate; retain signature verification."
                p2s_manifest_record repository_guidance "$file|sury|legacy_or_custom|manual_review=vendor_source_and_packaged_keyring|not_executed" ;;
            virtualmin:legacy)
                p2s_message_print warn "Legacy Virtualmin repository in $file; it may be intentional. If updates fail, review 'virtualmin configure-repos' ('virtualmin setup-repos' on older versions) and https://www.virtualmin.com/docs/installation/troubleshooting-repositories/ . Switching to the production repository can change Webmin module packaging."
                p2s_manifest_record repository_guidance "$file|virtualmin|legacy|manual_review=virtualmin configure-repos|not_executed" ;;
        esac
    done < "$P2S_WORK/repository-layouts"
}

# Return eligibility without downloading, changing source files or running package operations.
# P2S_REPOSITORY_REPAIR_REASON describes a failed assessment for human recommendations.
p2s_repository_repair_assess() {
    local recipe=$1 file line ownership native_uri native_origin suite security keyring source_seen=false
    P2S_REPOSITORY_REPAIR_REASON=''
    P2S_REPOSITORY_REPAIR_STATE=needed
    P2S_REPOSITORY_REPAIR_SUITE=''
    case "$P2S_BACKEND:$P2S_DISTRO:$P2S_RELEASE" in
        deb:debian:11|deb:debian:11.*) suite=bullseye ;; deb:debian:12|deb:debian:12.*) suite=bookworm ;;
        deb:debian:13|deb:debian:13.*) suite=trixie ;;
        deb:ubuntu:22.04) suite=jammy ;; deb:ubuntu:24.04) suite=noble ;;
        *) P2S_REPOSITORY_REPAIR_REASON='No repository repair recipe is reviewed for this OS release.'; return 1 ;;
    esac
    P2S_REPOSITORY_REPAIR_SUITE=$suite
    case "$recipe" in
        sury-key)
            case "${P2S_PANEL:-}" in ''|none) ;;
                *) P2S_REPOSITORY_REPAIR_REASON="Sury key repair is disabled for $P2S_PANEL-managed PHP; review its package sources through the panel's update procedure."; return 1 ;;
            esac
            [ "$P2S_DISTRO" = debian ] || { P2S_REPOSITORY_REPAIR_REASON='The Sury key recipe applies only to the standard Debian Sury source.'; return 1; }
            keyring=/usr/share/keyrings/debsuryorg-archive-keyring.gpg
            for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
                [ -f "$file" ] || continue
                [ -r "$file" ] || { P2S_REPOSITORY_REPAIR_REASON='An APT source file is unreadable.'; return 1; }
                if ! p2s_repository_source_layouts_output "$file" > "$P2S_WORK/repair-source-layouts"; then
                    P2S_REPOSITORY_REPAIR_REASON='The Sury source layout could not be assessed.'; return 1
                fi
                if grep -Eq '^sury[|]extrepo' "$P2S_WORK/repair-source-layouts"; then
                    P2S_REPOSITORY_REPAIR_REASON="The Sury source uses an extrepo-managed layout. Review its enabled state and 'extrepo update sury'; the package-owned keyring repair does not apply."
                    return 1
                fi
                sed 's/[[:space:]]*#.*$//; /^[[:space:]]*$/d' "$file" > "$P2S_WORK/repair-source-lines" || return 1
                while IFS= read -r line; do
                    case "$line" in *packages.sury.org*)
                        if [ "$line" != "deb [signed-by=$keyring] https://packages.sury.org/php/ $suite main" ] &&
                            [ "$line" != "deb [signed-by=$keyring] https://packages.sury.org/php $suite main" ]; then
                            P2S_REPOSITORY_REPAIR_REASON='The Sury source differs from its reviewed package-keyring configuration.'; return 1
                        fi
                        source_seen=true ;;
                    esac
                done < "$P2S_WORK/repair-source-lines"
            done
            $source_seen || { P2S_REPOSITORY_REPAIR_REASON='No standard matching Sury source was found.'; return 1; }
            [ -f "$keyring" ] && [ ! -L "$keyring" ] || { P2S_REPOSITORY_REPAIR_REASON='The standard Sury package keyring is absent or is a symlink.'; return 1; }
            ownership=$(p2s_command_run 30 dpkg-query -S "$keyring" 2>/dev/null) || { P2S_REPOSITORY_REPAIR_REASON='The archive keyring package owner could not be queried.'; return 1; }
            [ "$ownership" = "debsuryorg-archive-keyring: $keyring" ] || { P2S_REPOSITORY_REPAIR_REASON='The Sury keyring package owner is not verified.'; return 1; }
            ;;
        native-security-source)
            security=$suite-security
            case "$P2S_DISTRO" in
                debian) native_uri=https://security.debian.org/debian-security; native_origin=Debian; keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
                ubuntu) native_uri=https://security.ubuntu.com/ubuntu; native_origin=Ubuntu; keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
            esac
            [ -r "$keyring" ] && [ ! -L "$keyring" ] || { P2S_REPOSITORY_REPAIR_REASON='The installed native archive keyring is unavailable.'; return 1; }
            ownership=$(p2s_command_run 30 dpkg-query -S "$keyring" 2>/dev/null) || { P2S_REPOSITORY_REPAIR_REASON='The archive keyring package owner could not be queried.'; return 1; }
            case "$P2S_DISTRO:$ownership" in
                "debian:debian-archive-keyring: $keyring"|"ubuntu:ubuntu-keyring: $keyring") ;;
                *) P2S_REPOSITORY_REPAIR_REASON='The native archive keyring package owner is not verified.'; return 1 ;;
            esac
            if [ -e /etc/apt/sources.list.d/dephp2shell-native-security.list ] || [ -L /etc/apt/sources.list.d/dephp2shell-native-security.list ]; then
                printf 'deb [signed-by=%s] %s %s-security main\n' "$keyring" "$native_uri" "$suite" > "$P2S_WORK/repair-expected-source" || return 1
                if [ ! -f /etc/apt/sources.list.d/dephp2shell-native-security.list ] || [ -L /etc/apt/sources.list.d/dephp2shell-native-security.list ] ||
                    ! cmp -s "$P2S_WORK/repair-expected-source" /etc/apt/sources.list.d/dephp2shell-native-security.list; then
                    P2S_REPOSITORY_REPAIR_REASON='The dedicated security source differs from its exact reviewed definition; no file will be overwritten.'; return 1
                fi
                P2S_REPOSITORY_REPAIR_STATE=already_available
            fi
            for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
                [ -f "$file" ] || continue
                [ -r "$file" ] || { P2S_REPOSITORY_REPAIR_REASON='An APT source file is unreadable.'; return 1; }
                if ! p2s_repository_native_suites_verified "$file" "$suite" "$P2S_DISTRO"; then
                    P2S_REPOSITORY_REPAIR_REASON='An existing native source defines a foreign or unreviewed OS suite.'; return 1
                fi
                [ "$file" != /etc/apt/sources.list.d/dephp2shell-native-security.list ] || continue
                # Disabled Deb822 stanzas also prevent duplication: activation needs a separate review.
                if sed 's/[[:space:]]*#.*$//' "$file" | grep -Eq "(^|[[:space:]])${security}([[:space:]]|$)"; then
                    P2S_REPOSITORY_REPAIR_REASON='A matching security suite is already defined; repair its existing access or configuration instead.'; return 1
                fi
            done
            if ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/repair-native-policy" 2>/dev/null; then
                P2S_REPOSITORY_REPAIR_REASON='Native APT policy could not be inspected.'; return 1
            fi
            # No source is introduced unless cached native main metadata proves the current suite.
            if ! awk -v origin="$native_origin" -v suite="$suite" '
                /Packages$/ {uri=$2}
                /release / {o=""; n=""; c=""; count=split($0,a,","); for(i=1;i<=count;i++) {sub(/^.*release /,"",a[i]); gsub(/^[ \t]+/,"",a[i]); if(a[i] ~ /^o=/) o=substr(a[i],3); if(a[i] ~ /^n=/) n=substr(a[i],3); if(a[i] ~ /^c=/) c=substr(a[i],3)}
                    if(o==origin && n==suite && c=="main" &&
                        ((origin=="Debian" && uri ~ /^https?:\/\/(deb[.]debian[.]org\/debian|ftp[.]debian[.]org\/debian)\/?$/) ||
                         (origin=="Ubuntu" && uri ~ /^https?:\/\/(archive[.]ubuntu[.]com\/ubuntu)\/?$/))) found=1
                    if(o==origin && n!=suite && n!=suite "-updates" && n!=suite "-security" && n!=suite "-backports") bad=1
                } END {exit !found || bad}' "$P2S_WORK/repair-native-policy"; then
                P2S_REPOSITORY_REPAIR_REASON='A matching native main source was not verified, or mixed native OS suites are configured.'; return 1
            fi
            P2S_REPOSITORY_REPAIR_URI=$native_uri
            P2S_REPOSITORY_REPAIR_KEYRING=$keyring
            ;;
        *) P2S_REPOSITORY_REPAIR_REASON='Unknown repository repair recipe.'; return 1 ;;
    esac
    return 0
}

# Only a stale, expired or mismatched installed key justifies recommending key replacement.
p2s_repository_sury_key_needs_refresh() {
    local observed expired now
    p2s_command_exists gpg || return 2
    mkdir -p "$P2S_WORK/key-assessment" || return 2
    if ! p2s_command_run 30 gpg --no-options --homedir "$P2S_WORK/key-assessment" --batch --with-colons --show-keys /usr/share/keyrings/debsuryorg-archive-keyring.gpg > "$P2S_WORK/key-assessment/details" 2> "$P2S_WORK/key-assessment/error"; then
        p2s_manifest_record repository_key_gap 'sury-key|installed_key_could_not_be_inspected'
        return 2
    fi
    now=$(date -u '+%s') || return 2
    observed=$(awk -F: '$1=="pub" {primary=1} $1=="sub" {primary=0} $1=="fpr" && primary {print $10; primary=0}' "$P2S_WORK/key-assessment/details")
    [ -n "$observed" ] || return 2
    expired=$(awk -F: -v now="$now" '$1=="pub" && ($2=="e" || ($7 ~ /^[0-9]+$/ && $7+0>0 && $7+0<=now)) {expired=1} END {print expired+0}' "$P2S_WORK/key-assessment/details")
    p2s_manifest_record repository_key_assessment "sury-key|primary=$observed|expired=$expired|installed_key_only"
    [ "$expired" -eq 1 ] || [ "$observed" != 15058500A0235D97F5D10063B188E2B695BD4743 ]
}

# P2S-MUTATION: Repairs only the explicitly selected standard repository definition or key.
p2s_disruptive_repository_apply_recipe() {
    local recipe=${P2S_REPOSITORY_REPAIR:-none} keyring temp backup observed key_dir
    [ "$recipe" != none ] || return 0
    if [ "${P2S_MODE:-check}" != fix ] || ! ${P2S_DISRUPTIVE:-false}; then
        p2s_fix_block repository_repair 'Repository repair requires fix mode and --enable-extra-fixes.'; return 1
    fi
    if ! p2s_repository_repair_assess "$recipe"; then
        p2s_fix_block repository_repair "$P2S_REPOSITORY_REPAIR_REASON"; return 1
    fi
    p2s_package_deb_sury_trust_preflight || return 1
    case "$recipe" in
        native-security-source)
            if [ "$P2S_REPOSITORY_REPAIR_STATE" = already_available ]; then
                p2s_manifest_record repository_change "native-security-source|unchanged|already_available|suite=$P2S_REPOSITORY_REPAIR_SUITE-security"
                return 0
            fi
            temp=$(mktemp /etc/apt/sources.list.d/.dephp2shell-security.XXXXXX) || return 1
            if ! printf 'deb [signed-by=%s] %s %s-security main\n' "$P2S_REPOSITORY_REPAIR_KEYRING" "$P2S_REPOSITORY_REPAIR_URI" "$P2S_REPOSITORY_REPAIR_SUITE" > "$temp" || ! chmod 644 "$temp"; then
                rm -f "$temp"; return 1
            fi
            # Hard-link publication is atomic and cannot replace a file created since assessment.
            if ! ln -T "$temp" /etc/apt/sources.list.d/dephp2shell-native-security.list; then rm -f "$temp"; return 1; fi
            rm -f "$temp"
            p2s_manifest_record repository_change "native-security-source|added|suite=$P2S_REPOSITORY_REPAIR_SUITE-security|main_only|existing_archive_keyring"
            ;;
        sury-key)
            p2s_command_exists gpg || { p2s_fix_block repository_repair 'The Sury key repair requires an existing gpg command.'; return 1; }
            key_dir=$(mktemp -d "$P2S_WORK/repair-key.XXXXXX") || return 1
            if p2s_command_exists curl; then
                p2s_command_run 90 curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 60 --output "$key_dir/key" https://packages.sury.org/php/apt.gpg > "$key_dir/download.log" 2>&1 || return 1
            elif p2s_command_exists wget; then
                p2s_command_run 90 wget --timeout=20 --tries=1 --max-redirect=0 -O "$key_dir/key" https://packages.sury.org/php/apt.gpg > "$key_dir/download.log" 2>&1 || return 1
            else p2s_fix_block repository_repair 'The Sury key repair requires an existing curl or wget command.'; return 1; fi
            p2s_command_run 30 gpg --no-options --homedir "$key_dir" --batch --with-colons --show-keys "$key_dir/key" > "$key_dir/details" 2>/dev/null || return 1
            observed=$(awk -F: '$1=="pub" {primary=1} $1=="sub" {primary=0} $1=="fpr" && primary {print $10; primary=0}' "$key_dir/details")
            if [ "$observed" != 15058500A0235D97F5D10063B188E2B695BD4743 ]; then
                p2s_fix_block repository_repair 'The downloaded Sury key does not match its reviewed primary fingerprint.'; return 1
            fi
            keyring=/usr/share/keyrings/debsuryorg-archive-keyring.gpg
            temp=$(mktemp /usr/share/keyrings/.dephp2shell-sury.XXXXXX) || return 1
            if ! p2s_command_run 30 gpg --no-options --homedir "$key_dir" --batch --dearmor < "$key_dir/key" > "$temp" 2>/dev/null || ! chmod 644 "$temp"; then rm -f "$temp"; return 1; fi
            backup=$(mktemp /usr/share/keyrings/dephp2shell-sury-backup.XXXXXX) || { rm -f "$temp"; return 1; }
            if ! cp -p "$keyring" "$backup" || ! mv -fT "$temp" "$keyring"; then rm -f "$temp"; return 1; fi
            # The persistent backup survives later refresh/install failures; no customer sources changed.
            p2s_manifest_record repository_change "sury-key|replaced_standard_package_keyring|backup=$backup|primary_fingerprint=$observed"
            ;;
    esac
}


# Package repair assessment is read-only; unrelated audits never become permission to repair.
p2s_package_deb_repair_assess() {
    local name version arch status base source vendor row reason='' pending=false reinstall=false
    P2S_PENDING_PHP_REPAIR_ELIGIBLE=false; P2S_EXACT_PHP_REPAIR_ELIGIBLE=false
    : > "$P2S_WORK/repair-pending"; : > "$P2S_WORK/repair-reinstall"
    if [ "${P2S_BACKEND:-}" != deb ] || [ -n "${P2S_PANEL:-}" ]; then reason=unsupported_backend_or_panel
    elif [ ! -s "$P2S_WORK/audit-status" ] || [ ! -s "$P2S_WORK/audit-selected" ]; then reason=no_verified_audit_targets
    elif [ "${P2S_PACKAGE_AUDIT_EXIT_STATUS:-0}" -ne 0 ] || [ -s "$P2S_WORK/audit.err" ]; then reason=audit_query_failed
    elif [ -s "$P2S_WORK/audit-status.err" ]; then reason=status_query_failed
    elif ! awk -F'|' '
        NF!=4 || $1=="" || $2=="" || $3=="" ||
            $4 !~ /^(install|hold|deinstall|purge|unknown) (ok|reinstreq) (not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed)$/ {bad=1}
        END {exit bad}' "$P2S_WORK/audit-status"; then reason=unparseable_package_status
    elif ! awk -F'|' '
        NR==FNR {selected[$1 "|" $2 "|" $3 "|" $4]=1; next}
        {split($4,state," ")}
        state[2]!="ok" || (state[3]!="installed" && state[3]!="not-installed" && state[3]!="config-files") {
            if (!(($1 "|" $2 "|" $3 "|" $4) in selected)) bad=1
        }
        END {exit bad}' "$P2S_WORK/audit-selected" "$P2S_WORK/audit-status"; then reason=incomplete_pending_package_scope
    fi
    if [ -z "$reason" ]; then
        while IFS='|' read -r name version arch status; do
            base=${name%:*}
            case "$base" in php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9]) ;; *) reason=unreviewed_or_unrelated_package; break ;; esac
            case "$name:$version:$arch" in *[!a-zA-Z0-9.+:~_-]*) reason=invalid_package_identity; break ;; esac
            if [ -z "$name" ] || [ -z "$version" ] || [ -z "$arch" ]; then reason=invalid_package_identity; break; fi
            source=${base#libapache2-mod-}; source=${source%%-*}
            row=$(p2s_command_run 30 dpkg-query -W '-f=${Package}|${Version}|${Architecture}|${Source}|${Maintainer}\n' "$name" 2> "$P2S_WORK/repair-query.err") || { reason=source_identity_unavailable; break; }
            # dpkg Source can be "php8.2 (8.2.29-1)"; the binary revision must still match inventory.
            if ! printf '%s\n' "$row" | awk -F'|' -v n="$base" -v v="$version" -v a="$arch" -v s="$source" '
                {sub(/:.*/,"",$1); sub(/ \(.*/,"",$4); if ($4=="") $4=$1}
                NF!=5 || $1!=n || $2!=v || $3!=a || $4!=s {bad=1}
                END {exit bad || NR!=1}'; then reason=source_identity_mismatch; break; fi
            vendor=${row##*|}; vendor=$(p2s_package_provider "$name" "$vendor" "$version")
            case "$vendor" in
                Debian|Ubuntu) ;;
                Sury/*) if ! p2s_package_deb_is_sury "$version"; then reason=unreviewed_provider; break; fi ;;
                *) reason=unreviewed_provider; break ;;
            esac
            case "$status" in
                'install ok unpacked'|'install ok half-configured')
                    pending=true; printf '%s|%s|%s\n' "$name" "$version" "$arch" >> "$P2S_WORK/repair-pending" ;;
                'install ok installed')
                    # Missing checksum/list metadata needs reinstallation, not dpkg --configure.
                    if { [ -r "/var/lib/dpkg/info/$base.md5sums" ] || [ -r "/var/lib/dpkg/info/$base:$arch.md5sums" ]; } &&
                        { [ -r "/var/lib/dpkg/info/$base.list" ] || [ -r "/var/lib/dpkg/info/$base:$arch.list" ]; }; then
                        reason=audit_reason_not_missing_metadata; break
                    fi
                    reinstall=true; printf '%s|%s|%s\n' "$name" "$version" "$arch" >> "$P2S_WORK/repair-reinstall" ;;
                *) reason=unreviewed_package_state; break ;;
            esac
        done < "$P2S_WORK/audit-selected"
    fi
    # A mixed repair needs a separate reviewed sequence; neither flag implicitly selects the other.
    if $pending && $reinstall; then reason=mixed_repair_states; fi
    P2S_PACKAGE_REPAIR_REASON=$reason
    if [ -z "$reason" ]; then
        P2S_PENDING_PHP_REPAIR_ELIGIBLE=$pending; P2S_EXACT_PHP_REPAIR_ELIGIBLE=$reinstall
    fi
    p2s_manifest_record package_repair_assessment "pending_php=$P2S_PENDING_PHP_REPAIR_ELIGIBLE|exact_php_reinstall=$P2S_EXACT_PHP_REPAIR_ELIGIBLE|reason=${reason:-bounded_standard_php_targets}|cached_metadata_only"
}

# Only explicit affected PHP targets may process newly activated triggers. No --pending/-a.
p2s_package_deb_repair_finish() {
    local targets="$1" name version arch status target
    local triggers
    triggers=()
    p2s_command_run 30 dpkg-query -W '-f=${Package}|${Version}|${Architecture}|${Status}\n' > "$P2S_WORK/repair-after-status" 2> "$P2S_WORK/repair-query.err" || {
        p2s_fix_block package_repair "Could not verify package states after the repair attempt."; return 1;
    }
    while IFS='|' read -r name version arch status; do
        case "$status" in 'install ok installed'|'hold ok installed'|'deinstall ok config-files'|'purge ok not-installed'|'unknown ok not-installed') continue ;; esac
        case "$status" in 'install ok triggers-pending'|'install ok triggers-awaited') ;; *)
            p2s_fix_block package_repair "Package $name is not fully configured after the scoped PHP repair; no broader repair was attempted."; return 1 ;;
        esac
        if ! awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '
            ($1==n || $1 ":" $3==n) && $2==v && $3==a {found=1} END {exit !found}' "$targets"; then
            p2s_fix_block package_repair "The PHP repair activated a trigger outside its approved PHP targets ($name); no unrelated package scripts were run."; return 1
        fi
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        triggers[${#triggers[@]}]="$target"
    done < "$P2S_WORK/repair-after-status"
    if [ "${#triggers[@]}" -gt 0 ]; then
        # --no-triggers suppresses chains into other packages; explicit targets still process their own triggers.
        if ! (export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
            p2s_command_run 300 dpkg --force-confold --no-triggers --triggers-only "${triggers[@]}" > "$P2S_WORK/repair.log" 2>&1); then
            p2s_package_log_report "$P2S_WORK/repair.log"; p2s_fix_block package_repair "The scoped PHP trigger processing failed; review package state before retrying."; return 1
        fi
        p2s_package_log_report "$P2S_WORK/repair.log"
    fi
    if ! p2s_command_run 30 dpkg --audit > "$P2S_WORK/audit" 2> "$P2S_WORK/audit.err" || [ -s "$P2S_WORK/audit" ] || [ -s "$P2S_WORK/audit.err" ]; then
        p2s_manifest_record package_audit "$(cat "$P2S_WORK/audit" "$P2S_WORK/audit.err" | p2s_manifest_redact_repository_urls)"
        p2s_fix_block package_repair "The scoped PHP repair did not leave a clean package audit; no broader configuration or trigger processing was attempted."; return 1
    fi
    p2s_manifest_record package_repair_result 'audit_clean|PHP_patch_state_must_be_rechecked|service_replacement_still_required'
}

# P2S-MUTATION: Configure only verified unpacked/half-configured standard PHP packages.
p2s_disruptive_package_configure_pending_php() {
    local name version arch target
    local targets
    targets=()
    if [ "${P2S_MODE:-}" != fix ] || ! ${P2S_DISRUPTIVE:-false} ||
        ! ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} || ! ${P2S_PACKAGE_REPAIR_SAFETY_VERIFIED:-false}; then
        p2s_fix_block package_repair_consent "Pending PHP configuration requires --fix --enable-extra-fixes --configure-pending-php-packages and verified runtime, restart and filesystem safety."; return 1
    fi
    p2s_package_deb_repair_assess
    if ! $P2S_PENDING_PHP_REPAIR_ELIGIBLE; then
        p2s_fix_block package_repair_scope "Pending package configuration has no bounded standard PHP-only repair: $P2S_PACKAGE_REPAIR_REASON."; return 1
    fi
    while IFS='|' read -r name version arch; do
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        targets[${#targets[@]}]="$target"
    done < "$P2S_WORK/repair-pending"
    P2S_TRANSACTION_ATTEMPTED=true; P2S_PACKAGE_CONFIGURATION_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }dpkg --configure PHP packages"
    p2s_manifest_record package_repair_attempt 'configure_pending_php|explicit_targets_only|unrelated_triggers_suppressed|local_configuration_retained'
    if ! (export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
        p2s_command_run 600 dpkg --force-confold --no-triggers --configure "${targets[@]}" > "$P2S_WORK/repair.log" 2>&1); then
        p2s_package_log_report "$P2S_WORK/repair.log"; p2s_fix_block package_repair "Configuring the selected PHP packages failed or timed out; their maintainer scripts may have changed services."; return 1
    fi
    p2s_package_log_report "$P2S_WORK/repair.log"
    p2s_package_deb_repair_finish "$P2S_WORK/repair-pending"
}

# An exact reinstall restores package files/metadata; assess the retained version against the CVE fix rules.
p2s_package_deb_repair_exact_candidate_validate() {
    local name="$1" version="$2" arch="$3" target suite origin source provider
    target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
    source=${name#libapache2-mod-}; source=${source%%-*}
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*) suite=bullseye ;; debian:12|debian:12.*) suite=bookworm ;; debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        *) return 1 ;;
    esac
    provider=native; origin=Debian; [ "$P2S_DISTRO" != ubuntu ] || origin=Ubuntu
    if p2s_package_deb_is_sury "$version"; then provider=sury; fi
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/repair-origins" 2> "$P2S_WORK/repair-query.err" || return 1
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/repair-policy" 2> "$P2S_WORK/repair-query.err" || return 1
    p2s_manifest_record package_reinstall_policy "$name|$version|$arch
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/repair-policy")"
    # Bind each exact-version source row to authenticated release Origin and the measured OS suite.
    if ! awk -v v="$version" -v suite="$suite" -v origin="$origin" -v provider="$provider" -v arch="$arch" '
        function official_native(uri) {
            if (origin=="Debian") return uri ~ /^https?:\/\/(deb[.]debian[.]org\/debian(-security)?|security[.]debian[.]org(\/debian-security)?)\/?$/
            return uri ~ /^https?:\/\/(([a-z][a-z][.])?archive[.]ubuntu[.]com\/ubuntu|security[.]ubuntu[.]com\/ubuntu)\/?$/
        }
        NR==FNR {
            if ($1 ~ /^-?[0-9]+$/ && $2 ~ /^https?:\/\// && $5=="Packages") {key=$2 "|" $3 "|" $4; uri=$2; repo_arch=$4; next}
            if ($1=="release" && key!="") {
                release="," $2 ","; ok=0
                if (provider=="native" && official_native(uri) && index(release,",o=" origin ",") &&
                    (index(release,",n=" suite ",") || index(release,",n=" suite "-security,") || index(release,",n=" suite "-updates,"))) ok=1
                if (provider=="sury" && index(release,",n=" suite ",") &&
                    ((uri ~ /^https?:\/\/packages[.]sury[.]org\/php\/?$/ && index(release,",o=deb.sury.org,")) ||
                    (uri ~ /^https?:\/\/ppa[.]launchpad(content)?[.]net\/ondrej\/php\/ubuntu\/?$/ && index(release,",o=LP-PPA-ondrej-php,")))) ok=1
                if (ok && (repo_arch==arch || arch=="all") && index(release,",b=" repo_arch ",")) approved[key]=1
                key=""
            }
            next
        }
        $1=="Installed:" {installed=$2} $1=="Candidate:" {candidate=$2}
        $1=="***" {current=$2; next} NF==2 && $2 ~ /^-?[0-9]+$/ {current=$1; next}
        current==v && $1 ~ /^-?[0-9]+$/ && NF>=2 {
            if ($2=="/var/lib/dpkg/status") next
            if ($5=="Packages" && approved[$2 "|" $3 "|" $4]) matches++; else bad=1
        }
        END {exit installed!=v || candidate!=v || !matches || bad}' "$P2S_WORK/repair-origins" "$P2S_WORK/repair-policy"; then return 1; fi
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$version" > "$P2S_WORK/repair-metadata" 2> "$P2S_WORK/repair-query.err" || return 1
    awk -v n="${name%:*}" -v v="$version" -v a="$arch" -v s="$source" '
        function check() {if (!package) return; if (source=="") source=package; if (package!=n || version!=v || arch!=a || source!=s || !hash || !file) bad=1; records++}
        /^Package:/ {check(); package=$2; version=""; arch=""; source=""; hash=""; file=""}
        /^Version:/ {version=$2} /^Architecture:/ {arch=$2} /^Source:/ {source=$2}
        /^SHA256:/ {if (length($2)==64 && $2 !~ /[^0-9a-f]/) hash=$2}
        /^Filename:/ {if ($2 !~ /^\// && $2 !~ /(^|\/)\.\.(\/|$)/) file=$2}
        END {check(); exit bad || !records}' "$P2S_WORK/repair-metadata"
}

# P2S-MUTATION: Authenticated exact-version PHP reinstall, with no transaction expansion.
p2s_disruptive_package_reinstall_exact_php() {
    local name version arch target log="$P2S_WORK/repair.log"
    local targets
    targets=()
    if [ "${P2S_MODE:-}" != fix ] || ! ${P2S_DISRUPTIVE:-false} ||
        ! ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false} || ! ${P2S_PACKAGE_REPAIR_SAFETY_VERIFIED:-false}; then
        p2s_fix_block package_repair_consent "Exact PHP reinstallation requires --fix --enable-extra-fixes --reinstall-php-same-version and verified runtime, restart and filesystem safety."; return 1
    fi
    p2s_package_deb_repair_assess
    if ! $P2S_EXACT_PHP_REPAIR_ELIGIBLE; then
        p2s_fix_block package_repair_scope "Exact reinstallation has no bounded standard PHP-only repair: $P2S_PACKAGE_REPAIR_REASON."; return 1
    fi
    p2s_package_deb_sury_trust_preflight || return 1
    if ! p2s_command_run 300 apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowWeakRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false \
        -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
        -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update > "$log" 2>&1 ||
        grep -Ei '^(E:|W:.*(Failed to fetch|Some index files|GPG error|not signed))' "$log" >/dev/null; then
        p2s_package_log_report "$log"; p2s_fix_block package_repair "Package refresh failed or was incomplete; no exact reinstallation was attempted."; return 1
    fi
    while IFS='|' read -r name version arch; do
        if ! p2s_package_deb_repair_exact_candidate_validate "$name" "$version" "$arch"; then
            p2s_fix_block package_repair "The exact installed version of $name is not an authenticated candidate from the same package publisher for this OS suite; no alternate package was substituted."; return 1
        fi
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        targets[${#targets[@]}]="$target=$version"
    done < "$P2S_WORK/repair-reinstall"
    if ! p2s_command_run 120 apt-get -s --no-remove --reinstall -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--no-triggers \
        install --only-upgrade "${targets[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block package_repair "Exact PHP reinstallation simulation failed; no packages were installed."; return 1
    fi
    # Inst php8.2-cli [8.2.29-1] (8.2.29-1 Debian:12 [amd64]); additions have no [old].
    if ! awk -F'|' 'NR==FNR {
            base=$1; sub(/:.*/,"",base); key=base ":" $3
            v[$1]=$2; v[key]=$2; arch[$1]=$3; arch[key]=$3
            canonical[$1]=key; canonical[key]=key; needed[key]=1; next
        }
        /^(Inst|Conf) / {
            if ($0 ~ /^Inst / && $0 !~ /^Inst [a-z0-9][a-z0-9+.:_-]* \[[^][]+\] \([^()]+ \[[a-z0-9]+\]\)$/) {bad=1; next}
            if ($0 ~ /^Conf / && $0 !~ /^Conf [a-z0-9][a-z0-9+.:_-]* \([^()]+ \[[a-z0-9]+\]\)$/) {bad=1; next}
            split($0,a," "); line=$0; sub(/^[^(]*\(/,"",line); split(line,b,/[ )]/)
            fields=split($0,parts," "); observed=parts[fields]; gsub(/[\[\]()]/,"",observed)
            if (!(a[2] in v) || b[1]!=v[a[2]] || observed!=arch[a[2]]) bad=1
            if (a[1]=="Inst") {
                old=$0; sub(/^[^[]*\[/,"",old); sub(/\].*/,"",old)
                if (old!=v[a[2]]) bad=1
                seen[canonical[a[2]]]=1; count++
            }
            next
        }
        /^[ \t]*$/ || /^[ \t]+/ || /^(Reading package lists|Building dependency tree|Reading state information|The following|Suggested packages:|Recommended packages:|[0-9]+ upgraded,|NOTE: This is only a simulation[.]|[ \t]*apt-get needs root privileges)/ {next}
        {bad=1}
        END {for (key in needed) if (!seen[key]) bad=1; exit bad || !count}' "$P2S_WORK/repair-reinstall" "$log"; then
        p2s_fix_block package_repair "Exact PHP reinstallation proposes a changed identity, new package, removal, unrelated configuration or unrecognized plan; no packages were installed."; return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=true; P2S_PACKAGE_REINSTALL_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }apt-get install --reinstall PHP packages"
    p2s_manifest_record package_repair_attempt 'exact_php_reinstall|same_provider_name_version_architecture|local_configuration_retained|unrelated_triggers_suppressed'
    if ! (export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
        p2s_command_run 900 apt-get -y --no-remove --reinstall -o APT::Get::AllowUnauthenticated=false \
            -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowWeakRepositories=false \
            -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
            -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--no-triggers install --only-upgrade "${targets[@]}" > "$log" 2>&1); then
        p2s_package_log_report "$log"; p2s_fix_block package_repair "Exact PHP reinstallation failed or timed out; review package state before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_package_deb_repair_finish "$P2S_WORK/repair-reinstall"
}


# Read-only proposal approval; caller must rerun the pinned simulation and guard installation.
p2s_package_deb_dependency_approve_plan() {
    local log="$1" name old candidate arch installed_source record target suite origin file parent dep op required installed_version candidate_version maintainer plan_arch
    case "$P2S_BACKEND:$P2S_DISTRO:$P2S_RELEASE" in
        deb:debian:11|deb:debian:11.*) suite=bullseye; origin=Debian ;;
        deb:debian:12|deb:debian:12.*) suite=bookworm; origin=Debian ;;
        deb:debian:13|deb:debian:13.*) suite=trixie; origin=Debian ;;
        deb:ubuntu:22.04) suite=jammy; origin=Ubuntu ;;
        deb:ubuntu:24.04) suite=noble; origin=Ubuntu ;;
        deb:ubuntu:26.04) suite=resolute; origin=Ubuntu ;;
        *) p2s_fix_block dependency_platform "No reviewed native dependency upgrade method exists for this OS release."; return 1 ;;
    esac
    : > "$P2S_WORK/dependency-approved"
    : > "$P2S_WORK/dependency-arguments"
    : > "$P2S_WORK/dependency-needed"
    : > "$P2S_WORK/dependency-edges"
    if ! awk '/^(Remv|Purg|E:|W:) / {exit 1}
        /^Conf / {if ($0 !~ /^Conf [a-z0-9][a-z0-9+.:_-]* \([^()]+ \[[a-z0-9]+\]\)$/) exit 1; next}
        /^Inst / {
            if ($0 !~ /^Inst [a-z0-9][a-z0-9+.:_-]* \[[^][]+\] \([^()]+ \[[a-z0-9]+\]\)$/) exit 1
            name=$2; old=$3; gsub(/[\[\]]/,"",old); line=$0; sub(/^[^(]*\(/,"",line); split(line,a," ")
            arch=$NF; gsub(/[\[\]()]/,"",arch); print name "|" old "|" a[1] "|" arch; next
        }
        /^[ \t]*$/ || /^[ \t]+/ || /^(Reading package lists|Building dependency tree|Reading state information|The following|Suggested packages:|Recommended packages:|[0-9]+ upgraded,|NOTE: This is only a simulation[.]|[ \t]*apt-get needs root privileges)/ {next}
        {exit 1}' "$log" > "$P2S_WORK/dependency-plan"; then
        p2s_fix_block dependency_plan "Dependency approval requires a recognized upgrade-only APT plan with no package additions or removals."; return 1
    fi
    while IFS='|' read -r name old candidate plan_arch; do
        if awk -F'|' -v n="$name" '$1==n || $1 ":" $3==n {found=1} END {exit !found}' "$P2S_WORK/apt-approved"; then continue; fi
        case "${name%:*}" in libpcre2-8-0|libonig5|libargon2-1|libxml2|libzip4|libzip5|libsodium23) ;;
            *) p2s_fix_block dependency_scope "The proposed extra package $name is outside the reviewed native shared-library list."; return 1 ;;
        esac
        if [ -s "$P2S_WORK/holds" ] && awk -v n="${name%:*}" -v a="$plan_arch" '
            $1==n || $1==n ":" a {found=1} END {exit !found}' "$P2S_WORK/holds"; then
            p2s_fix_block held_package "Required PHP library $name is held; review the hold before updating."; return 1
        fi
        record=$(p2s_command_run 30 dpkg-query -W '-f=${Status}|${binary:Package}|${Version}|${Architecture}|${source:Package}|${Maintainer}\n' "$name") || return 1
        case "$record" in 'install ok installed|'*) ;; *) p2s_fix_block dependency_state "The proposed dependency $name is not fully installed."; return 1 ;; esac
        record=${record#*|}; target=${record%%|*}; record=${record#*|}; installed_version=${record%%|*}; record=${record#*|}; arch=${record%%|*}; record=${record#*|}; installed_source=${record%%|*}; maintainer=${record#*|}
        [ "${target%:*}" = "${name%:*}" ] && [ "$installed_version" = "$old" ] && [ -n "$installed_source" ] && [ "$arch" = amd64 ] && [ "$plan_arch" = "$arch" ] || {
            p2s_fix_block dependency_state "Installed dependency identity or architecture could not be verified for $name."; return 1;
        }
        case "$name" in *:*) [ "${name##*:}" = "$arch" ] || return 1 ;; esac
        if [ "$(p2s_package_provider "$name" "$maintainer" "$old")" != "$origin" ]; then
            p2s_fix_block dependency_provider "The installed dependency $name is not identified as a native OS package."; return 1
        fi
        target="${name%:*}:$arch"
        p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/dependency-policy" 2> "$P2S_WORK/dependency-query.err" || return 1
        if ! awk -v suite="$suite" -v origin="$origin" -v wanted="$candidate" -v old="$old" '
            function official(uri) {
                if (origin=="Debian") return uri ~ /^https?:\/\/(deb[.]debian[.]org\/debian(-security)?|security[.]debian[.]org(\/debian-security)?)\/?$/
                return uri ~ /^https?:\/\/(([a-z][a-z][.])?archive[.]ubuntu[.]com\/ubuntu|security[.]ubuntu[.]com\/ubuntu)\/?$/
            }
            NR==FNR {
                if ($1 ~ /^-?[0-9]+$/ && $2 ~ /:\/\// && $5=="Packages") {key=$2 "|" $3 "|" $4; native=official($2); next}
                if ($1=="release" && key!="") {
                    line="," $2 ","
                    if (native && index(line,",o=" origin ",") &&
                        (index(line,",n=" suite ",") || index(line,",n=" suite "-updates,") || index(line,",n=" suite "-security,"))) approved[key]=1
                    key=""
                }
                next
            }
            $1=="Installed:" {installed=$2; next}
            $1=="Candidate:" {candidate=$2; next}
            $1=="***" {version=$2; next}
            NF==2 && $2 ~ /^-?[0-9]+$/ {version=$1; next}
            version==wanted && $1 ~ /^-?[0-9]+$/ && NF>=2 {
                if ($2=="/var/lib/dpkg/status") next
                if ($5=="Packages" && approved[$2 "|" $3 "|" $4]) matches++; else other++
            }
            END {exit !(installed==old && candidate==wanted && matches>0 && other==0)}
        ' "$P2S_WORK/candidate-origins" "$P2S_WORK/dependency-policy"; then
            p2s_fix_block dependency_provider "The normal candidate for $name is not exclusively from reviewed native sources for this OS suite."; return 1
        fi
        dpkg --compare-versions "$candidate" gt "$old" || { p2s_fix_block dependency_downgrade "The proposed dependency $name is not an upgrade."; return 1; }
        file="$P2S_WORK/dependency-${name%:*}.metadata"
        p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$candidate" > "$file" 2> "$P2S_WORK/dependency-query.err" || return 1
        if ! awk -v n="${name%:*}" -v v="$candidate" -v a="$arch" -v s="$installed_source" '
            function check() {if (package!="" && (package!=n || version!=v || arch!=a || (source!="" ? source : package)!=s)) bad=1}
            /^Package:/ {check(); package=$2; version=""; arch=""; source=""}
            /^Version:/ {version=$2} /^Architecture:/ {arch=$2} /^Source:/ {source=$2}
            END {check(); exit (bad || package=="")}' "$file"; then
            p2s_fix_block dependency_identity "The dependency $name changes binary, source or architecture identity."; return 1
        fi
        printf '%s|%s|%s|%s\n' "${name%:*}" "$candidate" "$arch" "$name" >> "$P2S_WORK/dependency-approved"
        printf '%s|%s|%s\n' "${name%:*}" "$old" "$candidate" >> "$P2S_WORK/dependency-needed"
        printf '%s=%s\n' "$target" "$candidate" >> "$P2S_WORK/dependency-arguments"
    done < "$P2S_WORK/dependency-plan"
    [ -s "$P2S_WORK/dependency-approved" ] || return 0
    # Only a versioned, non-alternative dependency unsatisfied by the installed library proves necessity.
    cat "$P2S_WORK/apt-approved" "$P2S_WORK/dependency-approved" > "$P2S_WORK/dependency-parents"
    while IFS='|' read -r parent candidate arch name; do
        target="$parent:$arch"; [ "$arch" != all ] || target=$parent
        file="$P2S_WORK/dependency-$parent.metadata"
        {
            p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$candidate" > "$file" 2> "$P2S_WORK/dependency-query.err" || return 1
        }
        awk '/^(Pre-Depends|Depends):/ {line=$0; sub(/^[^:]*:[ \t]*/,"",line); active=1; print "," line; next}
            /^[ \t]/ {if (active) print; next} {active=0}' "$file" | tr '\n' ' ' | tr ',' '\n' |
            awk 'index($0,"|")==0 && $0 ~ /^[ \t]*[a-z0-9+.-]+(:[a-z0-9]+)?[ \t]+\((>=|>>|=)[ \t]+[^() \t]+\)[ \t]*$/ {
                gsub(/[()]/,""); print $1 "|" $2 "|" $3}' > "$P2S_WORK/dependency-fields"
        while IFS='|' read -r dep op required; do
            dep=${dep%:any}; dep=${dep%:amd64}
            record=$(awk -F'|' -v n="$dep" '$1==n {print $2 "|" $3}' "$P2S_WORK/dependency-needed")
            [ -n "$record" ] || continue
            installed_version=${record%%|*}; candidate_version=${record#*|}
            case "$op" in '>=' ) op=ge ;; '>>') op=gt ;; '=') op=eq ;; *) continue ;; esac
            if ! dpkg --compare-versions "$installed_version" "$op" "$required" && dpkg --compare-versions "$candidate_version" "$op" "$required"; then
                printf '%s|%s\n' "$parent" "$dep" >> "$P2S_WORK/dependency-edges"
            fi
        done < "$P2S_WORK/dependency-fields"
    done < "$P2S_WORK/dependency-parents"
    if ! awk -F'|' 'FILENAME==ARGV[1] {reachable[$1]=1; next}
        FILENAME==ARGV[2] {parent[++count]=$1; child[count]=$2; next}
        {needed[$1]=1}
        END {for (pass=0; pass<=count; pass++) for (i=1;i<=count;i++) if (reachable[parent[i]]) reachable[child[i]]=1
            for (name in needed) if (!reachable[name]) exit 1}' \
        "$P2S_WORK/apt-approved" "$P2S_WORK/dependency-edges" "$P2S_WORK/dependency-needed"; then
        p2s_fix_block dependency_necessity "At least one proposed library upgrade lacks a matching unsatisfied versioned PHP dependency; broader dependency changes need manual review."; return 1
    fi
    cat "$P2S_WORK/dependency-approved" >> "$P2S_WORK/apt-approved"
    p2s_manifest_record dependency_approval "$(cat "$P2S_WORK/dependency-approved")"
}


# Read installed package state only; reuse before prediction and immediately before APT changes.
p2s_package_deb_holds_preflight() {
    local name
    if p2s_command_exists apt-mark; then
        p2s_command_run 30 apt-mark showhold > "$P2S_WORK/holds" 2>/dev/null || { p2s_fix_block package_holds "Could not read package holds; manual review is required."; return 1; }
    else
        p2s_command_run 30 dpkg --get-selections > "$P2S_WORK/selections" 2>/dev/null || { p2s_fix_block package_holds "Could not read package selections; manual review is required."; return 1; }
        awk '$2 == "hold" { print $1 }' "$P2S_WORK/selections" > "$P2S_WORK/holds"
    fi
    while IFS= read -r name; do
        if p2s_package_is_php "$name"; then
            p2s_fix_block held_package "PHP package $name is held; review the hold before updating."
            return 1
        fi
    done < "$P2S_WORK/holds"
}

p2s_package_deb_preflight() {
    local audit_status=0
    p2s_command_exists apt-get || { p2s_fix_block apt_missing "apt-get is unavailable; cannot update Debian PHP packages."; return 1; }
    p2s_command_run 30 dpkg --audit > "$P2S_WORK/audit" 2> "$P2S_WORK/audit.err" || audit_status=$?
    P2S_PACKAGE_AUDIT_EXIT_STATUS=$audit_status
    if [ "$audit_status" -ne 0 ] || [ -s "$P2S_WORK/audit" ] || [ -s "$P2S_WORK/audit.err" ]; then
        p2s_manifest_record package_audit "$(cat "$P2S_WORK/audit" "$P2S_WORK/audit.err" | p2s_manifest_redact_repository_urls)"
        p2s_package_deb_audit_context_collect
        p2s_fix_block package_state "dpkg reports package-state or metadata warnings; review the package audit in the diagnostic report before updating PHP."
        return 1
    fi
    p2s_package_deb_holds_preflight
}

# P2S-MUTATION: APT update path; refreshes metadata and upgrades PHP and verified required native libraries.
p2s_package_deb_update() {
    local log="$P2S_WORK/apt.log" name version arch vendor changed sury=false has_sury=false target source branch
    local P2S_SURY_MIGRATION_ACTIVE=false
    local packages cache_options
    packages=(); cache_options=()
    : > "$P2S_WORK/dependency-approved"
    if [ "${P2S_MODE:-fix}" = check ]; then cache_options=(-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=); fi
    if ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        p2s_disruptive_sury_validate_equivalents || return 1
        P2S_SURY_MIGRATION_ACTIVE=true
        p2s_message_print warn "Switching from distribution PHP packages to third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages was explicitly requested. Only equivalent versioned packages with matching PHP branches, architecture and extension APIs are eligible."
        p2s_manifest_record provider_migration 'Sury|explicit_opt_in|same_names_branches_architectures_and_extension_API|required_fixed_candidates|selectors_frozen'
    fi
    while IFS='|' read -r name version arch vendor; do
        if p2s_package_deb_is_sury "$version"; then has_sury=true; fi
    done < "$P2S_WORK/packages"
    : > "$P2S_WORK/apt-selected"
    while IFS='|' read -r name version arch vendor; do
        case "${P2S_PANEL:-}:$name" in cpanel:cpanel-php*|cpanel:sw-engine*) continue ;; esac
        if $has_sury || $P2S_SURY_MIGRATION_ACTIVE; then
            # Freeze selectors: updating php-cli/php-xml can select a different already-installed branch.
            case "${name%:*}" in php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9]|php-common|php-pear) ;;
                *) p2s_manifest_record source_preservation "$name|selector_or_unreviewed_package_not_selected"; continue ;;
            esac
            case "${name%:*}" in php-common|php-pear)
                # New php-common revisions can Break older extension selectors; do not request a helper upgrade.
                continue ;;
            esac
            if $P2S_SURY_MIGRATION_ACTIVE && ! p2s_package_deb_is_sury "$version"; then
                source=$(awk -F'|' -v n="$name" '$1==n && !seen[$4]++ {print $4}' "$P2S_WORK/deb-source-records")
                branch=${name#libapache2-mod-}; branch=${branch%%-*}
                [ "$source" = "$branch" ] || continue
            fi
        fi
        # Generic selectors do not contain a PHP engine and can have no candidate on otherwise patchable hosts.
        case "${name%:*}" in php|php[0-9]|php[0-9].[0-9]|php-cli|php-cgi|php-fpm|php-phpdbg|libapache2-mod-php) continue ;; esac
        packages[${#packages[@]}]="$name"
        printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/apt-selected"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    p2s_package_deb_preflight || return 1
    if $has_sury || $P2S_SURY_MIGRATION_ACTIVE; then
        p2s_package_deb_sury_trust_preflight || return 1
        p2s_manifest_record source_preservation "APT|per_package_provider_checks|selectors_frozen|Sury_migration=$P2S_SURY_MIGRATION_ACTIVE"
    fi
    if [ "${P2S_MODE:-fix}" = fix ] && $P2S_SURY_MIGRATION_ACTIVE && ${P2S_ALLOW_SURY_REPOSITORY:-false}; then
        p2s_disruptive_sury_add_repository || return 1
    fi
    if [ "${P2S_MODE:-fix}" = fix ]; then
    p2s_message_print info "Refreshing package lists and checking PHP and required native-library updates."
    # Contents maps filenames to packages for apt-file searches; PHP updates need package indexes, not those large maps.
    # These command-only defaults preserve source files and trust checks. Explicit per-source Targets can override them.
    p2s_manifest_record apt_refresh_scope 'optional_Contents_defaults=disabled|translations=disabled|required_package_indexes_and_signature_checks=retained|persistent_configuration=unchanged'
    # P2S-MUTATION: Refreshes on-disk APT metadata; this does not install packages.
    if ! p2s_command_run 300 apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowWeakRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
        -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::Languages=none \
        -o Acquire::IndexTargets::deb::Contents-deb::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb::Contents-deb-legacy::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb::Contents-udeb::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb-src::Contents-dsc::DefaultEnabled=false update > "$log" 2>&1; then
        p2s_package_refresh_failure_report "$log" "Package refresh failed. Check repository availability, network/DNS, signatures and support entitlement."; return 1
    fi
    if grep -Ei '^(E:|W:.*(Failed to fetch|Some index files|GPG error|not signed))' "$log" >/dev/null; then
        p2s_package_refresh_failure_report "$log" "Package lists are incomplete or untrusted; refusing to install from stale metadata."; return 1
    fi
    p2s_package_log_report "$log"
    else
        p2s_manifest_record apt_refresh_scope 'cached_plan_only|repositories_not_refreshed|no_packages_or_services_changed'
    fi
    if ! p2s_command_exists apt-cache || ! p2s_command_exists dpkg ||
        ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/candidate-origins" 2> "$P2S_WORK/candidate-origins.err"; then
        if [ -s "$P2S_WORK/candidate-origins.err" ]; then p2s_manifest_record apt_policy_error "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-origins.err")"; fi
        p2s_fix_block candidate_provider "APT candidate origins could not be inspected; refusing an unchecked PHP package source change."
        return 1
    fi
    packages=()
    : > "$P2S_WORK/apt-approved"
    : > "$P2S_WORK/migration-api-branches"
    while IFS='|' read -r name version arch vendor; do
        sury=false
        if p2s_package_deb_is_sury "$version"; then sury=true; fi
        p2s_package_deb_candidate "$name" "$version" "$arch" "$sury" || return 1
        if [ "$P2S_DEB_CANDIDATE" = "$version" ]; then
            p2s_manifest_record candidate_unchanged "$name|$version|not_requested_for_upgrade"
            continue
        fi
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        packages[${#packages[@]}]="$target=$P2S_DEB_CANDIDATE"
        printf '%s|%s|%s|%s\n' "${name%:*}" "$P2S_DEB_CANDIDATE" "$arch" "$name" >> "$P2S_WORK/apt-approved"
    done < "$P2S_WORK/apt-selected"
    if $P2S_SURY_MIGRATION_ACTIVE; then
        while IFS='|' read -r name version arch vendor; do
            if ! p2s_package_is_engine "$name"; then continue; fi
            branch=${name#libapache2-mod-}; branch=${branch%%-*}
            if ! grep -Fx -e "$branch" "$P2S_WORK/migration-api-branches" >/dev/null; then
                p2s_fix_block candidate_abi "No matching installed and proposed PHP extension API was verified for $branch; this method needs a CLI, FPM, CGI or Apache package with a matching API."
                return 1
            fi
        done < "$P2S_WORK/apt-selected"
    fi
    if [ "${#packages[@]}" -eq 0 ]; then
        if $P2S_RESTART_PENDING || ${P2S_PANEL_UPDATE_COMPLETED:-false}; then return 0; fi
        p2s_fix_block no_candidate "No PHP update meeting this script's package-source and safety checks was found in the configured sources. See the package policy and candidate details in the run manifest."
        return 1
    fi
    if $has_sury || $P2S_SURY_MIGRATION_ACTIVE; then
        # APT can upgrade php-xml/php-curl selectors while resolving php-common, even if they
        # were not requested. Keep every other installed PHP package at its current version.
        # --only-upgrade also preserves their existing automatic/manual installation marks.
        while IFS='|' read -r name version arch vendor; do
            if awk -F'|' -v n="$name" -v a="$arch" '$4==n && $3==a {found=1} END {exit !found}' "$P2S_WORK/apt-approved"; then continue; fi
            target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
            packages[${#packages[@]}]="$target=$version"
            p2s_manifest_record package_version_constraint "$name|$version|$arch|retain_installed_version|command_only"
        done < "$P2S_WORK/packages"
    fi
    if ! p2s_command_run 120 apt-get -s "${cache_options[@]}" --no-remove install --only-upgrade "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"
        p2s_package_deb_policy_collect "${packages[@]}"
        p2s_fix_block transaction_plan "The PHP update simulation failed. Review package pins, holds, missing candidates and dependency conflicts in the run manifest. This APT simulation installed no packages and changed no restrictions; any earlier panel update is reported separately."
        return 1
    fi
    p2s_package_log_report "$log"
    if awk -F'|' '
        FILENAME==ARGV[1] {approved[$1]=1; approved[$1 ":" $3]=1; next}
        /^Inst / {split($0,a," "); if (!(a[2] in approved)) extra=1}
        END {exit !extra}' "$P2S_WORK/apt-approved" "$log"; then
        p2s_package_deb_dependency_approve_plan "$log" || return 1
        if [ -s "$P2S_WORK/dependency-arguments" ]; then
            while IFS= read -r target; do packages[${#packages[@]}]="$target"; done < "$P2S_WORK/dependency-arguments"
            if ! p2s_command_run 120 apt-get -s "${cache_options[@]}" --no-remove install --only-upgrade "${packages[@]}" > "$log" 2>&1; then
                p2s_package_log_report "$log"; p2s_fix_block dependency_plan "The exact pinned PHP dependency simulation failed; no packages were installed."; return 1
            fi
            p2s_package_log_report "$log"
        fi
    fi
    if [ -s "$P2S_WORK/dependency-approved" ] && ! awk -F'|' '
        FILENAME==ARGV[1] {v[$1]=$2; v[$1 ":" $3]=$2; arch[$1]=$3; arch[$1 ":" $3]=$3; next}
        /^(Inst|Conf) / {
            if ($0 ~ /^Inst / && $0 !~ /^Inst [a-z0-9][a-z0-9+.:_-]* \[[^][]+\] \([^()]+ \[[a-z0-9]+\]\)$/) {bad=1; next}
            if ($0 ~ /^Conf / && $0 !~ /^Conf [a-z0-9][a-z0-9+.:_-]* \([^()]+ \[[a-z0-9]+\]\)$/) {bad=1; next}
            split($0,a," "); line=$0; sub(/^[^(]*\(/,"",line); split(line,b," ")
            count=split($0,parts," "); observed=parts[count]; gsub(/[\[\]()]/,"",observed)
            if (!(a[2] in v) || b[1]!=v[a[2]] || observed!=arch[a[2]]) bad=1
            next
        }
        /^[ \t]*$/ || /^[ \t]+/ || /^(Reading package lists|Building dependency tree|Reading state information|The following|Suggested packages:|Recommended packages:|[0-9]+ upgraded,|NOTE: This is only a simulation[.]|[ \t]*apt-get needs root privileges)/ {next}
        {bad=1}
        END {exit bad}' "$P2S_WORK/apt-approved" "$log"; then
        p2s_fix_block dependency_plan "The pinned dependency simulation changed scope, versions, architecture or output format; no packages were installed."; return 1
    fi
    # Inst php8.4-cli [old] (new repository [arch]); do not silently upgrade unrelated dependencies.
    for changed in $(awk '/^(Inst|Conf) / {print $2}' "$log"); do
        case "${P2S_PANEL:-}:$changed" in
            cpanel:cpanel-php*|cpanel:sw-engine*) p2s_fix_block transaction_scope "The website PHP update proposes a panel-managed package ($changed); use the panel updater for it."; return 1 ;;
        esac
        if ! awk -F'|' -v name="$changed" '$1 == name || $1 ":" $3 == name { found=1 } END { exit !found }' "$P2S_WORK/apt-approved"; then
            p2s_fix_block transaction_scope "The proposed update would also change $changed, outside the approved PHP packages and verified required native libraries. We stopped before installing this transaction; review the package plan before retrying."; return 1
        fi
    done
    # Inst php8.2-cli [old] (new repo [amd64]); the install must use the exact approved version.
    if ! awk -F'|' 'NR==FNR {versions[$1]=$2; versions[$1 ":" $3]=$2; next}
        /^(Inst|Conf) / {split($0,a," "); line=$0; sub(/^[^(]*\(/,"",line); split(line,b,/[ )]/); if (b[1]!=versions[a[2]]) bad=1}
        END {exit bad}' "$P2S_WORK/apt-approved" "$log"; then
        p2s_fix_block transaction_scope "The simulated package versions differ from the approved APT candidates."
        return 1
    fi
    if grep '^Remv ' "$log" >/dev/null; then p2s_fix_block removals "The update proposes package removals; manual review is required."; return 1; fi
    if ! grep '^Inst ' "$log" >/dev/null; then
        if $P2S_RESTART_PENDING || ${P2S_PANEL_UPDATE_COMPLETED:-false}; then return 0; fi
        p2s_fix_block no_candidate "No PHP package upgrades were proposed. The configured repositories may not yet supply a verified fix, or packages may be held."
        return 1
    fi
    if [ "${P2S_MODE:-fix}" = check ]; then
        p2s_manifest_record cached_update_plan 'approved_with_cached_metadata_only|fresh_fix_preflight_and_refresh_required'
        return 0
    fi
    if [ "${P2S_MODE:-fix}" != fix ]; then
        p2s_fix_block privileges 'A package installation requires explicit fix mode.'; return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }apt-get install --only-upgrade PHP packages"
    if ! (export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
        # P2S-MUTATION: Installs PHP and verified required library updates; package scripts can also change services.
        p2s_command_run 1800 apt-get -y --no-remove -o APT::Get::AllowUnauthenticated=false \
            -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowWeakRepositories=false \
            -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
            -o Dpkg::Options::=--force-confold install --only-upgrade "${packages[@]}" > "$log" 2>&1); then
        p2s_package_log_report "$log"; p2s_fix_block package_update "PHP package installation failed or timed out. Check package-manager state before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "Updated installed PHP packages and any verified required native libraries through APT without permitting removals or replacing local configuration."
}

p2s_package_rpm_validate_plan() {
    # LANG=C DNF4/YUM: Upgrading:/Updating:, package rows, Transaction Summary.
    # Other formats require a new reviewed recipe; unknown output is not an approved plan.
    awk -F'|' -v panel="${P2S_PANEL:-}" 'NR==FNR {
            if (panel!="cpanel" || $1 !~ /^(cpanel-php|sw-engine)/) selected[$1]=1
            next
        }
        /^(Installing|Removing|Downgrading|Obsoleting|Reinstalling|Replacing|Upgrading dependencies|Updating for dependencies)/ { bad=1 }
        /^(Upgrading|Updating):/ { rows=1; seen=1; next }
        /^Transaction Summary/ { rows=0; summary=1 }
        rows && NF {
            split($0, fields, /[ \t\r\n\014\013]+/)
            name=fields[1]; if (name=="") name=fields[2]
            if (name ~ /^=+$/) next
            sub(/\.(x86_64|aarch64|noarch|i[3-6]86|ppc64le|s390x)$/, "", name)
            if (!(name in selected)) bad=1
        }
        END { exit (bad || !seen || !summary) }
    ' "$P2S_WORK/packages" "$1"
}

# P2S-MUTATION: DNF/YUM update path; refreshes caches and can install PHP packages.
p2s_package_rpm_update() {
    local manager log="$P2S_WORK/rpm-update.log" name version arch vendor
    local packages
    packages=()
    while IFS='|' read -r name version arch vendor; do
        case "${P2S_PANEL:-}:$name" in cpanel:cpanel-php*|cpanel:sw-engine*) continue ;; esac
        packages[${#packages[@]}]="$name"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    if p2s_command_exists dnf; then manager=dnf
    elif p2s_command_exists yum; then manager=yum
    else p2s_fix_block rpm_manager "Neither dnf nor yum is available; cannot update RPM PHP packages."; return 1
    fi
    # P2S-MUTATION: Writes refreshed repository metadata to the package-manager cache.
    if ! p2s_command_run 300 "$manager" -y '--setopt=*.metadata_expire=0' --setopt=timeout=20 --setopt=retries=1 --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false' makecache > "$log" 2>&1; then
        p2s_package_refresh_failure_report "$log" "RPM metadata refresh failed. Check repositories, network/DNS, signatures and subscriptions."; return 1
    fi
    p2s_package_log_report "$log"
    # P2S-MUTATION: Test transaction can download/cache packages; no real PHP installation is requested.
    if ! p2s_command_run 1800 "$manager" -y --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false' --setopt=tsflags=test update "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block transaction_plan "The RPM test transaction failed; no real update was requested."; return 1
    fi
    p2s_package_log_report "$log"
    # DNF can successfully report no work; that is not an unrecognised transaction.
    # Do not perform an install, or infer that the installed PHP has verified fixes.
    if grep -Fx 'Nothing to do.' "$log" >/dev/null; then
        p2s_manifest_record package_update_plan "$manager|no_updates"
        if $P2S_RESTART_PENDING || ${P2S_PANEL_UPDATE_COMPLETED:-false}; then return 0; fi
        p2s_fix_block no_candidate "The configured repositories offered no newer installed PHP packages. The installed build remains unverified; check the vendor security advisory and any package holds or exclusions."
        return 1
    fi
    if ! p2s_package_rpm_validate_plan "$log"; then
        p2s_fix_block transaction_scope "The RPM plan failed the PHP-only update checks. Review additional dependencies, removals and the plan format before proceeding."
        return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }$manager update PHP packages"
    # P2S-MUTATION: Installs PHP RPM updates; package scriptlets can also change services.
    if ! p2s_command_run 1800 "$manager" -y --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false' update "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block package_update "The RPM PHP update failed or timed out; check the package transaction before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "Updated installed PHP packages through $manager without switching streams or enabling package erasure."
}

# Manual migration advice only: cache inspection never enables or switches a module stream.
p2s_package_rpm_stream_guidance_report() {
    local record version arch vendor provider branch expected enabled state target stream_targets='' label unit
    case "$P2S_BACKEND:$P2S_DISTRO:$P2S_MAJOR" in rpm:rocky:8|rpm:almalinux:8|rpm:rocky:9|rpm:almalinux:9) ;; *) return 0 ;; esac
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 0 ;; esac
    # php-common is the engine family revision; php-pear and parallel/panel namespaces are not it.
    [ -r "$P2S_WORK/packages" ] || return 0
    record=$(awk -F'|' '$1=="php-common" {record=$2 FS $3 FS $4; count++} END {if (count==1) print record}' "$P2S_WORK/packages")
    [ -n "$record" ] || return 0
    IFS='|' read -r version arch vendor <<EOF
$record
EOF
    provider=$(p2s_package_provider php-common "$vendor" "$version")
    branch=${version#*:}; branch=${branch%%-*}; branch=${branch%.*}
    case "$provider:$P2S_MAJOR:$branch" in
        'Rocky Linux:8:7.2'|'Rocky Linux:8:7.3'|'Rocky Linux:8:8.0'|\
        'AlmaLinux:8:7.2'|'AlmaLinux:8:7.3'|'AlmaLinux:8:8.0'|\
        'Rocky Linux:9:8.1'|'AlmaLinux:9:8.1')
            expected=$branch; label="The native PHP $branch module stream has retired even though this OS release is still maintained." ;;
        Remi*:8:7.*|Remi*:8:8.0|Remi*:8:8.1|Remi*:9:7.*|Remi*:9:8.0|Remi*:9:8.1)
            expected="remi-$branch"; label="This installation uses Remi PHP $branch, which is no longer supported by the upstream PHP project." ;;
        *) return 0 ;;
    esac
    p2s_message_print warn "$label Ordinary dnf/yum upgrades stay in the enabled PHP stream; they do not select a newer PHP branch."
    state=$(awk -F'|' '$1=="php-common" {print $2; exit}' "$P2S_WORK/package-states" 2>/dev/null)
    if [ "$state" = N ]; then
        p2s_message_print info "This installed PHP build already has verified PHP2Shell fixes. The stream migration below concerns ongoing support, not an outstanding fix for these two CVEs."
    else
        p2s_message_print info "First try --fix for security updates from the existing PHP source and branch. A same-branch security update is usually the smallest application change."
    fi
    if ! p2s_fix_blockers_match '|no_candidate|' || ! p2s_command_exists dnf; then return 0; fi
    # DNF4 module list: php 7.2 [d][e] common [d], devel, minimal PHP scripting language.
    # -C reads cached metadata; disabled plugins and private log paths avoid refresh/subscription helpers.
    if ! LC_ALL=C p2s_command_run 60 dnf -C '--disableplugin=*' "--setopt=logfile=$P2S_WORK/module-source.log" \
        "--setopt=logdir=$P2S_WORK" module list php > "$P2S_WORK/php-module-cache" 2> "$P2S_WORK/php-module-cache.err"; then
        p2s_manifest_record php_module_gap "cache_query_failed|$(p2s_manifest_redact_repository_urls < "$P2S_WORK/php-module-cache.err")"
        p2s_message_print warn "The cached PHP module list could not be read. Run 'sudo dnf --refresh module list php' to see the streams currently available from this server's repositories."
        return 0
    fi
    p2s_manifest_record php_module_cache "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/php-module-cache")"
    LC_ALL=C awk '$1=="php" && $2 ~ /^[a-zA-Z0-9_.-]+$/ && !index($0,"[x]") {
        key=$2; available[key]=1; if (index($0,"[e]")) enabled[key]=1
    } END {for (key in available) print key "|" (enabled[key] ? "yes" : "no")}' "$P2S_WORK/php-module-cache" > "$P2S_WORK/php-module-streams"
    enabled=$(awk -F'|' '$2=="yes" {print $1}' "$P2S_WORK/php-module-streams")
    if [ "$enabled" != "$expected" ]; then
        p2s_manifest_record php_module_gap "installed_branch=$branch|expected=$expected|enabled=$enabled|stream_state_not_matched"
        p2s_message_print warn "The enabled PHP module stream could not be matched uniquely to installed PHP $branch. Review 'sudo dnf --refresh module list php' and 'rpm -q php-common' before choosing a migration."
        return 0
    fi
    case "$expected:$P2S_MAJOR" in
        remi-*:*) stream_targets=remi-8.4 ;;
        7.2:8|7.3:8) stream_targets='7.4 8.2' ;;
        8.0:8) stream_targets=8.2 ;;
        8.1:9) stream_targets='8.2 8.3' ;;
    esac
    record=''
    for target in $stream_targets; do
        awk -F'|' -v wanted="$target" '$1==wanted {found=1} END {exit !found}' "$P2S_WORK/php-module-streams" || continue
        case "$target" in
            7.4) label='Smaller PHP 7 compatibility step; this is a vendor-maintained EL8 stream despite upstream PHP 7.4 being end of life.' ;;
            remi-8.4) label='PHP 8.4 from the already configured Remi source. Confirm that the application and its extensions support PHP 8.4.'; target="$target/common" ;;
            *) label="Native PHP $target. Confirm application and extension support for this PHP branch." ;;
        esac
        p2s_manifest_record php_stream_migration "current=$expected|target=$target|availability=cached_module_list|architecture=$arch|fixed_candidate=not_queried|manual_only|preview=sudo dnf --refresh --assumeno module switch-to php:$target|apply=sudo dnf --refresh module switch-to php:$target"
        p2s_message_print info "Manual migration option php:$target. $label Preview the transaction: sudo dnf --refresh --assumeno module switch-to php:$target. After compatibility and package-plan review, apply that one option: sudo dnf --refresh module switch-to php:$target."
        record=offered
    done
    if [ -z "$record" ]; then
        p2s_message_print warn "No reviewed destination stream was found in the cached PHP module list. Refresh the list with 'sudo dnf --refresh module list php' before choosing a supported destination."
        return 0
    fi
    p2s_message_print warn "A stream switch can replace extensions, change configuration and remove packages unavailable in the destination. Review application/framework/plugin requirements and the proposed removals. No PHP branch change is guaranteed compatible."
    case "$branch" in
        7.*) p2s_message_print warn "PHP 7 to 8 removes legacy functions such as each() and create_function(), tightens error handling and can require Apache PHP module configuration changes. Even PHP 7.2 to 7.4 changes regular-expression behaviour and needs matching extension builds." ;;
        *) p2s_message_print info "Moving between PHP 8 branches can also introduce incompatible changes. Use the application's supported PHP versions and extension requirements to choose the destination." ;;
    esac
    p2s_message_print info "Published PHP2Shell fixes exist for these destination streams, but listing a stream does not verify its current package candidate. After applying one chosen migration, check the full installed build with 'rpm -q php-common' and rerun this script with --check. PHP 7.4 vendor backports can keep the 7.4.33 engine version."
    if [ -r "$P2S_WORK/services" ]; then
        while IFS= read -r unit; do
            case "$unit" in
                php-fpm.service) p2s_message_print info "After migration, validate the observed PHP-FPM service configuration with 'sudo php-fpm -t', then restart it with 'sudo systemctl restart php-fpm.service'." ;;
                httpd.service) p2s_message_print info "After migration, verify Apache's PHP handler and run 'sudo httpd -t', then restart it with 'sudo systemctl restart httpd.service'." ;;
            esac
        done < "$P2S_WORK/services"
    fi
    [ ! -s "$P2S_WORK/scheduled-php" ] || p2s_message_print info "Already-running PHP scheduled tasks retain their old PHP code. Let them finish or restart them through their application's procedure after the migration."
}

# Repository configuration inventory

p2s_repository_inventory_collect() {
    local file
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo; do
        [ -f "$file" ] || continue
        p2s_manifest_record repository_file "$file"
        [ -r "$file" ] || { p2s_manifest_record source_gap "$file|unreadable"; continue; }
        # Read data, never source configs. Whitelist useful fields; omit auth, proxy and signing-key contents.
        # deb [signed-by=/key] URI suite component; deb822 uses Types:/URIs:/Suites: stanzas.
        awk -v file="$file" '
            /^[ \t\r\n\014\013]*[#;]/ { next }
            /^[ \t\r\n\014\013]*$/ { stanza++; key=""; next }
            /^[ \t\r\n\014\013]*deb(-src)?[ \t\r\n\014\013]/ {
                line=$0; sub(/^[ \t\r\n\014\013]*/, "", line); sub(/\[[^]]*\][ \t\r\n\014\013]*/, "", line)
                sub(/[ \t\r\n\014\013]+#.*/, "", line)
                print file "|apt-list|" line; next
            }
            /^[ \t\r\n\014\013]*\[/ { section=$0; gsub(/^[ \t\r\n\014\013]*\[|\][ \t\r\n\014\013]*$/, "", section); next }
            {
                line=$0; sub(/^[ \t\r\n\014\013]*/, "", line)
                if (file ~ /[.]sources$/) {
                    if ($0 !~ /^[ \t]/ && line ~ /^[A-Za-z-]+:/) {
                        key=tolower(line); sub(/:.*/, "", key); sub(/^[^:]*:[ \t\r\n\014\013]*/, "", line)
                    } else if ($0 !~ /^[ \t\r\n\014\013]/) key=""
                    if (key ~ /^(types|uris|suites|components|enabled)$/)
                        print file "|deb822-stanza=" stanza+1 "|" key "|" line
                } else if (line ~ /^(baseurl|mirrorlist|metalink|enabled|gpgcheck|repo_gpgcheck)[ \t\r\n\014\013]*=/) {
                    sub(/[ \t\r\n\014\013]*=[ \t\r\n\014\013]*/, "|", line)
                    print file "|rpm-repo=" section "|" line
                }
            }' "$file" | p2s_manifest_redact_repository_urls |
            while IFS= read -r file; do p2s_manifest_record repository_definition "$file"; done
        p2s_repository_maintenance_report "$file"
    done
}

# Hosting-panel inventory and vendor updates

p2s_panel_inventory_collect() {
    # CageFS is CloudLinux's per-customer filesystem jail; host updates can leave jail copies unchanged.
    local name directory label panel_found=false tool container_tools='' version_file version
    local update_tools path key value
    P2S_PANEL=; P2S_PANEL_TOOL=
    for name in cpanel plesk virtualmin directadmin cloudlinux cagefs litespeed aapanel; do
        case "$name" in
            cpanel) directory=/usr/local/cpanel; label=cPanel ;;
            plesk) directory=/usr/local/psa; label=Plesk ;;
            virtualmin) directory=/etc/webmin/virtual-server; label=Virtualmin ;;
            directadmin) directory=/usr/local/directadmin; label=DirectAdmin ;;
            cloudlinux) directory=/etc/cl.selector; label=CloudLinux ;;
            cagefs) directory=/etc/cagefs; label=CageFS ;;
            litespeed) directory=/usr/local/lsws; label=LiteSpeed ;;
            aapanel) directory=/www/server/panel; label=aaPanel ;;
        esac
        [ -d "$directory" ] || continue
        p2s_manifest_record panel "$name|$directory"
        if [ "$name" = cpanel ]; then
            for path in "$directory" "$directory/version" "$directory/cpsrvd" "$directory/3rdparty/bin/perl"; do
                p2s_manifest_path_record panel_path "$path"
            done
            if [ -r /etc/cpupdate.conf ]; then
                # CPANEL=release / SECURITY_UPDATES=never: keep only documented update settings, never other configuration.
                LC_ALL=C awk -F= '
                    NF==2 && (($1=="CPANEL" && ($2 ~ /^(edge|current|release|stable|lts)$/ || $2 ~ /^[0-9]+([.][0-9]+)*$/)) ||
                    ($1=="SECURITY_UPDATES" && $2 ~ /^(hourly|never)$/) ||
                    (($1=="RPMUP" || $1=="UPDATES") && $2 ~ /^(daily|manual|never)$/)) {print $1 "|" $2}
                ' /etc/cpupdate.conf | while IFS='|' read -r key value; do
                    p2s_manifest_record panel_update_setting "cpanel|$key=$value"
                    case "$key=$value" in
                        SECURITY_UPDATES=never)
                            p2s_message_print warn "cPanel's critical security updater is disabled by SECURITY_UPDATES=never in /etc/cpupdate.conf. Enable critical security updates in WHM's Update Preferences before retrying." ;;
                        CPANEL=[0-9]*)
                            # CPANEL=136 selects a branch; 136.0.29 or 11.136.0.29 pins an exact build.
                            if printf '%s\n' "$value" | awk -F. 'NF==4 || (NF==3 && $1!=11) {found=1} END {exit !found}'; then
                                p2s_message_print warn "cPanel is pinned to release $value in /etc/cpupdate.conf. Its critical security updater skips pinned releases. Review the release selection in WHM's Update Preferences."
                            fi ;;
                    esac
                done
            else p2s_manifest_record panel_update_setting 'cpanel|/etc/cpupdate.conf|unavailable'; fi
            p2s_cpanel_last_update_report
        elif [ "$name" = cloudlinux ]; then
            p2s_manifest_path_record panel_path "$directory"
        fi
        case "$name" in
            cpanel|plesk)
                version=
                version_file="$directory/version"
                if [ -r "$version_file" ]; then
                    version=$(head -n 1 "$version_file")
                    p2s_manifest_record panel_version "$name|$version_file|$version"
                else p2s_manifest_record panel_version "$name|$version_file|unavailable"; fi
                # Check mode inventories tools without invoking an updater or refreshing repositories.
                if [ "$name" = cpanel ]; then
                    update_tools=("$directory/scripts/upcp" "$directory/scripts/update-packages" "$directory/scripts/rpmup")
                else
                    update_tools=("$directory/admin/sbin/autoinstaller" /usr/sbin/plesk)
                fi
                for tool in "${update_tools[@]}"; do
                    if [ "$name" = cpanel ]; then p2s_manifest_path_record panel_path "$tool"; fi
                    [ -x "$tool" ] && p2s_manifest_record panel_update_tool "$name|$tool|not_executed"
                done
                p2s_manifest_record panel_update_scope "$name|website_PHP_and_panel_PHP_require_separate_verification|broad_vendor_updates_can_change_non_PHP_components" ;;
        esac
        case "$name" in
            cpanel|plesk)
                panel_found=true
                if [ -n "$P2S_PANEL" ]; then
                    p2s_fix_block control_panel "More than one hosting panel was detected. Review the installation before running vendor updates."
                    continue
                fi
                P2S_PANEL=$name
                if [ "$name" = cpanel ] && [ -x "$directory/scripts/upcp" ] &&
                    printf '%s\n' "$version" | awk -F. '$1==11 && $2 ~ /^[0-9]+$/ && $2>=110 {ok=1} END {exit !ok}'; then
                    P2S_PANEL_TOOL="$directory/scripts/upcp"
                    p2s_message_print info "Control panel detected: cPanel. Fix mode can request critical panel security updates, then update installed website PHP packages. Panel and website PHP are verified separately."
                    p2s_manifest_record panel_update_recipe 'cpanel|upcp --security|then_explicit_website_PHP_packages|no_force'
                elif [ "$name" = plesk ] && [ -x /usr/sbin/plesk ] &&
                    printf '%s\n' "$version" | grep '^18[.]0[.][0-9]' >/dev/null; then
                    P2S_PANEL_TOOL=/usr/sbin/plesk
                    p2s_message_print warn "Control panel detected: Plesk. Fix mode runs the vendor updater for installed components within the current Plesk release. This can update PHP, databases, mail and web-server components, and may interrupt those services."
                    p2s_manifest_record panel_update_recipe 'plesk|installer --select-release-current --upgrade-installed-components|scope=all_installed_components'
                else
                    p2s_fix_block control_panel "Control panel detected: $label. Its version or required update tool could not be matched to a supported recipe (cPanel 110 or later, or Plesk Obsidian 18)."
                    if [ "$name" = cpanel ] && { [ ! -r "$version_file" ] || [ ! -x "$directory/scripts/upcp" ]; }; then
                        p2s_message_print warn "cPanel core files are unavailable. Review panel_path diagnostics for an incomplete installation or leftover files before repairing or removing panel components."
                    fi
                fi ;;
            virtualmin)
                panel_found=true
                p2s_message_print info "Control panel detected: Virtualmin. Fix mode can update package-managed PHP using the existing repositories and supported service restarts. Check each virtual server's selected PHP version and application compatibility; website PHP selections are not changed by this script." ;;
            cloudlinux) p2s_fix_block control_panel "CloudLinux was detected. Its PHP packages and service restarts need a vendor-specific review; automatic updates are disabled for this setup." ;;
            cagefs) P2S_UNKNOWN=true; p2s_fix_block cagefs "CageFS configuration was found. This script cannot verify whether applications use separate PHP copies or safely update them." ;;
            litespeed) p2s_fix_block detached_php "LiteSpeed was detected. Detached LSPHP workers can survive a web-server restart; a handler-specific update and restart review is required." ;;
            *)
                panel_found=true
                p2s_fix_block control_panel "Control panel detected: $label. Its PHP packages and service restarts need a panel-specific review; automatic updates are disabled for this setup." ;;
        esac
    done
    if ! $panel_found; then p2s_message_print info "No recognised hosting control panel detected in the checked locations."; fi
    for tool in docker podman lxc-ls; do
        p2s_command_exists "$tool" || continue
        case "$tool" in docker) label=Docker ;; podman) label=Podman ;; lxc-ls) label=LXC ;; esac
        container_tools="${container_tools:+$container_tools, }$label"
        p2s_manifest_record container_tool "$label|$tool|installed_only"
    done
    if [ -n "$container_tools" ]; then
        p2s_manifest_record scope_note "containers|installed_tools=$container_tools|installed_only"
        p2s_message_print info "Container software installed: $container_tools."
    fi
}

p2s_cpanel_last_update_report() {
    local directory=/var/cpanel/updatelogs log modified line
    # The last log can predate this no-op security request; never attribute it to this attempt.
    ${P2S_CPANEL_LAST_LOG_REPORTED:-false} && return 0
    P2S_CPANEL_LAST_LOG_REPORTED=true
    p2s_command_exists readlink || return 0
    directory=$(readlink -f "$directory" 2>/dev/null) || return 0
    log=$(readlink -f "$directory/last" 2>/dev/null) || return 0
    case "$log" in "$directory"/*) ;; *) return 0 ;; esac
    [ -f "$log" ] && [ -r "$log" ] || return 0
    # Read only the final 256 KiB; log size must not make a diagnostic expensive.
    tail -c 262144 "$log" > "$P2S_WORK/cpanel-last-update.log" 2>/dev/null || return 0
    modified=$(LC_ALL=C TZ=UTC stat -c '%y' "$log" 2>/dev/null) || modified=unavailable
    p2s_manifest_record panel_previous_update_log "$log|modified_UTC=$modified|scope=last_262144_bytes|not_current_attempt_output"
    p2s_message_print info "cPanel's last recorded update log is $log (last modified: $modified UTC). It records a previous update; the reported problems may have been resolved since then."
    LC_ALL=C grep -Ei 'Blocker found:|conflicts with|conflicts:|The install encountered a fatal error:|reported error (number|code)[^0-9]*[1-9][0-9]*|ea-apache24.*(conflicts with httpd-mmn|requires ea-apache24-mmn)|cannot install.*(mod_ssl|httpd-core)' "$P2S_WORK/cpanel-last-update.log" |
        head -n 20 | p2s_manifest_redact_repository_urls |
        while IFS= read -r line; do p2s_manifest_record panel_previous_update_error "$line"; done
    p2s_cpanel_update_blockers_report "$P2S_WORK/cpanel-last-update.log" previous || :
    if LC_ALL=C grep -Ei 'The install encountered a fatal error:|reported error (number|code)[^0-9]*[1-9][0-9]*' "$P2S_WORK/cpanel-last-update.log" >/dev/null; then
        p2s_message_print warn "cPanel's last recorded update log reports a failed component update. These historical errors may explain why PHP remains unfixed; they are not output from this update attempt."
    fi
}

# Share exact blocker/conflict reporting between dated logs and current updater output.
p2s_cpanel_update_blockers_report() {
    local log=$1 scope=$2 line key reason failed=false
    LC_ALL=C grep -Ei 'Blocker found:|conflicts with|conflicts:|((invalid|expired|missing|not valid|not activated).*licen[cs]e|licen[cs]e.*(invalid|expired|missing|not found|not valid|not activated))' "$log" |
        head -n 20 | p2s_manifest_redact_repository_urls > "$P2S_WORK/cpanel-update-blockers"
    while IFS= read -r line; do
        key=panel_update
        if printf '%s\n' "$line" | LC_ALL=C grep -Ei 'licen[cs]e' >/dev/null; then
            key=panel_license
            reason="cPanel reported a license problem. A valid cPanel license is required for this update path. Check the current license status in WHM. Reported reason: $line"
        elif printf '%s\n' "$line" | LC_ALL=C grep -Ei 'conflicts with|conflicts:' >/dev/null; then
            key=panel_package_conflict
            reason='cPanel reported conflicting packages that cannot be installed together.'
            if printf '%s\n' "$line" | LC_ALL=C grep -E 'ea-apache24.*conflicts with httpd-mmn.*httpd-core' >/dev/null; then
                reason="cPanel's Apache package (ea-apache24) conflicts with the operating system's Apache package (httpd-core)."
            fi
            reason="$reason Resolve the package selections before retrying. Reported conflict: $line"
        else
            reason="cPanel reported an update blocker: $line"
        fi
        if [ "$scope" = current ]; then
            p2s_manifest_record panel_update_diagnostics "cpanel|$key|$line"
            p2s_fix_block "$key" "$reason Some changes may already have been made."
        else
            p2s_message_print warn "cPanel's last recorded update log: $reason"
        fi
        failed=true
    done < "$P2S_WORK/cpanel-update-blockers"
    ! $failed
}

# P2S-MUTATION: Vendor update path; Plesk can update non-PHP components as well.
p2s_panel_update() {
    local log="$P2S_WORK/panel-update.log" status
    local arguments
    case "$P2S_PANEL" in
        cpanel)
            arguments=("$P2S_PANEL_TOOL" --security)
            p2s_message_print info "Running $P2S_PANEL_TOOL --security to request cPanel's critical security updates before checking website PHP packages." ;;
        plesk)
            arguments=("$P2S_PANEL_TOOL" installer --select-release-current --upgrade-installed-components)
            p2s_message_print warn "Updating installed Plesk components within the current release. This operation can also update databases, mail and web-server components; check those services and applications afterwards." ;;
        *) return 1 ;;
    esac
    p2s_manifest_record panel_update_command "${arguments[*]}"
    P2S_TRANSACTION_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }${arguments[*]}"
    # P2S-MUTATION: Runs the installed vendor updater; do not force a release change or rewrite preferences.
    p2s_command_run 1800 "${arguments[@]}" < /dev/null > "$log" 2>&1
    status=$?
    p2s_package_log_report "$log"
    p2s_manifest_record panel_update_exit "$P2S_PANEL|$status"
    # Report every selected blocker before returning: licensing and package conflicts can coexist.
    if [ "$P2S_PANEL" = cpanel ] && ! p2s_cpanel_update_blockers_report "$log" current; then return 1; fi
    # cPanel can exit zero after a nested updater reports a fatal error or nonzero child exit.
    if [ "$P2S_PANEL" = cpanel ] && LC_ALL=C grep -Ei 'The install encountered a fatal error:|reported error (number|code)[^0-9]*[1-9][0-9]*' "$log" >/dev/null; then
        p2s_manifest_record panel_update_diagnostics 'cpanel|nested_update_failed|see_vendor_update_log'
        p2s_fix_block panel_update "cPanel reported a failed component update (main command exit status $status). Review the cPanel update log and resolve its reported blockers before retrying. Components or services may already have changed."
        return 1
    fi
    if [ "$status" -ne 0 ]; then
        p2s_fix_block panel_update "$P2S_PANEL update failed or timed out (exit $status). Components or services may have changed. Review the vendor update log and service health before retrying."
        return 1
    fi
    P2S_PANEL_UPDATE_COMPLETED=true
    p2s_message_print fixmethod "${arguments[*]} returned success. Checking installed PHP and running processes to see whether the fixes were installed."
}

# Process scope, scheduled jobs and running-code inventory

p2s_process_check_host_scope() {
    local entry="$1" pid="$2" executable="${3% (deleted)}" root namespace own_namespace cgroup container='' process_label='PHP or web-server process' usage_note='' review_key advice php_review=true level
    root=$(readlink "$entry/root" 2>/dev/null)
    namespace=$(readlink "$entry/ns/mnt" 2>/dev/null)
    own_namespace=$(readlink /proc/self/ns/mnt 2>/dev/null)
    p2s_manifest_record process_scope "$pid|${root:-unknown}|${namespace:-unavailable}"
    if [ "$root" = / ]; then
        [ "$namespace" = "$own_namespace" ] && return 0
        # PrivateTmp creates a mount namespace too; verify shared files, not namespace names alone.
        if [ -n "$namespace" ] && [ -n "$own_namespace" ] && [ "$entry/root" -ef / ] &&
            [ -n "$executable" ] && [ "$entry/root$executable" -ef "$executable" ]; then
            p2s_manifest_record process_scope_shared "$pid|$executable"
            return 0
        fi
    fi
    # Match this process to a container using namespace/cgroup observations.
    cgroup=$(cat "$entry/cgroup" 2>/dev/null)
    case "$cgroup" in
        */docker/*|*/docker-*.scope*) container=Docker ;;
        */libpod-*.scope*) container=Podman ;;
        */lxc/*|*/lxc.payload.*) container=LXC ;;
    esac
    p2s_manifest_record process_container_evidence "$pid|${container:-unidentified}|$cgroup"
    case "${executable##*/}" in
        nginx*|apache*|httpd*|lshttpd*|caddy*|lighttpd*)
            process_label="${executable##*/} web-server process"
            # A separate web server is not a PHP gap unless it maps PHP or cannot be inspected.
            if [ -r "$entry/maps" ] &&
                usage_note=$(awk '/\/[^ ]*libphp[^\/ ]*\.so/ {found=1} END {if (found) print "PHP module loaded"}' "$entry/maps" 2>/dev/null); then
                [ -n "$usage_note" ] || php_review=false
            else usage_note='PHP module inspection failed'
            fi ;;
        php*|lsphp*|sw-engine*|frankenphp*) process_label="${executable##*/} PHP process" ;;
    esac
    p2s_manifest_record process_scope_review "$pid|$process_label|$executable|${container:-unidentified}"
    if $php_review; then
        P2S_UNKNOWN=true
        P2S_SEPARATE_ENVIRONMENT_REVIEW=true
        p2s_manifest_record verification_gap "isolated_runtime|$pid|$process_label|${container:-unidentified}|host_updates_allowed|$usage_note"
        level=warn
        advice=" Check and update PHP inside that environment separately."
        [ -z "$usage_note" ] || advice=" $usage_note.$advice"
    else
        p2s_manifest_record scope_note "isolated_web_server|$pid|no_PHP_module_in_inspected_mappings"
        level=info; advice=''
    fi
    # Foreign paths/PIDs stay excluded from host probes and automatic service restarts.
    review_key="$process_label|$executable|${container:-unidentified}|$usage_note"
    if grep -Fx -e "$review_key" "$P2S_WORK/scope-reviews-reported" >/dev/null 2>&1; then return 1; fi
    printf '%s\n' "$review_key" >> "$P2S_WORK/scope-reviews-reported"
    if [ -n "$container" ]; then
        p2s_message_print "$level" "A running $process_label is inside a $container container.$advice"
    else
        p2s_message_print "$level" "A running $process_label uses a separate or unidentified application environment.$advice"
    fi
    return 1
}

p2s_process_start_ticks() {
    # /proc/PID/stat field 22 is identity information, unlike a PID that can be reused.
    # Strip the parenthesised command first; it can contain spaces and parentheses.
    awk '{ sub(/^.*\) /, ""); print $20; exit }' "$1" 2>/dev/null
}

p2s_process_scheduled_php_collect() {
    local pid="$1" executable="${2% (deleted)}" unit="$3" started="$4" owner ticks uid
    case "$unit" in cron.service|crond.service) ;; *) return 1 ;; esac
    case "${executable##*/}" in php|php[0-9]|php[0-9].[0-9]) ;; *) return 1 ;; esac
    owner=$(p2s_package_owner_for_path "$executable")
    # Only a known CLI engine qualifies. CGI/FPM, wrappers and custom binaries retain their blockers.
    case "$owner" in php*-cli|ea-php*-php-cli|alt-php*-cli|rh-php*-php-cli|plesk-php*-cli|cpanel-php*-cli) ;; *) return 1 ;; esac
    p2s_package_is_engine "$owner" || return 1
    awk -F'|' -v name="$owner" '$1==name {found=1} END {exit !found}' "$P2S_WORK/packages" || return 1
    ticks=$(p2s_process_start_ticks "/proc/$pid/stat")
    uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null)
    printf '%s|%s|%s\n' "$pid" "$ticks" "$executable" >> "$P2S_WORK/scheduled-php"
    p2s_manifest_record scheduled_php "$pid|$executable|$owner|$unit|uid=${uid:-unavailable}|started=$started|start_ticks=${ticks:-unavailable}|not_an_automatic_restart_target"
}

p2s_process_scheduled_php_verify() {
    local pid ticks executable current remaining=0 pids='' process_label='PHP scheduled-task processes' verb=are
    [ "$P2S_PHASE" = afterfix ] && [ -r "$P2S_WORK/scheduled-php.before" ] || return 0
    # Compare only after a real update/restart attempt, not after a refused preflight or failed refresh.
    ${P2S_TRANSACTION_ATTEMPTED:-false} || ${P2S_RESTART_ATTEMPTED:-false} || return 0
    while IFS='|' read -r pid ticks executable; do
        case "$pid" in ''|*[!0-9]*) continue ;; esac
        [ -d "/proc/$pid" ] || continue
        current=$(p2s_process_start_ticks "/proc/$pid/stat")
        if [ -n "$ticks" ] && [ -n "$current" ] && [ "$ticks" != "$current" ]; then
            p2s_manifest_record scheduled_php_finished "$pid|original_process_exited|PID_reused"
            continue
        fi
        remaining=$((remaining + 1)); pids="${pids:+$pids, }$pid"
        P2S_UNKNOWN=true
        p2s_manifest_record verification_gap "scheduled_php|$pid|$executable|running_before_update|start_ticks=${ticks:-unavailable}|current_ticks=${current:-unavailable}|must_finish_or_be_reviewed"
    done < "$P2S_WORK/scheduled-php.before"
    if [ "$remaining" -gt 0 ]; then
        if [ "$remaining" -eq 1 ]; then process_label='PHP scheduled-task process'; verb=is; fi
        p2s_message_print warn "$remaining $process_label from before the update $verb still running or could not be identified reliably (PIDs: $pids). Updating packages does not replace PHP code already loaded by these tasks. Let those tasks finish, or safely stop and rerun them using their application-specific procedure, then run this check again. Restarting cron, Apache or PHP-FPM does not reliably replace these tasks. This script did not terminate them."
    fi
}

p2s_process_inventory_collect() {
    # FPM (FastCGI Process Manager) keeps PHP workers separate from the front-end web server.
    # mod_php instead loads PHP into Apache workers, so those workers must also be replaced.
    local entry pid comm executable started maps path unit needs_restart service candidate service_count parent parent_executable parent_comm parent_unit label process_found=false process_count=0
    local unreadable_executables=0 unreadable_maps=0 web_server_found=false web_server comparison_status maps_verified
    : > "$P2S_WORK/services"
    : > "$P2S_WORK/processes"
    : > "$P2S_WORK/fpm-masters"
    : > "$P2S_WORK/unmapped-services"
    : > "$P2S_WORK/scheduled-php"
    : > "$P2S_WORK/scope-reviews-reported"
    P2S_PROCESS_USAGE_COMPLETE=false
    : > "$P2S_WORK/process-runtime-paths"
    : > "$P2S_WORK/web-restart-advisories"
    if [ ! -r /proc/1/stat ] || ! p2s_command_exists readlink || ! p2s_command_exists ps; then
        P2S_UNKNOWN=true
        p2s_fix_block process_inventory "Process executable information is unavailable; running PHP workers cannot be verified."
        return
    fi
    : > "$P2S_WORK/web-servers.$P2S_PHASE"
    for entry in /proc/[0-9]*; do
        [ -r "$entry/stat" ] || continue
        pid=${entry##*/}
        comm=$(awk '{ sub(/^[^(]*\(/, ""); sub(/\).*/, ""); print }' "$entry/stat" 2>/dev/null)
        # Recognising a web server is informational; it does not select it for a PHP restart.
        case "$comm" in
            apache*|httpd*) web_server=Apache ;; nginx*) web_server=nginx ;;
            caddy*) web_server=Caddy ;; lighttpd*) web_server=lighttpd ;;
            lshttpd*) web_server=LiteSpeed ;; frankenphp*) web_server=FrankenPHP ;;
            *) web_server= ;;
        esac
        if [ -n "$web_server" ]; then
            web_server_found=true
            printf '%s\n' "$web_server" >> "$P2S_WORK/web-servers.$P2S_PHASE"
            p2s_manifest_record web_process "$pid|$comm"
        fi
        case "$comm" in php*|lsphp*|sw-engine*|apache*|httpd*|nginx*|lshttpd*|frankenphp*) ;; *) continue ;; esac
        process_found=true
        process_count=$((process_count + 1))
        executable=$(readlink "$entry/exe" 2>/dev/null)
        if [ -z "$executable" ]; then
            if [ ! -d "$entry" ]; then
                p2s_manifest_record process_exit "$pid|$comm|exited_before_executable_check"
                continue
            fi
            P2S_UNKNOWN=true
            unreadable_executables=$((unreadable_executables + 1))
            p2s_manifest_record inventory_gap "process_executable|$pid|$comm|unreadable_or_exited"
            continue
        fi
        started=$(TZ=UTC ps -p "$pid" -o lstart= 2>/dev/null)
        if [ -n "$started" ]; then started="$started UTC"
        else started="elapsed $(ps -p "$pid" -o etime= 2>/dev/null)"
        fi
        p2s_manifest_record process "$pid|$comm|$executable|$started"
        # Child start times remain in the manifest; show masters in the customer summary.
        parent=$(sed 's/.*) //' "$entry/stat" | awk '{print $2}')
        parent_executable=$(readlink "/proc/$parent/exe" 2>/dev/null)
        # CGI workers may be launched by Apache, a FastCGI supervisor or a custom service.
        # Identify the parent executable and service before planning the application restart.
        parent_comm=$(awk '{ sub(/^[^(]*\(/, ""); sub(/\).*/, ""); print }' "/proc/$parent/stat" 2>/dev/null)
        parent_unit=$(sed -n 's@.*/\([^/]*\.service\)$@\1@p' "/proc/$parent/cgroup" 2>/dev/null | head -n 1)
        p2s_manifest_record process_parent "$pid|${parent:-unknown}|${parent_comm:-unknown}|${parent_executable:-unknown}|${parent_unit:-unknown}"
        if [ "$parent_executable" != "$executable" ]; then
            label=
            case "$comm" in
                php-fpm[0-9]*) label="PHP-FPM ${comm#php-fpm}" ;;
                php*fpm*) label="PHP-FPM ($comm)" ;; apache*|httpd*) label=Apache ;;
                nginx*) label=nginx ;; sw-engine*) label='WebPros sw-engine PHP' ;;
                lshttpd*) label=LiteSpeed ;; frankenphp*) label=FrankenPHP ;;
            esac
            [ -z "$label" ] || p2s_message_print info "$label main process started: ${started:-unknown} (PID $pid; executable $executable)."
        fi
        if ! p2s_process_check_host_scope "$entry" "$pid" "$executable"; then continue; fi
        case "$comm" in php*|lsphp*|sw-engine*|frankenphp*)
            p2s_runtime_path_add "${executable% (deleted)}"
            printf '%s|%s|executable\n' "${executable% (deleted)}" "$pid" >> "$P2S_WORK/process-runtime-paths"
            p2s_manifest_record process_runtime_reference "$pid|executable|$executable" ;;
        esac
        needs_restart=true
        maps_verified=false
        case "$comm" in nginx*|apache*|httpd*) needs_restart=false ;; esac
        if [ -r "$entry/maps" ]; then
            # /proc/PID/maps: address perms offset dev inode /path/libphp8.4.so (deleted)
            # Old mawk requires escaped slash delimiters even inside character classes.
            if maps=$(awk '/\/.*libphp[^\/]*\.so/ { sub(/^[^\/]*\//, "/"); print }' "$entry/maps"); then
                maps_verified=true
            else
                if [ ! -d "$entry" ]; then
                    p2s_manifest_record process_exit "$pid|$comm|exited_before_memory_check"
                    continue
                fi
                P2S_UNKNOWN=true
                unreadable_maps=$((unreadable_maps + 1))
                p2s_manifest_record inventory_gap "process_maps|$pid|$comm|read_failed"
                maps=
            fi
            while IFS= read -r path; do
                [ -n "$path" ] || continue
                needs_restart=true
                case "$path" in *' (deleted)') P2S_UNKNOWN=true; P2S_RESTART_PENDING=true ;; esac
                if ! [ "$entry/root${path% (deleted)}" -ef "${path% (deleted)}" ]; then
                    P2S_UNKNOWN=true
                    p2s_fix_block isolated_module "Process $pid maps a PHP module whose filesystem path differs from the host; its package and restart require manual review."
                    continue
                fi
                p2s_runtime_path_add "${path% (deleted)}"
                printf '%s|%s|module\n' "${path% (deleted)}" "$pid" >> "$P2S_WORK/process-runtime-paths"
                p2s_manifest_record process_runtime_reference "$pid|module|$path"
            done <<EOF
$maps
EOF
        else
            if [ ! -d "$entry" ]; then
                p2s_manifest_record process_exit "$pid|$comm|exited_before_memory_check"
                continue
            fi
            P2S_UNKNOWN=true
            unreadable_maps=$((unreadable_maps + 1))
            p2s_manifest_record inventory_gap "process_maps|$pid|$comm|unreadable_or_exited"
        fi
        # Linux keeps the old executable inode in use after replacement and labels its path '(deleted)'.
        # Only PHP-serving processes affect this CVE. A replaced nginx/Apache binary alone
        # needs separate maintenance, not another PHP-FPM restart. Failed map reads remain unknown.
        case "$executable" in *' (deleted)')
            if $needs_restart; then
                P2S_UNKNOWN=true; P2S_RESTART_PENDING=true
                p2s_manifest_record php_restart_pending "$pid|$comm|$executable|deleted_executable"
            elif $maps_verified; then
                p2s_manifest_record web_restart_advisory "$pid|$comm|$executable|no_php_module_detected"
                printf '%s|%s\n' "$comm" "${executable% (deleted)}" >> "$P2S_WORK/web-restart-advisories"
            fi ;;
        esac
        $needs_restart || continue
        case "$comm" in
            lsphp*|lshttpd*) p2s_fix_block detached_php "LiteSpeed/LSAPI process $comm needs a handler-specific restart; restarting its web server alone does not replace detached PHP." ;;
        esac
        # Discover the exact active systemd unit; never infer a unit from an executable name.
        unit=$(sed -n 's@.*/\([^/]*\.service\)$@\1@p' "$entry/cgroup" 2>/dev/null | head -n 1)
        # Cron's unit identifies a launcher, not a PHP restart target. Update CLI packages but do not restart cron
        # or terminate tasks; retain their identities separately for post-update verification.
        if p2s_process_scheduled_php_collect "$pid" "$executable" "$unit" "$started"; then continue; fi
        case "$unit" in
            php*-fpm.service|httpd.service|apache2.service)
                printf '%s\n' "$unit" >> "$P2S_WORK/services" ;;
            *)
                # Panel-specific units need both an observed service association and the matching panel.
                case "${P2S_PANEL:-}:$unit" in
                    plesk:plesk-web-socket.service)
                        if p2s_service_plesk_web_socket_verified; then
                            printf '%s\n' "$unit" >> "$P2S_WORK/services"
                        else
                            P2S_BLOCKED=true
                            p2s_manifest_record service_mapping "$pid|$comm|$executable|$unit|restart_target_unverified"
                            printf '%s|%s|%s\n' "$comm" "$executable" "$unit" >> "$P2S_WORK/unmapped-services"
                        fi ;;
                    cpanel:ea-php[0-9][0-9]-php-fpm.service|cpanel:cpanel_php_fpm.service|cpanel:sw-engine.service|plesk:plesk-php[0-9][0-9]-fpm.service|plesk:sw-engine.service)
                        printf '%s\n' "$unit" >> "$P2S_WORK/services" ;;
                    *)
                        case "$comm" in
                            php*|apache*|httpd*|nginx*|lsphp*|sw-engine*|lshttpd*|frankenphp*)
                                service=; service_count=0
                                case "$comm" in
                                    apache*) [ -x /etc/init.d/apache2 ] && service=apache2 ;;
                                    httpd*) [ -x /etc/init.d/httpd ] && service=httpd ;;
                                    php*fpm*)
                                        for candidate in /etc/init.d/php*-fpm /etc/init.d/php-fpm; do
                                            [ -x "$candidate" ] || continue
                                            service=${candidate##*/}; service_count=$((service_count + 1))
                                        done
                                        [ "$service_count" -eq 1 ] || service= ;;
                                esac
                                if [ -n "$service" ]; then printf 'init:%s\n' "$service" >> "$P2S_WORK/services"
                                else
                                    P2S_BLOCKED=true
                                    p2s_manifest_record service_mapping "$pid|$comm|$executable|${unit:-unknown}|restart_target_unverified"
                                    printf '%s|%s|%s\n' "$comm" "$executable" "${unit:-unknown}" >> "$P2S_WORK/unmapped-services"
                                fi ;;
                        esac ;;
                esac ;;
        esac
        case "$comm" in php*fpm*|sw-engine-fpm*)
            if [ "$parent_executable" != "$executable" ]; then
                printf '%s|%s\n' "$pid" "${executable% (deleted)}" >> "$P2S_WORK/fpm-masters"
            fi ;;
        esac
        printf '%s|%s\n' "$pid" "$executable" >> "$P2S_WORK/processes"
    done
    sort -u "$P2S_WORK/web-restart-advisories" | while IFS='|' read -r comm path; do
        p2s_message_print warn "Separate maintenance: $comm is running an executable that has been replaced on disk ($path). No PHP module was detected in its inspected memory mappings. Review a restart of this web server to load the installed executable and libraries."
    done
    sort -u "$P2S_WORK/web-servers.$P2S_PHASE" -o "$P2S_WORK/web-servers.$P2S_PHASE"
    # Updates/restarts must preserve running web servers; worker PIDs may legitimately change.
    if [ "$P2S_PHASE" = afterfix ] && [ -r "$P2S_WORK/web-servers.beforefix" ] &&
        { ${P2S_TRANSACTION_ATTEMPTED:-false} || ${P2S_RESTART_ATTEMPTED:-false}; }; then
        while IFS= read -r web_server; do
            if grep -Fx -e "$web_server" "$P2S_WORK/web-servers.afterfix" >/dev/null; then
                continue
            else
                comparison_status=$?
                if [ "$comparison_status" -ne 1 ]; then
                    p2s_message_print warn "Could not compare web-server processes before and after the update attempt. Check service status and website availability."
                    break
                fi
            fi
            p2s_manifest_record web_server_missing "$web_server|running_before|not_detected_after"
            p2s_message_print warn "$web_server was running before the update attempt but no $web_server process was detected afterwards. This update is not expected to leave the web server stopped. Check its service status, logs and website availability immediately; restart it if appropriate."
        done < "$P2S_WORK/web-servers.beforefix"
    fi
    # Worker PIDs remain in the manifest; one warning per executable/unit explains the required action.
    awk -F'|' '{ key=$0; count[key]++; name[key]=$1; unit[key]=$3 }
        END {
            for (key in count) {
                advice="This script has no verified restart procedure for this service. Identify the affected application and its safe shutdown and restart procedure before retrying."
                if (unit[key] ~ /^(cron|crond)[.]service$/) advice="Cron launched these PHP tasks, but their package-managed command-line runtime could not be verified. Identify the tasks and PHP installation before updating. Restarting cron does not reliably replace existing tasks; the script will not terminate them."
                if (name[key] ~ /^php.*cgi/) advice="These CGI/FastCGI workers need their launcher or supervising service identified before a restart can be planned. Restarting PHP-FPM alone may not replace them. Automatic updates are blocked until the restart target is verified."
                if (unit[key] ~ /^(supervisor|supervisord)[.]service$/) advice="This script cannot safely restart these Supervisor-managed applications. During maintenance, identify the affected programs using supervisorctl status with the correct configuration and the service_mapping/process_parent records. Stop only those programs and confirm their PHP children stop and stay stopped. Retry --fix, then restore the programs even if patching fails. Verify the applications and rerun --check. Do not stop Supervisor itself or all its programs."
                print "Automatic updating is paused: we could not verify a safe restart method for " name[key] " (" count[key] (count[key]==1 ? " process" : " processes") "; service " unit[key] "). " advice
            }
        }' "$P2S_WORK/unmapped-services" |
        while IFS= read -r label; do p2s_fix_block service_mapping "$label"; done
    if [ -s "$P2S_WORK/scheduled-php" ]; then
        p2s_message_print info "Scheduled background PHP tasks are running (launched by cron, the task scheduler). These recognised package-managed tasks do not block PHP package updates or supported web-service restarts. Already-running tasks keep their loaded PHP code until they finish; after a successful package update, new tasks use the updated executable. Task PIDs, user IDs and start times are in the run manifest."
    fi
    sort -u "$P2S_WORK/services" -o "$P2S_WORK/services"
    if [ "$unreadable_executables" -gt 0 ] || [ "$unreadable_maps" -gt 0 ]; then
        p2s_message_print warn "We could not fully check some running PHP or web-server processes. Rerun the check; if this continues, review process access using the details in the run log."
    fi
    if [ "$unreadable_executables" -eq 0 ] && [ "$unreadable_maps" -eq 0 ] && [ "$(id -u)" = 0 ]; then P2S_PROCESS_USAGE_COMPLETE=true; fi
    p2s_manifest_record process_summary "matched_processes=$process_count|restart_pending=$P2S_RESTART_PENDING"
    p2s_manifest_record web_process_summary "recognised_server=$web_server_found|scope=inspected_process_list"
    if $process_found && ! $web_server_found; then
        p2s_message_print info "No recognised web-server process was detected in the inspected process list."
    fi
    if ! $process_found; then
        if $web_server_found; then
            p2s_message_print info "A recognised web-server process was found. No running PHP process was detected during this check."
        else
            p2s_message_print info "No running PHP or recognised web-server process was detected during this check."
        fi
    elif [ -s "$P2S_WORK/process-runtime-paths" ] && ! $P2S_RESTART_PENDING; then
        p2s_message_print info "No deleted PHP executables or modules were detected in the inspected processes."
    fi
}

# Web listener inventory

p2s_web_listener_inventory_collect() {
    local table family inspected=0 incomplete=false ports
    : > "$P2S_WORK/web-listeners"
    # Linux exposes numeric TCP listeners without needing ss/netstat, even on older VMs.
    # /proc/net/tcp[6]: field 2 is local address:hex-port; field 4 is 0A for LISTEN.
    # This observes our network namespace only, not firewall reachability or PHP use.
    for table in /proc/net/tcp /proc/net/tcp6; do
        family=${table##*/}
        if [ ! -r "$table" ]; then
            p2s_manifest_record web_listener_table "$family|unavailable"
            # tcp6 can be absent when IPv6 is disabled; a missing IPv4 table is a gap.
            if [ "$family" = tcp ] || [ -e "$table" ]; then incomplete=true; fi
            continue
        fi
        if p2s_command_run 10 awk -v family="$family" 'NR>1 && $4=="0A" {
            split($2, address, ":"); port=toupper(address[2]);
            if (port=="0050" || port=="01BB") print family "|" (port=="0050" ? 80 : 443) "|" $2
        }' "$table" > "$P2S_WORK/web-listeners.$family" 2>/dev/null; then
            cat "$P2S_WORK/web-listeners.$family" >> "$P2S_WORK/web-listeners"
            inspected=$((inspected + 1))
            p2s_manifest_record web_listener_table "$family|read"
        else
            incomplete=true
            p2s_manifest_record web_listener_table "$family|read_failed"
        fi
    done
    p2s_manifest_record web_listener_scope 'network_namespace=current|transport=TCP|ports=80,443|source=proc'
    if [ -s "$P2S_WORK/web-listeners" ]; then
        p2s_manifest_record web_listener "$(cat "$P2S_WORK/web-listeners")"
        ports=$(awk -F'|' '{ seen[$2]=1 } END { if (seen[80]) printf "80"; if (seen[443]) printf "%s443", (seen[80] ? " and " : "") }' "$P2S_WORK/web-listeners")
        p2s_message_print info "Listening TCP ports: $ports (current network namespace)."
    elif [ "$inspected" -gt 0 ] && ! $incomplete; then
        p2s_message_print info "No TCP listener on port 80 or 443 was found in the readable host network tables."
    else
        p2s_message_print info "TCP listener information for ports 80 and 443 could not be fully inspected."
    fi
}

# PHP runtime paths, version probes and startup diagnostics

p2s_runtime_path_add() {
    local suffix=''
    # Package lists include cron, init and logrotate definitions named php or sw-engine; never execute them as PHP.
    case "$1" in /etc/cron.*/*|/etc/init.d/*|/etc/logrotate.d/*) return 0 ;; esac
    # RPM and EasyApache sysconfig files configure PHP-FPM; they are not its executable.
    case "$1" in /etc/sysconfig/*|/opt/cpanel/ea-php[0-9][0-9]/root/etc/sysconfig/*) return 0 ;; esac
    # Package lists also contain directories such as /usr/share/php, not PHP executables.
    [ ! -d "$1" ] || return 0
    # Package file lists contain manuals too: never treat php-fpm8.4.8.gz as an engine.
    case "${1##*/}" in
        php-cgi[0-9]*) suffix=${1##*/}; suffix=${suffix#php-cgi} ;;
        php-fpm[0-9]*) suffix=${1##*/}; suffix=${suffix#php-fpm} ;;
        lsphp[0-9]*) suffix=${1##*/}; suffix=${suffix#lsphp} ;;
    esac
    case "$suffix" in *[!0-9.]*) return ;; esac
    # Debian 8 names its engines php5-fpm/php5-cgi; newer Debian uses php-fpm8.4/php-cgi8.4.
    # Match the basename: */php[0-9]* would also match configuration below /etc/php8.4/.
    case "$1" in /*) ;; *) return ;; esac
    case "${1##*/}" in
        php|php[0-9]|php[0-9].[0-9]|php5-cgi|php5-fpm|php-cgi|php-cgi[0-9]*|php-fpm|php-fpm[0-9]*|lsphp|lsphp[0-9]*|sw-engine|sw-engine-fpm|libphp*.so|frankenphp)
            printf '%s\n' "$1" >> "$P2S_WORK/paths.raw" ;;
    esac
}

p2s_runtime_probe_version() {
    # FrankenPHP embeds PHP in a Caddy-based web server; it need not use a separate PHP-FPM service.
    # 'frankenphp version' reports both the server and embedded PHP versions: https://frankenphp.dev/docs/
    # Ordinary PHP uses -n to skip php.ini/configured extensions and -v to report the engine version.
    case "${1##*/}" in
        frankenphp) p2s_command_run 15 "$1" version ;;
        *) p2s_command_run 15 "$1" -n -v ;;
    esac
}

p2s_runtime_report_startup_warnings() {
    if printf '%s\n' "$2" | LC_ALL=C grep -Ei 'PHP (Warning|Fatal error)|PHP Startup:|undefined symbol|Unable to load dynamic library' >/dev/null; then
        p2s_manifest_record php_startup_warning "$1|review_extension_and_shared_library_configuration|CVE_state_unchanged"
        p2s_message_print warn "PHP startup warnings were detected for $1. An extension or shared library may not have loaded, even if the version or configuration command succeeded. Websites using that component may fail. Review the diagnostic output and PHP extension configuration in the run manifest. This warning is separate from PHP2Shell patch status."
    fi
}

p2s_runtime_inventory_collect() {
    local path owner output state version package_version expected actual role built vendor provider resolved reason upstream_state probe_status observation level
    : > "$P2S_WORK/runtime-reviews"
    : > "$P2S_WORK/runtime-package-observations"
    # Software Collections keep parallel PHP versions under /opt/remi or /opt/rh instead of /usr/bin.
    # Bounded conventional locations, panel trees and software collections. No traversal of /home or /.
    for path in /usr/bin/php* /usr/sbin/php* /usr/bin/sw-engine /usr/local/bin/php* /usr/local/sbin/php* /usr/local/bin/lsphp* /usr/local/bin/frankenphp \
        /usr/lib/apache*/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so /usr/lib/cgi-bin/php* \
        /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
        /usr/local/cpanel/3rdparty/bin/php /usr/local/cpanel/3rdparty/php/*/bin/php \
        /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/bin/lsphp /opt/alt/php*/usr/sbin/php-fpm \
        /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm /opt/rh/rh-php*/root/usr/bin/php /opt/rh/rh-php*/root/usr/sbin/php-fpm \
        /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm /opt/php*/bin/php /opt/php*/sbin/php-fpm \
        /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/fcgi-bin/lsphp* \
        /www/server/php/*/bin/php /www/server/php/*/sbin/php-fpm; do
        [ -f "$path" ] && p2s_runtime_path_add "$path"
    done
    sort -u "$P2S_WORK/paths.raw" > "$P2S_WORK/paths"
    while IFS= read -r path; do
        if [ ! -f "$path" ]; then
            owner=$(p2s_package_owner_for_path "$path")
            p2s_manifest_path_record runtime_path "$path" "${owner:-unverified}"
            P2S_UNKNOWN=true
            p2s_manifest_record inventory_gap "runtime_file|$path|missing_or_not_regular"
            printf '|unverified|%s\n' "$path" >> "$P2S_WORK/runtime-package-observations"
            p2s_message_print warn "An inventoried PHP runtime file is missing or is not a regular file: $path. Review the package files and running-process references."
            continue
        fi
        owner=$(p2s_package_owner_for_path "$path")
        p2s_manifest_record runtime "$path|${owner:-unowned}"
        if [ -z "$owner" ]; then
            p2s_manifest_record runtime_source "$path|package_owner=unverified|installation_method=unknown|source_build_not_proven"
        fi
        resolved="$path"
        if p2s_command_exists readlink; then
            output=$(readlink -f "$path" 2>/dev/null)
            [ -z "$output" ] || resolved="$output"
        fi
        package_version=$(awk -F'|' -v name="$owner" '$1 == name { print $2; exit }' "$P2S_WORK/packages")
        vendor=$(awk -F'|' -v name="$owner" '$1 == name { print $4; exit }' "$P2S_WORK/packages")
        provider=$(p2s_package_provider "$owner" "$vendor" "$package_version")
        if [ -z "$owner" ] || ! awk -F'|' -v name="$owner" '$1 == name { found=1 } END { exit !found }' "$P2S_WORK/packages"; then
            P2S_BLOCKED=true
            if [ "$P2S_BACKEND" = unknown ]; then reason=package_inventory_unavailable
            else reason=owner_outside_PHP_inventory
            fi
            printf '%s|%s\n' "$reason" "$provider" >> "$P2S_WORK/runtime-reviews"
        else
            reason=package_owner_identified
        fi
        p2s_manifest_record runtime_identity "$path|$resolved|${owner:-unverified}|$package_version|$provider|$reason"
        observation=executable
        case "$path" in *.so) observation=module ;; esac
        # Match paths, not version numbers: two package publishers can supply the same PHP release.
        # Record the process reference separately; loaded code and website routing need their own checks.
        if [ -s "$P2S_WORK/process-runtime-paths" ] &&
            awk -F'|' -v path="$path" -v resolved="$resolved" '$1 == path || $1 == resolved { found=1 } END { exit !found }' "$P2S_WORK/process-runtime-paths"; then
            observation=running_path
        fi
        p2s_manifest_record runtime_observation "$path|$observation"
        printf '%s|%s|%s\n' "$owner" "$observation" "$path" >> "$P2S_WORK/runtime-package-observations"
        case "$path" in *.so)
            state=$(awk -F'|' -v name="$owner" '$1 == name { print $2; exit }' "$P2S_WORK/package-states" 2>/dev/null)
            if [ -n "$state" ]; then
                actual=$(printf '%s\n' "${package_version#*:}" | sed 's/[^0-9.].*//')
                printf '%s|%s|Apache module||%s|%s|%s|%s|engine_package_assessment\n' "$actual" "$state" "$provider" "$package_version" "$(p2s_version_upstream_state "$package_version")" "$observation" >> "$P2S_WORK/summary-versions"
            else
                P2S_UNKNOWN=true
                p2s_manifest_record inventory_gap "module_version|$path|no_assessed_engine_owner"
                p2s_message_print warn "Could not identify the PHP version in Apache module $path; no assessed PHP engine package owns it."
            fi
            continue ;;
        esac
        if [ ! -x "$path" ]; then
            p2s_manifest_path_record runtime_path "$path" "${owner:-unverified}"
            P2S_UNKNOWN=true
            p2s_manifest_record inventory_gap "runtime_version|$path|not_executable"
            p2s_message_print warn "Cannot read the PHP version: $path is not executable."
            continue
        fi
        # Only runtime executables, never php-config, phpize or package-maintenance helpers.
        case "${path##*/}" in php|php[0-9]|php[0-9].[0-9]|php5-cgi|php5-fpm|php-cgi|php-cgi[0-9]*|php-fpm|php-fpm[0-9]*|lsphp|lsphp[0-9]*|sw-engine|sw-engine-fpm|frankenphp) ;; *) continue ;; esac
        if output=$(p2s_runtime_probe_version "$path" 2>&1); then
            p2s_manifest_record runtime_probe "$path|exit=0"
            # PHP 8.4.27 (cli) ...; FrankenPHP v1.11.1 PHP 8.4.27 Caddy v2.10.2.
            # For FrankenPHP, v1.11.1 is the server version; PHP 8.4.27 is the engine we assess.
            version=$(printf '%s\n' "$output" | sed -n 's/.*PHP \([0-9][^ ,)]*\).*/\1/p' | head -n 1)
            p2s_manifest_record php_version "$path|$output"
            p2s_runtime_report_startup_warnings "$path" "$output"
            if [ -z "$version" ]; then
                P2S_UNKNOWN=true
                p2s_manifest_record inventory_gap "runtime_version|$path|unrecognised_output"
                p2s_message_print warn "The version command for $path completed, but no PHP version could be recognised. Review its output in the run manifest."
                continue
            fi
            upstream_state=$(p2s_version_upstream_state "$version")
            # The owning package's verified backport takes precedence over php -v's upstream number.
            if [ "${path##*/}" != frankenphp ] && [ -n "$owner" ] && awk -F'|' -v name="$owner" '$1 == name { found=1 } END { exit !found }' "$P2S_WORK/packages"; then
                state=$(awk -F'|' -v name="$owner" '$1 == name { print $2; exit }' "$P2S_WORK/package-states" 2>/dev/null)
                expected=$(printf '%s\n' "${package_version#*:}" | sed 's/[^0-9.].*//')
                actual=$(printf '%s\n' "$version" | sed 's/[^0-9.].*//')
                # A selector/wrapper RPM can be 1.0.0 while launching PHP 8.4.27.
                # Compare numeric versions only when the owner was assessed as an engine package.
                if [ "$owner" = sw-engine ]; then
                    # The product revision is not PHP 6.x; preserve it only as separate manifest evidence.
                    state=$upstream_state; [ "$state" = N ] || state='?'
                    reason=embedded_engine_independent_version
                    printf '%s\n' "$owner" >> "$P2S_WORK/embedded-assessed"
                elif [ -z "$state" ]; then
                    state=$upstream_state; [ "$state" = N ] || state='?'
                    P2S_BLOCKED=true
                    reason=owner_is_not_an_assessed_engine
                    p2s_state_include "$state"
                    printf '%s|%s\n' "$reason" "$provider" >> "$P2S_WORK/runtime-reviews"
                elif [ "$actual" != "$expected" ]; then
                    state='?'
                    P2S_UNKNOWN=true
                    reason=engine_package_version_mismatch
                    p2s_fix_block runtime_mismatch "$path reports PHP $version but its package is $package_version; manual verification is required."
                else
                    reason=engine_package_assessment
                fi
            else
                state=$upstream_state
                # Keep package ownership unknown when its package manager is unsupported.
                if [ "$P2S_BACKEND" = unknown ]; then state='?'; fi
                p2s_state_include "$state"
                case "$owner" in frankenphp*) printf '%s\n' "$owner" >> "$P2S_WORK/embedded-assessed" ;; esac
            fi
            [ -n "$state" ] || state='?'
            [ "$state" != '?' ] || P2S_UNKNOWN=true
            role='PHP executable'
            case "$output" in
                *'(cli)'*) role='command line' ;; *'(cgi-fcgi)'*) role=CGI ;; *'(fpm-fcgi)'*) role=PHP-FPM ;;
            esac
            built=$(printf '%s\n' "$output" | sed -n 's/.*(built: \([^)]*\)).*/\1/p' | head -n 1)
            actual=$(printf '%s\n' "$version" | sed 's/[^0-9.].*//')
            p2s_manifest_record runtime_assessment "$path|$owner|$version|$package_version|$provider|$state|$reason|upstream=$upstream_state"
            # A wrapper's revision is not a PHP revision; keep it in runtime_assessment only.
            case "$reason" in owner_is_not_an_assessed_engine|engine_package_version_mismatch|embedded_engine_independent_version) package_version= ;; esac
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$actual" "$state" "$role" "$built" "$provider" "$package_version" "$upstream_state" "$observation" "$reason" >> "$P2S_WORK/summary-versions"
        else
            probe_status=$?
            P2S_UNKNOWN=true
            p2s_manifest_path_record runtime_path "$path" "${owner:-unverified}"
            # Keep loader/wrapper errors as data, never as customer or protocol messages.
            p2s_manifest_record runtime_probe "$path|exit=$probe_status"
            p2s_manifest_record runtime_error "$path|$output"
            if [ "$owner" = ea-php-cli ] && [ "$probe_status" -eq 2 ] && [ "$output" = 'Default PHP is not configured!' ]; then
                p2s_message_print warn "cPanel's command-line PHP selector at $path has no default PHP version configured, so this command cannot run PHP. Configure the default in WHM's MultiPHP Manager. Installed versioned PHP runtimes are checked separately."
            else
                p2s_message_print warn "Could not obtain a PHP version from $path (exit $probe_status; 124 means timeout). Review this executable's startup error in the diagnostic output; missing libraries or runtime configuration may need repair."
            fi
        fi
    done < "$P2S_WORK/paths"
    if [ -r "$P2S_WORK/embedded-pending" ]; then
        while IFS= read -r owner; do
            if ! grep -Fx -e "$owner" "$P2S_WORK/embedded-assessed" >/dev/null 2>&1; then
                P2S_UNKNOWN=true
                p2s_manifest_record inventory_gap "embedded_PHP_version|$owner|no_successful_probe"
                p2s_message_print warn "Could not identify the PHP version embedded in $owner."
            fi
        done < "$P2S_WORK/embedded-pending"
    fi
    sort -u "$P2S_WORK/runtime-reviews" | while IFS='|' read -r reason provider; do
        level=warn
        if p2s_state_has_only_fixed_versions; then level=info; fi
        case "$reason" in
            package_inventory_unavailable) continue ;; # The package-inventory warning already explains this gap.
            owner_is_not_an_assessed_engine)
                p2s_fix_block runtime_owner "$provider: PHP executables belong to a selector or other package rather than a PHP engine package. Automatic updates require a separate procedure." "$level" ;;
            *) p2s_fix_block custom_runtime "$provider: PHP files have no inventoried PHP engine owner. Automatic updates require a separate procedure; paths and ownership details are in the run manifest." "$level" ;;
        esac
    done
    if [ ! -s "$P2S_WORK/paths" ] && [ "$P2S_COUNT" -gt 0 ]; then
        P2S_UNKNOWN=true
        p2s_message_print warn "PHP packages were found but their runtime files were not identified."
    fi
}

# Service validation, restarts and worker replacement

p2s_service_plesk_web_socket_verified() {
    local properties fragment overrides owner checksum
    [ "${P2S_PANEL:-}" = plesk ] && [ "${P2S_BACKEND:-}" = deb ] || return 1
    p2s_command_exists systemctl && p2s_command_exists sha256sum || return 1
    properties=$(p2s_command_run 30 systemctl show plesk-web-socket.service -p FragmentPath -p DropInPaths) || return 1
    fragment=$(printf '%s\n' "$properties" | sed -n 's/^FragmentPath=//p')
    overrides=$(printf '%s\n' "$properties" | sed -n 's/^DropInPaths=//p')
    [ -z "$overrides" ] && printf '%s\n' "$properties" | grep -Fx 'DropInPaths=' >/dev/null || return 1
    case "$fragment" in /lib/systemd/system/plesk-web-socket.service|/usr/lib/systemd/system/plesk-web-socket.service) ;; *) return 1 ;; esac
    owner=$(p2s_package_owner_for_path "$fragment") || return 1
    case "$owner" in plesk-web-socket|plesk-web-socket:amd64) ;; *) return 1 ;; esac
    checksum=$(sha256sum "$fragment" 2>/dev/null) || return 1
    # Reviewed Debian 11/12 vendor unit; changed units need another review, not a guessed restart.
    [ "${checksum%% *}" = 74fce302ab0d79255587ebdf271d705b3d2a5bab7a630e80faab62d1e02680fe ] || return 1
    p2s_manifest_record service_unit_verified 'plesk-web-socket.service|vendor_unit_sha256|no_dropins|plesk-web-socket_package'
}

p2s_service_check_config() {
    local label="$1" status argument redaction='
s@https\{0,1\}://[^[:space:]]*@[URL redacted]@g
s@ftp://[^[:space:]]*@[URL redacted]@g
/[Pp][Aa][Ss][Ss]/s/.*/[sensitive diagnostic redacted]/
/[Tt][Oo][Kk][Ee][Nn]/s/.*/[sensitive diagnostic redacted]/
/[Ss][Ee][Cc][Rr][Ee][Tt]/s/.*/[sensitive diagnostic redacted]/'
    shift
    # Arguments and errors stay in the manifest, never masquerading as customer/protocol messages.
    for argument in "$@"; do
        p2s_manifest_record configtest_argument "$(printf '%s\n' "$argument" | sed "$redaction")"
    done
    p2s_command_run 30 "$@" > "$P2S_WORK/configtest" 2>&1
    status=$?
    p2s_manifest_record configtest_exit "$label|$status"
    p2s_manifest_record configtest_output "$(sed "$redaction" "$P2S_WORK/configtest")"
    case "$label" in PHP-FPM*) p2s_runtime_report_startup_warnings "$label" "$(cat "$P2S_WORK/configtest")" ;; esac
    if [ "$status" -ne 0 ]; then
        p2s_fix_block configtest "$label configuration validation failed (exit $status; 124 means timeout). Review the validation details in the run manifest and service logs before retrying."
        return 1
    fi
}

p2s_service_fpm_preflight() {
    local pid="$1" path="$2" argument config='' need_value=false path_value=false
    local arguments
    arguments=()
    if [ ! -x "$path" ] || [ ! -r "/proc/$pid/cmdline" ]; then
        p2s_fix_block configtest "Cannot inspect the active PHP-FPM executable or startup arguments (PID $pid); manual validation is required."
        return 1
    fi
    # FPM normally replaces argv with its master title, including the effective FPM config path.
    # Otherwise retain supported config options from NUL-separated argv, without evaluating shell text.
    while IFS= read -r -d '' argument; do
        if [ "${#arguments[@]}" -eq 0 ]; then
            case "$argument" in
                'php-fpm: master process ('*')'|'sw-engine-fpm: master process ('*')')
                    config=${argument#*': master process ('}; config=${config%')'}
                    # Never silently fall back to a compiled-in default after a malformed master title.
                    case "$config" in /*) ;; *) p2s_fix_block configtest "PHP-FPM reports a missing or non-absolute configuration path; manual validation is required."; return 1 ;; esac
                    if [ ! -r "$config" ]; then p2s_fix_block configtest "The active PHP-FPM configuration cannot be read; manual validation is required."; return 1; fi
                    arguments=("$path" -y "$config")
                    break ;;
                'php-fpm:'*|'sw-engine-fpm:'*) p2s_fix_block configtest "Unrecognised PHP-FPM master title (PID $pid); manual validation is required."; return 1 ;;
                *) arguments=("$path"); continue ;;
            esac
        fi
        if $need_value; then
            if $path_value; then
                case "$argument" in /*) ;; *) p2s_fix_block configtest "Relative PHP-FPM configuration paths require manual validation (PID $pid)."; return 1 ;; esac
            fi
            arguments[${#arguments[@]}]="$argument"; need_value=false; continue
        fi
        case "$argument" in
            -y|--fpm-config|-c|--php-ini|-p|--prefix|-d|--define)
                arguments[${#arguments[@]}]="$argument"; need_value=true; path_value=true
                case "$argument" in -d|--define) path_value=false ;; esac ;;
            -y/*|-c/*|-p/*|--fpm-config=/*|--php-ini=/*|--prefix=/*|-d?*|--define=*|-n|--no-php-ini|-R|--allow-to-run-as-root)
                arguments[${#arguments[@]}]="$argument" ;;
            -D|--daemonize|-F|--nodaemonize|-O|--force-stderr) ;;
            *) p2s_fix_block configtest "Unsupported PHP-FPM startup arguments (PID $pid); manual validation is required."; return 1 ;;
        esac
    done < "/proc/$pid/cmdline"
    if $need_value || [ "${#arguments[@]}" -eq 0 ]; then
        p2s_fix_block configtest "Incomplete PHP-FPM startup arguments (PID $pid); manual validation is required."
        return 1
    fi
    p2s_service_check_config "PHP-FPM (PID $pid)" "${arguments[@]}" -t
}

p2s_service_preflight() {
    local unit control pid path
    if [ ! -s "$P2S_WORK/services" ]; then return 0; fi
    # Only active FPM masters are tested; installed unused engines and package manuals are not services.
    if [ -s "$P2S_WORK/fpm-masters" ]; then
        while IFS='|' read -r pid path; do
            p2s_service_fpm_preflight "$pid" "$path" || return 1
        done < "$P2S_WORK/fpm-masters"
    fi
    while IFS= read -r unit; do
        case "$unit" in *.service)
            if ! p2s_command_exists systemctl || [ ! -d /run/systemd/system ]; then
                p2s_fix_block restart_backend "A service requires systemd but it is unavailable; manual review is required."
                return 1
            fi ;;
        esac
        case "$unit" in
            plesk-web-socket.service)
                p2s_service_plesk_web_socket_verified || {
                    p2s_fix_block service_unit "The Plesk Web Socket service differs from the reviewed vendor unit or has overrides; its restart needs review."
                    return 1
                }
                continue ;;
            apache2.service|init:apache2) control=apache2ctl ;;
            httpd.service|init:httpd) control=apachectl ;;
            *) continue ;;
        esac
        if ! p2s_command_exists "$control"; then
            p2s_fix_block configtest "Apache configuration validation is unavailable; refusing an unattended update/restart."
            return 1
        fi
        p2s_service_check_config Apache "$control" -t || return 1
    done < "$P2S_WORK/services"
}

# P2S-MUTATION: Service action dispatcher; restart changes live services, status only probes them.
p2s_service_run() {
    local unit="$1" action="$2"
    if [ "$unit:$action" = plesk-web-socket.service:restart ]; then
        p2s_service_plesk_web_socket_verified || return 1
    fi
    case "$unit" in
        *.service)
            if [ "$action" = status ]; then p2s_command_run 30 systemctl is-active --quiet "$unit"
            else p2s_command_run 120 systemctl "$action" "$unit" # P2S-MUTATION: Applies the requested service action.
            fi ;;
        init:*)
            if p2s_command_exists service; then p2s_command_run 120 service "${unit#init:}" "$action" # P2S-MUTATION: Restarts for action=restart; status is a probe.
            else p2s_command_run 120 "/etc/init.d/${unit#init:}" "$action" # P2S-MUTATION: Direct init-script restart/status fallback.
            fi ;;
        *) return 1 ;;
    esac
}

# P2S-MUTATION: Restarts the saved PHP-serving services and verifies worker replacement.
p2s_service_restart_and_verify() {
    local unit pid executable failed=false
    while IFS= read -r unit; do
        p2s_message_print info "Restarting $unit to replace PHP workers."
        P2S_RESTART_ATTEMPTED=true
        # P2S-MUTATION: Requests the restart; the following status call only verifies it.
        if ! p2s_service_run "$unit" restart > "$P2S_WORK/restart.log" 2>&1 || ! p2s_service_run "$unit" status > /dev/null 2>&1; then
            p2s_fix_block restart "Could not restart and verify $unit; check the service configuration and logs."
            failed=true
        else
            p2s_message_print fixmethod "Restarted $unit and confirmed it is active."
        fi
    done < "$P2S_WORK/services.before"
    # Recheck original worker identities after the service command completes.
    while IFS='|' read -r pid executable; do
        case "$executable" in */nginx*) continue ;; esac
        if [ -e "/proc/$pid/exe" ]; then
            p2s_fix_block old_worker "A previously running PHP/web worker (PID $pid) remains after restart; manual verification is required."
            failed=true
        fi
    done < "$P2S_WORK/processes.before"
    if $failed; then return 1; fi
}

# Customer summaries

p2s_summary_print_versions() {
    local level message prefix=
    ${P2S_RETRY_ASSESSMENT:-false} && return 0
    if [ "${P2S_MODE:-check}" = fix ]; then
        prefix='Initial check: '
        if [ "$P2S_PHASE" = afterfix ] &&
            { ${P2S_TRANSACTION_ATTEMPTED:-false} || ${P2S_RESTART_ATTEMPTED:-false}; }; then
            prefix='After update attempt: '
            if [ -n "${P2S_UPDATE_METHOD:-}" ]; then prefix="After update attempt ($P2S_UPDATE_METHOD): "
            elif ${P2S_RESTART_ATTEMPTED:-false}; then prefix='After service restart attempt: '
            fi
        fi
    fi
    # Keep package publishers separate: fixed EasyApache and unverified panel PHP can report the same version.
    # Unknown builds show package revisions and the missing evidence; full paths/output remain in the manifest.
    [ -s "$P2S_WORK/summary-versions" ] || return 0
    sort -u "$P2S_WORK/summary-versions" | awk -F'|' -v prefix="$prefix" '
        {
            key=$1 SUBSEP $2 SUBSEP $5
            # A backport changes the package build while php -v can stay unchanged.
            if ($5 ~ /^Sury\//) key=key SUBSEP $6
            if (!(key in version)) { order[++count]=key; version[key]=$1; state[key]=$2; provider[key]=$5 }
            if (!seen_role[key SUBSEP $3]++) roles[key]=roles[key] (roles[key] ? ", " : "") $3
            if ($7 == "Y") affected_upstream[key]=1
            if ($2 == "Y" && $7 == "?") presumed_affected[key]=1
            if ($8 != "") evidence[key SUBSEP $8]=1
            if ($6 != "" && !seen_revision[key SUBSEP $6]++) revisions[key]=revisions[key] (revisions[key] ? ", " : "") $6
            if ($9 != "") reasons[key SUBSEP $9]=1
            if ($10 != "" && !seen_package[key SUBSEP $10]++) packages[key]=packages[key] (packages[key] ? ", " : "") $10
            if ($11 != "" && !seen_fixed[key SUBSEP $11]++) fixed_builds[key]=fixed_builds[key] (fixed_builds[key] ? ", " : "") $11
        }
        END {
            for (i=1; i<=count; i++) {
                key=order[i]; level="info"; conclusion="fixes verified for both PHP2Shell vulnerabilities."
                if (state[key]=="Y") { level="warn"; conclusion="vulnerable; update these components and restart the services using them." }
                if (state[key]=="Y" && presumed_affected[key])
                    conclusion="presumed vulnerable because this stock CentOS 5 PHP package predates the PHP2Shell fixes and has no verified backport. Migrate applications to maintained, patched PHP. Exploitability has not been tested."
                if (state[key]=="?") { level="warn"; conclusion="patch status not verified." }
                split(version[key], parts, "[.]")
                if (state[key]=="?" && version[key] ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ &&
                    (parts[1]<5 || (parts[1]==5 && parts[2]<4)))
                    conclusion="outside this detector\047s verified PHP2Shell coverage; review its security support and migrate applications to maintained, patched PHP."
                text=prefix "PHP " version[key] " (" roles[key] "): " conclusion
                source=provider[key]; sub(/ [(](revision|namespace) hint[)]$/, "", source)
                if (source) text=text " Package publisher: " source "."
                if (packages[key]) text=text " Installed packages: " packages[key] "."
                if (provider[key] ~ /^Sury\// && revisions[key]) text=text " Installed package build: " revisions[key] "."
                if (state[key]=="N" && affected_upstream[key]) text=text " The PHP package publisher added the security fixes without changing the PHP version."
                if (state[key]=="?") {
                    if (provider[key] !~ /^Sury\// && revisions[key]) text=text " Installed package build: " revisions[key] "."
                    if (reasons[key SUBSEP "engine_package_version_mismatch"])
                        text=text " The executable reports a different PHP version from its owning package; check the runtime mismatch warning."
                    else if (reasons[key SUBSEP "package_inventory_unavailable"])
                        text=text " Package inventory is unavailable, so the installed build and any vendor security fixes could not be checked."
                    else if (reasons[key SUBSEP "owner_is_not_an_assessed_engine"] || reasons[key SUBSEP "owner_outside_PHP_inventory"])
                        text=text " No assessed PHP engine package owns this executable; confirm its installation source and security fixes."
                    else if (reasons[key SUBSEP "sury_build_older"])
                        text=text " The installed Sury package build is older than this check\047s verified fixed build: " fixed_builds[key] ". The installed build is not on this check\047s list of verified patched packages."
                    else if (reasons[key SUBSEP "sury_build_newer"])
                        text=text " The installed Sury package build is newer than this check\047s verified fixed build: " fixed_builds[key] ". This particular build has not been verified."
                    else if (reasons[key SUBSEP "sury_build_equal"])
                        text=text " The package revision compares equal to the verified fixed Sury build: " fixed_builds[key] ". Its exact build and source identity did not match a reviewed package."
                    else if (reasons[key SUBSEP "sury_build_tool_unavailable"])
                        text=text " The dpkg version-comparison tool is unavailable; the reviewed fixed Sury build is " fixed_builds[key] "."
                    else if (reasons[key SUBSEP "sury_build_failed"])
                        text=text " dpkg could not compare the installed package version with the reviewed fixed Sury build: " fixed_builds[key] "."
                    else if (reasons[key SUBSEP "sury_build_not_compared"])
                        text=text " No reviewed fixed Sury build could be compared for this OS release, architecture and package."
                    else if (affected_upstream[key])
                        text=text " This PHP release needs security fixes from its package publisher. This script has no verified fix record for the installed build. Check both CVEs with the publisher or install a confirmed fixed build."
                    else text=text " No verified version or package fix rule matches this build; check both CVEs with its publisher."
                }
                if (state[key]=="Y" && provider[key]=="AlmaLinux") text=text " AlmaLinux has published security updates for this PHP stream; check your configured package sources for an available fix."
                if (evidence[key SUBSEP "running_path"]) text=text " Running processes use this installation."
                else if (evidence[key SUBSEP "executable"]) text=text " Installed; no matching running process was found."
                else if (evidence[key SUBSEP "module"]) text=text " Apache module installed; no matching running process was found."
                else if (evidence[key SUBSEP "package"]) text=text " Checked installed packages; no PHP executable or Apache module was matched."
                print level "|" text
            }
        }' | while IFS='|' read -r level message; do p2s_message_print "$level" "$message"; done
}

p2s_summary_print_result() {
    local unresolved_versions
    # This describes the final phase only; before/after protocol markers remain unchanged.
    case "$P2S_STATE" in
        Y) p2s_message_print warn "Result: This VM has at least one PHP installation identified as vulnerable to PHP2Shell. Update every affected installation and restart the services using it. If a prompt fix is not possible, temporarily disable the affected PHP applications." ;;
        '?')
            # Package and executable checks can disagree within one installation; describe component evidence.
            if p2s_state_has_only_fixed_versions; then
                if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}; then
                    p2s_message_print warn "Result: Verified host PHP builds include both PHP2Shell fixes. PHP in a separate application environment still needs checking; see the warnings below."
                else
                    p2s_message_print warn "Result: Verified PHP builds include both PHP2Shell fixes. We could not complete all checks; see the warnings below."
                fi
                p2s_manifest_record verification_scope "assessed_host_versions=fixed|separate_environment_review=${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}|overall=unknown"
            elif [ -s "$P2S_WORK/summary-versions" ] && awk -F'|' '
                $2 == "N" { fixed=1 } $2 == "?" { unverified=1 }
                END { exit !(fixed && unverified) }' "$P2S_WORK/summary-versions"; then
                p2s_message_print warn "Result: Some PHP installations include both PHP2Shell fixes; others still need verification or an update. See the PHP versions needing attention below."
            else
                p2s_message_print warn "Result: We could not verify whether all PHP installations include both PHP2Shell fixes. See the checks needing attention below."
            fi ;;
        N)
            if [ "$P2S_COUNT" -eq 0 ]; then
                p2s_message_print info "Result: No PHP installation was found in the checked packages and runtime locations. No PHP update was identified by this check."
            else
                p2s_message_print info "Result: All detected PHP installations include both PHP2Shell fixes. No PHP restart is pending."
            fi ;;
    esac
    if [ "$P2S_STATE" != N ] && [ -s "$P2S_WORK/summary-versions" ]; then
        # Check package publisher support for unverified backports; migrate sites/jobs explicitly when a branch lacks a supported fix.
        unresolved_versions=$(sort -u "$P2S_WORK/summary-versions" | awk -F'|' '
            $1 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ {
                split($1, parts, "[.]"); branch=parts[1] "." parts[2]
                if (!seen_branch[branch]++) branches++
                if ($2 != "N" && !seen_version[$1]++) versions=versions (versions ? ", " : "") "PHP " $1
            }
            END { if (branches > 1 && versions != "") print versions }')
        if [ -n "$unresolved_versions" ]; then
            p2s_message_print warn "PHP versions needing attention: $unresolved_versions. If your configured PHP package sources cannot supply a fixed package, move the affected websites, applications and scheduled jobs to a supported, patched PHP version. Test them before removing old PHP packages. Changing the default PHP version alone does not move individual websites."
        fi
    fi
    case "$P2S_STATE" in
        Y|'?') p2s_message_print info "RimuHosting offers a no-cost, no-obligation investigation and a report on mitigation or migration to a server with a supported OS and PHP, including for servers hosted elsewhere. A server migration can stay with your current hosting provider. Contact RimuHosting to coordinate the server manifest and investigation. Any changes or further work are agreed separately." ;;
    esac
}

# Inventory and fix orchestration

p2s_inventory_collect_and_assess() {
    P2S_INVENTORY_MESSAGES=true
    P2S_COUNT=0; P2S_VULNERABLE=false; P2S_UNKNOWN=${P2S_FIX_FAILED:-false}; P2S_RESTART_PENDING=false
    P2S_SEPARATE_ENVIRONMENT_REVIEW=false; P2S_PACKAGE_POLICY_REVIEW=false
    : > "$P2S_WORK/paths.raw"
    p2s_package_inventory_collect
    p2s_panel_inventory_collect
    p2s_package_sources_collect
    p2s_package_release_report
    p2s_repository_sury_installed_source_report
    p2s_package_inventory_assess
    p2s_process_inventory_collect
    p2s_web_listener_inventory_collect
    p2s_runtime_inventory_collect
    p2s_process_scheduled_php_verify
    p2s_package_release_usage_report
    if [ "$(id -u)" != 0 ]; then P2S_UNKNOWN=true; p2s_message_print warn "A root check is required to inspect all PHP workers."; fi
    if $P2S_RESTART_PENDING; then p2s_message_print warn "A relevant process still uses a deleted executable or PHP module; a restart needs verification."; fi
    # All inventoried versions/interfaces (CLI, FPM, Apache module, embedded PHP) share one CVE marker.
    # Any known vulnerable installation wins; otherwise unknown evidence prevents a clean result.
    if $P2S_VULNERABLE; then P2S_STATE=Y
    elif $P2S_UNKNOWN; then P2S_STATE='?'
    else P2S_STATE=N
    fi
    p2s_manifest_record aggregate "$P2S_STATE|runtime_packages=$P2S_COUNT|restart_pending=$P2S_RESTART_PENDING"
    p2s_summary_print_versions
    p2s_package_rpm_stream_guidance_report
    P2S_INVENTORY_MESSAGES=false
}

p2s_fix_block() {
    P2S_BLOCKED=true
    if [ "${P2S_ASSESSMENT_ONLY:-false}" != true ] && [ -n "${P2S_WORK:-}" ] && [ -d "$P2S_WORK" ]; then printf '%s\n' "$1" >> "$P2S_WORK/blocker-keys"; fi
    p2s_message_print "${3:-warn}" "$2"
    p2s_manifest_record blocker "$1|$2"
}

p2s_fix_check_distro_recipe() {
    local name version arch vendor sury_engine=false
    # A complete negative PHP inventory needs no update recipe. An incomplete inventory must still warn.
    if [ "${P2S_STATE:-?}" = N ] && [ "${P2S_COUNT:-0}" -eq 0 ]; then
        p2s_manifest_record update_recipe 'not_needed|no_php_detected_in_checked_scope'
        return 0
    fi
    # Snapshot 2026-10-22. Entitled Ubuntu ESM may still supply packages on old LTSs.
    case "$P2S_DISTRO:$P2S_MAJOR" in
        arch:*)
            p2s_fix_block update_recipe "Automatic updates are not implemented for Arch Linux. Arrange a reviewed system upgrade using pacman; Arch does not support partial package upgrades."
            return 1 ;;
        debian:*)
            [ "$P2S_MAJOR" -ge 12 ] && return 0
            if [ "$P2S_MAJOR" -eq 11 ] && [ "${P2S_BACKEND:-}" = deb ] && [ -r "$P2S_WORK/packages" ]; then
                if ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
                    p2s_manifest_record update_recipe 'debian11|explicit_Sury_migration|migration_candidate_and_restart_checks_required'
                    return 0
                fi
                while IFS='|' read -r name version arch vendor; do
                    case "${name%:*}" in php|php[0-9]|php[0-9].[0-9]|php-common|php-cli|php-cgi|php-fpm|php-phpdbg|libapache2-mod-php) continue ;; esac
                    p2s_package_is_engine "$name" || continue
                    if [ "$arch" != amd64 ] || ! p2s_package_deb_is_sury "$version"; then sury_engine=false; break; fi
                    sury_engine=true
                done < "$P2S_WORK/packages"
                if $sury_engine; then
                    p2s_manifest_record update_recipe 'debian11|existing_Sury_engines_only|amd64|candidate_and_restart_checks_required'
                    return 0
                fi
            fi ;;
        ubuntu:*)
            case "$P2S_RELEASE" in
                22.04|24.04|26.04|26.10) return 0 ;;
                14.04|16.04|18.04|20.04)
                    p2s_message_print warn "This Ubuntu release needs the appropriate extended-support entitlement for PHP fixes."
                    return 0 ;;
            esac ;;
        almalinux:*|rocky:*|rhel:*|ol:*) [ "$P2S_MAJOR" -ge 8 ] && return 0 ;;
        centos:*) [ "$P2S_MAJOR" -ge 9 ] && return 0 ;;
    esac
    p2s_fix_block unsupported_os "No automatic update recipe for $P2S_DISTRO $P2S_RELEASE is implemented in this script. Check maintained package sources for a suitable fix; archived repositories retain historical packages."
    return 1
}

# These local probes do not refresh repositories, install packages or restart services.
# Fix mode repeats them because a saved check is not permission to bypass changing prerequisites.
p2s_fix_preflight() {
    local low_space name version arch vendor
    if $P2S_BLOCKED; then return 1; fi
    if ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        if [ "$P2S_BACKEND" != deb ]; then
            p2s_fix_block provider_migration "The Sury migration method requires native Debian/Ubuntu packages; no change between package formats or RPM package publishers is implemented."
            return 1
        fi
        p2s_disruptive_sury_validate_equivalents || return 1
    fi
    case "${P2S_PANEL:-}:$P2S_BACKEND" in
        cpanel:deb|plesk:deb)
            while IFS='|' read -r name version arch vendor; do
                if p2s_package_deb_is_sury "$version"; then
                    p2s_fix_block candidate_provider "Sury PHP and a panel vendor updater were both detected. Their combined transaction needs review before any panel or PHP updates."
                    return 1
                fi
            done < "$P2S_WORK/packages" ;;
    esac
    if ! p2s_command_has_timeout && ! p2s_command_has_shell_watchdog; then
        p2s_fix_block watchdog "Neither the timeout command nor the embedded Bash/sleep watchdog is available; automatic updates are disabled."
        return 1
    fi
    [ "$(id -u)" = 0 ] || { p2s_fix_block privileges "Root access is required for package updates and service restarts."; return 1; }
    if p2s_command_exists df; then
        if ! p2s_command_run 10 df -Pk / /var /usr /tmp > "$P2S_WORK/fix-disk" 2>/dev/null; then
            p2s_fix_block disk_check "Free disk space could not be checked; manual review is required."
            return 1
        fi
        p2s_manifest_record disk_preflight "$(cat "$P2S_WORK/fix-disk")"
        if ! awk 'NR > 1 && $4 ~ /^[0-9]+$/ && $4 < 131072 { low=1 } END { exit low }' "$P2S_WORK/fix-disk"; then
            # df -Pk row: /dev/root 12582912 12582912 0 100% / ; columns 4/6 give free KiB and mount.
            low_space=$(awk '
                NR>1 && $4 ~ /^[0-9]+$/ && $4<131072 && !seen[$1 SUBSEP $6]++ {
                    printf "%s%s (%s): %s KiB available", separator, $6, $1, $4; separator="; "
                }' "$P2S_WORK/fix-disk")
            p2s_fix_block disk_space "Insufficient free space for a PHP update: $low_space. At least 128 MiB free is required on the checked system filesystems; larger updates may need more. Free space or check whether an enlarged VM disk still needs its partition/filesystem grown, then retry."
            return 1
        fi
    fi
    [ -s "$P2S_WORK/packages" ] || { p2s_fix_block no_packages "There are no identified PHP packages this script can update."; return 1; }
    case "$P2S_BACKEND" in
        deb) p2s_command_exists apt-get || { p2s_fix_block apt_missing "apt-get is unavailable; cannot update Debian PHP packages."; return 1; } ;;
        rpm) p2s_command_exists dnf || p2s_command_exists yum || { p2s_fix_block rpm_manager "Neither dnf nor yum is available; cannot update RPM PHP packages."; return 1; } ;;
        *) p2s_fix_block package_backend "No supported package manager was identified for an automatic PHP update."; return 1 ;;
    esac
    p2s_service_preflight || return 1
}

p2s_package_lock_warn() {
    local locks file metadata device inode identity pid details parent elapsed name age warned_key
    [ -r /proc/locks ] || return 0
    # Snapshot actual kernel locks; file age and an open descriptor are not lock ownership.
    locks=$(</proc/locks)
    [ -n "$locks" ] || return 0
    for file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
        [ -e "$file" ] || continue
        metadata=$(p2s_command_run 5 stat -Lc '%d %i' "$file" 2>/dev/null) || continue
        read -r device inode <<EOF
$metadata
EOF
        case "$device" in ''|*[!0-9]*) continue ;; esac
        case "$inode" in ''|*[!0-9]*) continue ;; esac
        # Linux dev_t packs the major in bits 8..19 and the minor in bits 0..7 and 20..31.
        identity=$(printf '%02x:%02x:%s' "$(((device >> 8) & 4095))" "$(((device & 255) | ((device >> 12) & 1048320)))" "$inode")
        # 12: POSIX ADVISORY WRITE 4242 08:01:12345 0 EOF -> owner 4242; skip -> waiters.
        for pid in $(printf '%s\n' "$locks" | awk -v identity="$identity" '
            $2 == "POSIX" && $4 == "WRITE" && $5 ~ /^[0-9]+$/ && $5 > 1 && $6 == identity {print $5}
        '); do
            warned_key="|$file:$pid|"
            case "${P2S_PACKAGE_LOCK_WARNED:-}" in *"$warned_key"*) continue ;; esac
            details=$(LC_ALL=C p2s_command_run 5 ps -p "$pid" -o ppid= -o etime= -o comm= 2>/dev/null) || continue
            read -r parent elapsed name <<EOF
$details
EOF
            case "$parent" in ''|*[!0-9]*) continue ;; esac
            age=$(printf '%s\n' "$elapsed" | awk '
                # ps etime: 35-02:03:04 -> 3031384 seconds; 05:00 -> 300 seconds.
                /^[0-9]+(-[0-9]+)?:[0-9][0-9](:[0-9][0-9])?$/ {
                    days=0; value=$0
                    if (index(value,"-")) {split(value,d,"-"); days=d[1]; value=d[2]}
                    count=split(value,t,":")
                    seconds=days*86400+t[count]+t[count-1]*60
                    if (count==3) seconds+=t[1]*3600
                    if (seconds>=3600) printf "%.0f",seconds
                }
            ')
            [ -n "$age" ] || continue
            name=$(printf '%s' "$name" | LC_ALL=C tr -c '[:print:]' '?')
            P2S_PACKAGE_LOCK_WARNED="${P2S_PACKAGE_LOCK_WARNED:-}$warned_key"
            p2s_manifest_record package_manager_long_running_lock "$file|pid=$pid|ppid=$parent|owner_elapsed=$elapsed|owner_seconds=$age|command=$name|lock_acquired_at=unavailable"
            p2s_message_print warn "Package lock $file is held by PID $pid ($name, parent $parent), running for $elapsed (warning threshold: 1 hour). Lock acquisition time is unavailable. Check its progress before stopping it."
            p2s_message_print warn "Recheck the owner: ps -p $pid -o pid,ppid,etime,stat,comm; lslocks. If confirmed stuck and still holding the lock, stop it with: kill -TERM $pid. Interrupting package installation/configuration can leave packages unfinished. No process was stopped and no lock file was removed."
        done
    done
    return 0
}

# A package lock file can exist without an owner. fuser supplies a conservative open-file check.
p2s_package_lock_probe() {
    local file status=0 observed busy=false timeout=5 remaining
    [ "${P2S_BACKEND:-}" = deb ] && p2s_command_exists fuser || return 2
    for file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
        [ -e "$file" ] || continue
        if [ -n "${P2S_PACKAGE_LOCK_WAIT_DEADLINE:-}" ]; then
            remaining=$((P2S_PACKAGE_LOCK_WAIT_DEADLINE - SECONDS))
            [ "$remaining" -gt 0 ] || return 1
            if [ "$remaining" -lt 5 ]; then timeout=$remaining; else timeout=5; fi
        fi
        status=0
        p2s_command_run "$timeout" fuser "$file" > "$P2S_WORK/lock-pids" 2> "$P2S_WORK/lock-query.err" || status=$?
        if [ "$status" -eq 0 ]; then
            busy=true
            observed=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) printf "%s%s",separator,$i; separator=" "}' "$P2S_WORK/lock-pids")
            p2s_manifest_record package_lock "$file|open_by_process=$observed|conservative_open_file_probe"
        elif [ "$status" -ne 1 ] || [ -s "$P2S_WORK/lock-query.err" ]; then
            p2s_manifest_record package_lock_gap "$file|probe_exit=$status"
            return 2
        fi
    done
    ! $busy
}

p2s_package_lock_wait() {
    local remaining=${P2S_PACKAGE_LOCK_WAIT_SECONDS:-0} status=0
    [ "$remaining" -gt 0 ] || return 0
    # Bash's elapsed timer includes time spent probing; slow probes must not extend every retry.
    local P2S_PACKAGE_LOCK_WAIT_DEADLINE=$((SECONDS + remaining))
    p2s_message_print info "Waiting up to $remaining seconds for other package operations; no process or lock file will be removed."
    while :; do
        status=0; p2s_package_lock_probe || status=$?
        [ "$status" -ne 0 ] || return 0
        if [ "$status" -eq 2 ]; then
            p2s_fix_block package_lock_probe "Package-lock waiting requires a working fuser probe on an APT system; no update was attempted."; return 1
        fi
        remaining=$((P2S_PACKAGE_LOCK_WAIT_DEADLINE - SECONDS))
        if [ "$remaining" -le 0 ]; then
            p2s_fix_block package_manager_busy "A package lock file remains open after the requested wait; retry after the owning package operation finishes."; return 1
        fi
        p2s_command_run 2 sleep 1 || return 1
    done
}

# Do not discard other runtime, OS, ownership or service blockers to attempt a repair.
p2s_fix_blockers_match() {
    local allowed=$1
    if [ ! -s "$P2S_WORK/blocker-keys" ]; then ! ${P2S_BLOCKED:-false}; return $?; fi
    awk -v allowed="$allowed" 'index(allowed,"|" $0 "|")==0 {bad=1} END {exit bad}' "$P2S_WORK/blocker-keys"
}

p2s_package_deb_repair_audit_collect() {
    local status=0
    P2S_REPAIR_AUDIT_NEEDED=false
    p2s_command_run 30 dpkg --audit > "$P2S_WORK/audit" 2> "$P2S_WORK/audit.err" || status=$?
    P2S_PACKAGE_AUDIT_EXIT_STATUS=$status
    if [ "$status" -ne 0 ] || [ -s "$P2S_WORK/audit" ] || [ -s "$P2S_WORK/audit.err" ]; then
        P2S_REPAIR_AUDIT_NEEDED=true
        p2s_manifest_record package_audit "$(cat "$P2S_WORK/audit" "$P2S_WORK/audit.err" | p2s_manifest_redact_repository_urls)"
        p2s_package_deb_audit_context_collect
        p2s_package_deb_repair_assess
    fi
}

p2s_fix_selected_repair_preflight() {
    local allowed='|'
    [ "${P2S_REPOSITORY_REPAIR:-none}" = none ] || allowed="${allowed}repositories|source_authentication|"
    if ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} || ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}; then allowed="${allowed}package_state|"; fi
    if ${P2S_ALLOW_SURY_MIGRATION:-false}; then allowed="${allowed}unsupported_os|"; fi
    if ! p2s_fix_blockers_match "$allowed"; then
        p2s_fix_block repair_prerequisite "Other reported blockers prevent the selected repair; no repair can bypass runtime, OS or restart safety checks."; return 1
    fi
    [ "$P2S_BACKEND" = deb ] && p2s_command_exists df || {
        p2s_fix_block repair_prerequisite "These repairs require a verified APT package setup and filesystem-space check."; return 1;
    }
    local P2S_BLOCKED=false
    p2s_fix_preflight && p2s_package_deb_holds_preflight
}

# P2S-MUTATION: Apply selected repairs before the ordinary PHP transaction, then reassess from scratch.
p2s_fix_prepare_selected_methods() {
    [ "${P2S_MODE:-check}" = fix ] && ${P2S_DISRUPTIVE:-false} || return 1
    if [ "${P2S_REPOSITORY_REPAIR:-none}" != none ]; then
        p2s_disruptive_repository_apply_recipe || return 1
    fi
    if ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} || ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}; then
        p2s_package_deb_repair_audit_collect
        if $P2S_REPAIR_AUDIT_NEEDED; then
            P2S_PACKAGE_REPAIR_SAFETY_VERIFIED=true
            if ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} && ${P2S_PENDING_PHP_REPAIR_ELIGIBLE:-false}; then
                p2s_disruptive_package_configure_pending_php || return 1
            elif ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false} && ${P2S_EXACT_PHP_REPAIR_ELIGIBLE:-false}; then
                p2s_disruptive_package_reinstall_exact_php || return 1
            else
                p2s_fix_block package_repair_scope "The selected repair does not match a verified PHP-only package problem: ${P2S_PACKAGE_REPAIR_REASON:-unknown audit state}."; return 1
            fi
        else
            p2s_manifest_record package_repair_result 'not_needed|audit_clean|no_package_repair_attempt'
        fi
    fi
    P2S_PACKAGE_REPAIR_SAFETY_VERIFIED=false
    P2S_BLOCKED=false; : > "$P2S_WORK/blocker-keys"
    p2s_inventory_collect_and_assess
    p2s_fix_check_distro_recipe
}

p2s_fix_recommendation_print() {
    local method=$1 options=$2 evidence=$3
    # An unresolved fix already tried the ordinary update path; retain only specific repair options.
    if [ "$P2S_PHASE" = afterfix ] && [ "$options" = --fix ]; then return 0; fi
    P2S_FIX_RECOMMENDATION_EMITTED=true
    p2s_message_print info "Suggested options: $options. $evidence Fix mode rechecks prerequisites and PHP afterwards; updates can interrupt applications."
    p2s_manifest_record fix_recommendation "$method|options=$options|$evidence|check_only_no_changes|fresh_fix_preflight_required"
}

# These assessments use installed/cached evidence only; no refresh, source write, wait or repair.
p2s_fix_recommend_options() {
    local status=0 name version arch vendor exact=true native_php=false migration_repair=''
    [ "${P2S_STATE:-N}" != N ] || return 0
    case "${P2S_PANEL:-}" in
        cpanel|plesk)
            if ! ${P2S_BLOCKED:-false}; then p2s_fix_recommendation_print existing_provider '--fix' 'Use the detected panel updater for its PHP packages.'; fi
            return 0 ;;
    esac
    if [ "${P2S_BACKEND:-}" != deb ]; then
        if ! ${P2S_BLOCKED:-false}; then p2s_fix_recommendation_print existing_provider '--fix' 'Use the current supported package or panel procedure.'; fi
        return 0
    fi
    status=0; p2s_package_lock_probe || status=$?
    if [ "$status" -eq 1 ] && p2s_fix_blockers_match '|package_manager_busy|'; then p2s_fix_recommendation_print package_lock '--fix --wait-for-package-lock 120' 'A package lock file is open; wait for that operation without forcing an unlock.'; fi
    if p2s_fix_blockers_match '|package_state|'; then
        p2s_package_deb_repair_audit_collect
        if ${P2S_REPAIR_AUDIT_NEEDED:-false}; then
            if ${P2S_PENDING_PHP_REPAIR_ELIGIBLE:-false}; then
                p2s_fix_recommendation_print pending_php '--fix --enable-extra-fixes --configure-pending-php-packages' 'Only recognized pending PHP package configuration was identified; unrelated package repair remains excluded.'
            elif ${P2S_EXACT_PHP_REPAIR_ELIGIBLE:-false}; then
                while IFS='|' read -r name version arch; do
                    if ! p2s_package_deb_repair_exact_candidate_validate "$name" "$version" "$arch"; then exact=false; break; fi
                done < "$P2S_WORK/repair-reinstall"
                if $exact; then p2s_fix_recommendation_print exact_php '--fix --enable-extra-fixes --reinstall-php-same-version' 'Cached metadata has an equivalent exact installed-version PHP candidate; reinstallation retains that version, which needs a separate CVE assessment.'; fi
            fi
            return 0
        fi
    fi
    if [ -s "$P2S_WORK/summary-versions" ] && ! ${P2S_RESTART_PENDING:-false} && p2s_state_has_only_fixed_versions; then return 0; fi
    if ! p2s_fix_blockers_match '|unsupported_os|candidate_provider|no_candidate|repositories|source_authentication|'; then return 0; fi
    if p2s_repository_repair_assess sury-key && p2s_command_exists gpg &&
        { p2s_command_exists curl || p2s_command_exists wget; } && p2s_repository_sury_key_needs_refresh; then
        if p2s_fix_blockers_match '|repositories|source_authentication|'; then
        p2s_fix_recommendation_print repository_repair '--fix --enable-extra-fixes --refresh-sury-signing-key' 'The standard Sury source uses an expired or mismatched installed key; this recipe replaces only its verified package keyring.'
        return 0
        fi
        migration_repair=' --refresh-sury-signing-key'
    fi
    # Prefer a normal update, including verified necessary native-library upgrades.
    if ! ${P2S_BLOCKED:-false} && (
        P2S_ASSESSMENT_ONLY=true; P2S_MODE=check; P2S_ALLOW_SURY_MIGRATION=false
        P2S_ALLOW_SURY_REPOSITORY=false; P2S_DISRUPTIVE=false
        p2s_package_deb_update
    ) > "$P2S_WORK/recommend-plan.log" 2>&1; then
        p2s_manifest_record option_assessment "existing_provider_and_dependencies|cached_only
$(cat "$P2S_WORK/recommend-plan.log")"
        p2s_fix_recommendation_print existing_provider '--fix' 'The cached PHP plan uses existing package sources, including verified necessary native-library upgrades; fix mode will refresh and revalidate candidates.'
        return 0
    fi
    if [ -f "$P2S_WORK/recommend-plan.log" ]; then
        p2s_manifest_record option_assessment "existing_provider_and_dependencies|cached_only
$(cat "$P2S_WORK/recommend-plan.log")"
    fi
    if [ -r "$P2S_WORK/packages" ]; then
        while IFS='|' read -r name version arch vendor; do
            if p2s_package_is_engine "$name" && ! p2s_package_deb_is_sury "$version"; then
                case "$(p2s_package_provider "$name" "$vendor" "$version")" in Debian|Ubuntu) native_php=true ;; esac
            fi
        done < "$P2S_WORK/packages"
    fi
    if $native_php && p2s_fix_blockers_match '|repositories|source_authentication|' && p2s_repository_repair_assess native-security-source &&
        [ "${P2S_REPOSITORY_REPAIR_STATE:-needed}" = needed ]; then
        p2s_fix_recommendation_print repository_repair '--fix --enable-extra-fixes --add-os-security-repository' 'A matching native security source is missing; fresh repository access and fixed candidates still need verification.'
        return 0
    fi
    if ! ${P2S_BLOCKED:-false}; then
        p2s_fix_recommendation_print existing_provider '--fix' 'The cached plan is incomplete; refresh and try the configured PHP package repositories before considering third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages.'
    fi
    if (
        P2S_ASSESSMENT_ONLY=true; P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true
        p2s_disruptive_sury_validate_equivalents
    ) > "$P2S_WORK/recommend-migration.log" 2>&1; then
        if (
            P2S_ASSESSMENT_ONLY=true; P2S_MODE=check; P2S_DISRUPTIVE=true
            P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=false
            p2s_package_deb_update
        ) > "$P2S_WORK/recommend-migration-plan.log" 2>&1; then
            p2s_fix_recommendation_print sury_migration "--fix --enable-extra-fixes --migrate-php-to-sury$migration_repair" 'Cached candidates pass equivalent-package and necessary native-library checks for the configured Sury source.'
        elif (p2s_repository_sury_source_present; [ "$?" -eq 1 ]); then
            p2s_fix_recommendation_print sury_source '--fix --enable-extra-fixes --migrate-php-to-sury --add-sury-repository' 'Optional switch from distribution PHP packages to third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages: local package identities fit the reviewed scope, but candidates from the missing repository have not been checked.'
        fi
    fi
    if [ -f "$P2S_WORK/recommend-migration.log" ]; then
        p2s_manifest_record option_assessment "sury_migration_identity|cached_only
$(cat "$P2S_WORK/recommend-migration.log")"
    fi
    if [ -f "$P2S_WORK/recommend-migration-plan.log" ]; then
        p2s_manifest_record option_assessment "sury_migration_candidate_plan|cached_only
$(cat "$P2S_WORK/recommend-migration-plan.log")"
    fi
    return 0
}


p2s_fix_report_patchability() {
    local assessment source_scope='using its existing PHP package sources'
    if ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        source_scope='using the explicitly enabled Sury migration method'
    fi
    if [ "$P2S_STATE" = N ]; then
        assessment=not_needed
        p2s_message_print info "Automatic update: No update is needed for PHP2Shell within the scope of this check."
    else
        if p2s_fix_preflight; then
            if [ "$P2S_BACKEND" = deb ] && ! p2s_package_deb_preflight; then P2S_BLOCKED=true; fi
        else
            # A failed probe must not become an optimistic prediction even if it had no specific diagnostic.
            P2S_BLOCKED=true
        fi
        if $P2S_BLOCKED; then
            assessment=blocked
            p2s_message_print warn "Automatic update: This script cannot proceed under the reported conditions. See the specific blockers above. No package installation or service restart was attempted."
        elif [ "$P2S_STATE" = Y ] && ! $P2S_UNKNOWN && ! ${P2S_PACKAGE_POLICY_REVIEW:-false} && p2s_command_exists df; then
            assessment=eligible_to_attempt
            p2s_message_print info "Automatic update: This server appears suitable for an update attempt $source_scope. The local prerequisite checks passed. Run the update to find out whether patched packages are available and can be installed safely; successful updates and service restarts still need verification."
        else
            assessment=unknown
            p2s_message_print info "Automatic update: No local blocker was found; fix feasibility remains unresolved until the package sources and candidates are checked. Running the update will check the package sources and report what can be updated; any remaining unverified PHP installations will still need review."
        fi
    fi
    # Keep fix eligibility separate from CVE state; refresh cached metadata before selecting an update candidate.
    p2s_manifest_record patchability "$assessment|scope=host_php|repositories=not_refreshed|candidate_fixes=not_verified|vulnerability=$P2S_STATE|inventory_unknown=$P2S_UNKNOWN|package_policy_review=${P2S_PACKAGE_POLICY_REVIEW:-false}"
}

# P2S-MUTATION: Orchestrates package updates and service restarts after preflight checks.
p2s_fix_run() {
    if [ "${P2S_MODE:-fix}" != fix ]; then
        p2s_fix_block mode 'Package updates, repairs and restarts require fix mode.'; return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=false; P2S_PANEL_UPDATE_COMPLETED=false
    P2S_PACKAGE_CONFIGURATION_ATTEMPTED=false; P2S_PACKAGE_REINSTALL_ATTEMPTED=false
    local selected_repairs=false
    if [ "${P2S_REPOSITORY_REPAIR:-none}" != none ] || ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} || ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}; then selected_repairs=true; fi
    if [ "${P2S_BACKEND:-}" = deb ]; then p2s_package_lock_warn; fi
    p2s_package_lock_wait || return 1
    # Repeating a host update cannot repair an uninspected container when host PHP is already fixed.
    if ! $P2S_BLOCKED && ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} && ! $P2S_RESTART_PENDING && p2s_state_has_only_fixed_versions; then
        p2s_manifest_record host_update 'not_needed|assessed_host_versions=fixed|separate_environment_review_required'
        p2s_message_print info "No further host PHP package update is needed for the assessed versions. Containers or separate application environments still require review."
        return 0
    fi
    if $selected_repairs; then p2s_fix_selected_repair_preflight || return 1
    else p2s_fix_preflight || return 1
    fi
    # A vendor installer can also invoke dpkg; discover broken state or PHP holds before any panel changes.
    case "${P2S_PANEL:-}:$P2S_BACKEND" in cpanel:deb|plesk:deb) p2s_package_deb_preflight || return 1 ;; esac
    cp "$P2S_WORK/services" "$P2S_WORK/services.before" || return 1
    cp "$P2S_WORK/processes" "$P2S_WORK/processes.before" || return 1
    # Scheduled CLI tasks are never included in automatic service restart targets.
    if [ -r "$P2S_WORK/scheduled-php" ]; then
        cp "$P2S_WORK/scheduled-php" "$P2S_WORK/scheduled-php.before" || return 1
    fi
    p2s_message_print attemptingfix "Checking for PHP package updates and required service restarts."
    local update_status=0
    if $selected_repairs; then
        p2s_fix_prepare_selected_methods || update_status=$?
        if [ "$update_status" -eq 0 ]; then p2s_fix_preflight || update_status=$?; fi
        if [ "$update_status" -eq 0 ]; then
            sort -u "$P2S_WORK/services.before" "$P2S_WORK/services" > "$P2S_WORK/services.union" && mv "$P2S_WORK/services.union" "$P2S_WORK/services.before" || update_status=1
            sort -u "$P2S_WORK/processes.before" "$P2S_WORK/processes" > "$P2S_WORK/processes.union" && mv "$P2S_WORK/processes.union" "$P2S_WORK/processes.before" || update_status=1
        fi
    fi
    case "$update_status:${P2S_PANEL:-}" in
        0:cpanel|0:plesk)
            # P2S-MUTATION: Runs the panel security/component updater before verifying PHP again.
            p2s_panel_update || update_status=$? ;;
    esac
    # Plesk owns its component transaction. cPanel website PHP still needs its own package update.
    if [ "$update_status" -eq 0 ] && [ "${P2S_PANEL:-}" != plesk ] && { ! $selected_repairs || [ "$P2S_STATE" != N ]; }; then
        # P2S-MUTATION: Dispatches to the APT or RPM PHP package update implementation.
        case "$P2S_BACKEND" in deb) p2s_package_deb_update ;; rpm) p2s_package_rpm_update ;; *) return 1 ;; esac
        update_status=$?
    fi
    # Maintainer scripts may already have replaced workers; still verify the saved services.
    local restart_status=0
    # P2S-MUTATION: Replaces workers after an installation attempt or a pending restart.
    if $P2S_TRANSACTION_ATTEMPTED || $P2S_RESTART_PENDING; then p2s_service_restart_and_verify; restart_status=$?; fi
    p2s_manifest_record fix_commands "update_exit=$update_status|restart_exit=$restart_status|restart_attempted=$P2S_RESTART_ATTEMPTED|pending_php_configuration_attempted=$P2S_PACKAGE_CONFIGURATION_ATTEMPTED|exact_php_reinstall_attempted=$P2S_PACKAGE_REINSTALL_ATTEMPTED"
    [ "$update_status" -eq 0 ] && [ "$restart_status" -eq 0 ]
}

# Command-line entry point

p2s_main() {
    # Update the revision when script behaviour changes; the checksum separately identifies the loaded functions.
    local mode=check result=0 command script_revision=2026-10-29.15
    case "$#:$1" in
        0:|1:--check|1:--check-vuln) ;;
        1:--fix|1:--fix-vuln) mode=fix ;;
        1:--help|1:-h)
            p2s_usage_print
            return 0 ;;
        *) p2s_usage_print >&2; return 64 ;;
    esac
    P2S_MODE=$mode
    P2S_INVENTORY_MESSAGES=false
    case "$mode" in
        check) p2s_message_print info "Check only: no packages or services will be changed." ;;
        fix) p2s_message_print info "Update requested. We will check PHP first and only attempt an update if a fix or further verification is needed. Updates and service restarts can interrupt websites." ;;
    esac
    P2S_PHASE=beforefix; P2S_BLOCKED=false; P2S_FIX_FAILED=false
    P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=false
    P2S_UPDATE_METHOD=; P2S_RETRY_ASSESSMENT=false
    P2S_CPANEL_LAST_LOG_REPORTED=false
    P2S_SURY_REPOSITORY_CREATED=false; P2S_SURY_KEY_CREATED=false
    for command in awk sed grep sort tr head cat date uname id mkdir rm; do
        if ! p2s_command_exists "$command"; then
            p2s_message_print error "Required basic tool $command is unavailable; cannot perform a reliable check."
            printf '%s\n' 'dss:isvulnerable:beforefix: CVE_2026_109618?' 'dss:isvulnerable:afterfix: CVE_2026_109618?'
            return 1
        fi
    done
    if ! p2s_command_has_timeout && ! p2s_command_has_shell_watchdog && ! p2s_command_exists perl; then
        p2s_message_print error "No supported timeout, sleep or Perl is available to bound commands; a manual check is required."
        printf '%s\n' 'dss:isvulnerable:beforefix: CVE_2026_109618?' 'dss:isvulnerable:afterfix: CVE_2026_109618?'
        return 1
    fi
    umask 077
    p2s_work_directory_init || return 1
    : > "$P2S_WORK/blocker-keys"
    : > "$P2S_WORK/messages.inventory"
    # Main runs in a subshell so traps/options never leak into a caller that sources this script.
    trap 'p2s_disruptive_sury_cleanup_added_repository; rm -rf "$P2S_WORK"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export LC_ALL=C
    p2s_manifest_record schema 'php2shell-v1|CVE_2026_109618|covers=CVE-2026-109618,CVE-2026-109619|rules=2026-10-29'
    p2s_manifest_record script_revision "$script_revision"
    p2s_manifest_record source_preservation 'policy=explicit_provider_migrations_only|script_repository_changes=explicit_opt_in_only|APT_Sury_candidates=provider_branch_architecture_and_exact_version_guarded|other_providers_and_panel_transactions_require_separate_review'
    p2s_manifest_record dependency_policy 'required_installed_native_libraries|automatic_with_APT_PHP_updates|reviewed_list_only|matching_official_OS_sources|no_additions_removals_or_downgrades'
    p2s_manifest_record disruptive_options "enabled=${P2S_DISRUPTIVE:-false}|allow_sury_migration=${P2S_ALLOW_SURY_MIGRATION:-false}|allow_sury_repository=${P2S_ALLOW_SURY_REPOSITORY:-false}|repository_repair=${P2S_REPOSITORY_REPAIR:-none}|pending_php_configuration=${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false}|exact_php_reinstall=${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}|package_lock_wait_seconds=${P2S_PACKAGE_LOCK_WAIT_SECONDS:-0}"
    p2s_manifest_record bash "$BASH_VERSION"
    # SSH can deliver source on stdin; $0 would identify Bash, not the delivered script.
    # Record optional cksum output for comparing the loaded functions between runs.
    if p2s_command_exists cksum; then
        p2s_manifest_record function_checksum "$(declare -f | cksum)"
    else
        p2s_manifest_record function_checksum unavailable
    fi
    for command in timeout sleep perl mktemp dpkg-query dpkg apt-get apt-cache rpm dnf yum pacman vercmp wget curl gpg sha256sum fuser systemctl service; do
        if p2s_command_exists "$command"; then p2s_manifest_record capability "$command|available"
        else p2s_manifest_record capability "$command|absent"
        fi
    done
    p2s_manifest_record observed_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'RET:NOW:%s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf 'RET:HOSTNAME:%s\n' "$(hostname 2>/dev/null)"
    p2s_manifest_record kernel "$(uname -a)"
    p2s_manifest_record hostname "$(hostname 2>/dev/null)"
    [ -r /proc/uptime ] && p2s_manifest_record uptime "$(cat /proc/uptime)"
    if p2s_command_exists df; then p2s_command_run 10 df -Pk / > "$P2S_WORK/disk" 2>/dev/null && p2s_manifest_record disk "$(cat "$P2S_WORK/disk")"; fi
    p2s_distro_detect
    p2s_repository_inventory_collect
    p2s_inventory_collect_and_assess
    if [ "$P2S_BACKEND" = deb ]; then p2s_package_lock_warn; fi
    p2s_fix_check_distro_recipe
    if [ "$mode" = check ]; then p2s_fix_report_patchability; p2s_fix_recommend_options; fi
    printf 'dss:isvulnerable:beforefix: CVE_2026_109618%s\n' "$P2S_STATE"
    if [ "$mode" = fix ] && [ "$P2S_STATE" != N ]; then
        # Share the legacy lock so scripts deployed under either name cannot patch concurrently.
        if ! mkdir /var/run/rh-php2shell.lock 2>/dev/null; then
            p2s_fix_block lock "Another PHP update may be running, or its lock remains at /var/run/rh-php2shell.lock. Check before retrying."
            result=1
        else
            trap 'p2s_disruptive_sury_cleanup_added_repository; rmdir /var/run/rh-php2shell.lock; rm -rf "$P2S_WORK"' EXIT
            # P2S-MUTATION: Fix-only entry into package updates and service restarts.
            if ! p2s_fix_run; then result=1; fi
            P2S_PHASE=afterfix
            if [ "$result" -ne 0 ]; then P2S_FIX_FAILED=true; fi
            p2s_inventory_collect_and_assess
            # Fresh masters may differ after package scripts/restarts. Check their actual configurations
            # for extension-loader warnings too; -n version probes intentionally skip php.ini extensions.
            if $P2S_TRANSACTION_ATTEMPTED && ! p2s_service_preflight; then result=1; P2S_FIX_FAILED=true; fi
            if [ "$result" -ne 0 ] && [ "$P2S_STATE" = N ]; then P2S_STATE='?'; fi
        fi
    fi
    printf 'dss:isvulnerable:afterfix: CVE_2026_109618%s\n' "$P2S_STATE"
    if [ "$mode" = fix ] && [ "$P2S_STATE" != N ]; then
        # Reassess current blockers without carrying consent or stale failures into retry advice.
        (
            P2S_MODE=check; P2S_BLOCKED=false; : > "$P2S_WORK/blocker-keys"
            P2S_DISRUPTIVE=false; P2S_ALLOW_SURY_MIGRATION=false; P2S_ALLOW_SURY_REPOSITORY=false
            P2S_ALLOW_PENDING_PHP_CONFIGURATION=false; P2S_ALLOW_EXACT_PHP_REINSTALL=false
            P2S_REPOSITORY_REPAIR=none
            P2S_PHASE=afterfix
            P2S_RETRY_ASSESSMENT=true
            p2s_inventory_collect_and_assess
            p2s_fix_check_distro_recipe
            if p2s_fix_preflight; then
                if [ "$P2S_BACKEND" = deb ]; then p2s_package_deb_preflight; fi
            fi
            P2S_FIX_RECOMMENDATION_EMITTED=false
            p2s_fix_recommend_options
            if ! $P2S_FIX_RECOMMENDATION_EMITTED; then
                p2s_message_print warn "This script could not finish the PHP fix. Check the earlier messages for the remaining problems. After resolving them, run --check again."
            fi
        )
        if ! $P2S_TRANSACTION_ATTEMPTED && ! $P2S_RESTART_ATTEMPTED; then
            if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} && p2s_state_has_only_fixed_versions; then
                p2s_message_print warn "Automatic changes were skipped. The assessed host PHP versions have verified fixes, but containers or separate application environments still require review. No PHP package installation or service restart was attempted. Review those environments and any other reported blockers; rerunning a host package update alone will not resolve the separate-environment check."
            else
                p2s_message_print error "We could not apply an automatic update under the reported conditions. No PHP package installation or service restart was attempted. See the specific blockers above."
            fi
            p2s_manifest_record fix_outcome 'blocked|package_install_attempted=false|service_restart_attempted=false'
        else
            if [ "$result" -eq 0 ] && [ "$P2S_STATE" = '?' ]; then
                p2s_message_print error "The update attempt finished, but we could not verify that all PHP installations are patched. See the remaining verification warnings above."
            elif [ "$result" -eq 0 ] && [ "$P2S_STATE" = Y ]; then
                p2s_message_print error "The update attempt finished, but at least one PHP installation is still vulnerable. See the remaining PHP versions and update messages above."
            else
                p2s_message_print error "The update could not be completed or verified. Packages or services may have changed. Review the messages and check your websites before retrying."
            fi
            p2s_manifest_record fix_outcome "incomplete|package_install_attempted=$P2S_TRANSACTION_ATTEMPTED|service_restart_attempted=$P2S_RESTART_ATTEMPTED"
        fi
        result=1
    fi
    p2s_summary_print_result
    return "$result"
}

# Public command line; the inspection/update engine retains its structured output.

p2s_usage_print() {
    cat <<'EOF'
Usage: dephp2shell.sh [--check|--fix] [--enable-extra-fixes] [options]

  --check           Check PHP without package changes or service restarts (default).
  --fix             Refresh package lists, attempt allowed PHP updates and restart supported services.
                    Include verified necessary upgrades of reviewed installed native libraries from matching OS sources.
                    Other applications may share these libraries; no new packages or broad OS upgrade.
                    Use existing PHP package repositories and publishers by default; panel updaters can have broader effects.
  --enable-extra-fixes
                    Permit only the extra methods selected below; it does not bypass safety checks.
                    Implies --fix unless --check is explicit. Extra methods are disabled by default.
  --migrate-php-to-sury
                    Change eligible PHP packages to Sury (Debian) or the ondrej PHP PPA (Ubuntu).
                    Keep the PHP branch; download through an existing authenticated APT source.
                    This flag adds no repository. Switching PHP package publishers still needs application testing.
  --add-sury-repository
                    Also allow a new matching Sury/PPA source file and dedicated verified signing key.
                    Sources: packages.sury.org/php or ppa.launchpadcontent.net/ondrej/php/ubuntu.
                    Requires --migrate-php-to-sury. New files remain after a transaction attempt,
                    including failure; they are removed on exit if no transaction was attempted.
  --refresh-sury-signing-key
                    Restore access to Sury updates by replacing the key that verifies their source.
                    Download and replace the standard Debian Sury signing key; retain a backup.
                    Source definitions stay unchanged. Extrepo/custom layouts need separate review.
  --add-os-security-repository
                    Let the server look for security updates from the Debian or Ubuntu security repository.
                    Add the matching Debian/Ubuntu main security source using its installed archive keyring.
                    The new source persists after failure. Choose only one repository repair per attempt.
  --configure-pending-php-packages
                    Finish a PHP installation that was interrupted or did not complete.
                    Finish setup of explicitly identified pending PHP packages; no configure-all.
                    This repair downloads no packages, but setup scripts can change files/services.
  --reinstall-php-same-version
                    Repair PHP installation records by installing the same version again.
                    Repair identified missing dpkg file-list/checksum metadata using the same PHP version.
                    APT fetches its exact candidate. Package files are replaced and setup scripts run again;
                    the installed version may still be vulnerable.
  --wait-for-package-lock SECONDS
                    Give another software update time to finish before starting this one.
                    Wait 0..600 seconds on APT systems with an existing fuser (default 0).
                    No locks are deleted or processes stopped; an expired/inconclusive wait stops the fix.
  --output FORMAT   human (default) or machine (structured records for integrations).
  --log-dir DIR     Save full diagnostics in a private timestamped subdirectory of DIR.
  --color WHEN      auto (default), always or never; only human console accents.
  --no-color        Disable colour; bold is controlled separately.
  --bold WHEN       auto (default), always or never; emphasise labels and results.
  --no-bold         Disable bold emphasis.
  --help, -h        Show this help without inspecting or changing the server.

Linux only. Other operating systems exit before inventory or log creation.
DP2S_OUTPUT, DP2S_LOG_DIR, DP2S_COLOR and DP2S_BOLD set defaults.
DP2S_MIGRATE_PHP_TO_SURY, DP2S_ADD_SURY_REPOSITORY,
DP2S_CONFIGURE_PENDING_PHP_PACKAGES, DP2S_REINSTALL_PHP_SAME_VERSION and
DP2S_UPGRADE_REQUIRED_PHP_LIBRARIES accept true/false, yes/no or 1/0 (default false).
DP2S_REFRESH_SURY_SIGNING_KEY and DP2S_ADD_OS_SECURITY_REPOSITORY are also Boolean defaults (false).
DP2S_WAIT_FOR_PACKAGE_LOCK_SECONDS defaults to 0. --enable-extra-fixes is command-line consent only.
Method settings require --enable-extra-fixes. Explicit --check stays read-only and
recommends applicable options from installed/cached evidence without refreshing sources.
Nonempty NO_COLOR disables colour by default; explicit options take precedence.
Auto styling leaves pipes plain; machine output is always unstyled.
Human output saves logs under $HOME/dephp2shellinfo/runs by default.
Machine output creates no persistent logs unless a log directory is specified.

Updates and service restarts can interrupt applications. Plesk's updater can
also update non-PHP components. The ordinary APT PHP path adds no repositories or PHP package publishers.
Opted-in Sury migration keeps package names, PHP branches, architecture and extension
API, and rejects removals or unrelated changes. Reviewed native library upgrades need
their separate permission. Package repairs may execute PHP package scripts and
verified PHP triggers. A successful repair can be followed by ordinary PHP updates.
For APT methods, PHP packages come through APT rather than hard-coded .deb URLs.
Public signing keys have separate direct downloads.
Repository repairs retain their changes and key backups
even if later patching fails. Only reviewed OS releases are eligible.
Package scripts can change configuration/services; failed attempts have no automatic rollback.
No operating systems are upgraded and no reboots are performed by this tool.

Before granting a method, read its file changes, download sources, benefits and risks:
https://github.com/pbkwee/dephp2shell/blob/main/docs/resolution-options.md
EOF
}

p2s_option_boolean() {
    case "$1" in
        true|TRUE|yes|YES|y|Y|on|ON|1) printf 'true\n' ;;
        false|FALSE|no|NO|n|N|off|OFF|0) printf 'false\n' ;;
        *) return 1 ;;
    esac
}

p2s_output_print_human() {
    local color="${1:-auto}" weight="${2:-auto}" line message terminal=false colors
    local warning='' error='' reset='' marker_warning='' marker_error='' emphasis='' emphasis_reset=''
    if [ -t 1 ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ]; then terminal=true; fi
    if [ "$color" = always ]; then
        marker_warning=$(printf '\033[33m!\033[39m ')
        marker_error=$(printf '\033[31m!\033[39m ')
    elif [ "$color" = auto ] && $terminal; then
        colors=$(tput colors 2>/dev/null) || colors=0
        case "$colors" in ''|*[!0-9]*) colors=0 ;; esac
        if [ "$colors" -ge 8 ] 2>/dev/null &&
            warning=$(tput setaf 3 2>/dev/null) && error=$(tput setaf 1 2>/dev/null) &&
            reset=$(tput sgr0 2>/dev/null) && [ -n "$warning" ] && [ -n "$error" ] && [ -n "$reset" ]; then
            marker_warning="$warning!$reset "
            marker_error="$error!$reset "
        fi
    fi
    if [ "$weight" = always ]; then
        emphasis=$(printf '\033[1m'); emphasis_reset=$(printf '\033[22m')
    elif [ "$weight" = auto ] && $terminal; then
        if ! { emphasis=$(tput bold 2>/dev/null) && emphasis_reset=$(tput sgr0 2>/dev/null) &&
            [ -n "$emphasis" ] && [ -n "$emphasis_reset" ]; }; then
            emphasis=''; emphasis_reset=''
        fi
    fi
    # Keep words in the terminal's own foreground; only optional markers carry colour.
    # Input: "dss:warn: PHP needs attention" -> "Warning: PHP needs attention".
    # Other records remain in the detailed log, including manifest and RET fields.
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            dss:info:*)
                message=${line#dss:info:}; message=${message# }
                case "$message" in
                    Result:*) printf '%sResult:%s%s\n' "$emphasis" "$emphasis_reset" "${message#Result:}" ;;
                    *) printf '%s\n' "$message" ;;
                esac ;;
            dss:warn:*)
                message=${line#dss:warn:}
                printf '%s%sWarning:%s %s\n' "$marker_warning" "$emphasis" "$emphasis_reset" "${message# }" ;;
            dss:error:*)
                message=${line#dss:error:}
                printf '%s%sError:%s %s\n' "$marker_error" "$emphasis" "$emphasis_reset" "${message# }" ;;
        esac || return 1
    done
}

p2s_cli() {
    local mode=check action='' output="${DP2S_OUTPUT:-human}" log_root="${DP2S_LOG_DIR:-}"
    local option value run_directory log_file stamp status permissions log_requested=false disruptive=false
    local color="${DP2S_COLOR:-auto}" bold="${DP2S_BOLD:-auto}"
    local P2S_DISRUPTIVE=false P2S_ALLOW_SURY_MIGRATION="${DP2S_MIGRATE_PHP_TO_SURY:-false}" P2S_ALLOW_SURY_REPOSITORY="${DP2S_ADD_SURY_REPOSITORY:-false}"
    local P2S_ALLOW_PENDING_PHP_CONFIGURATION="${DP2S_CONFIGURE_PENDING_PHP_PACKAGES:-false}"
    local P2S_ALLOW_EXACT_PHP_REINSTALL="${DP2S_REINSTALL_PHP_SAME_VERSION:-false}"
    local refresh_sury_signing_key="${DP2S_REFRESH_SURY_SIGNING_KEY:-false}"
    local add_os_security_repository="${DP2S_ADD_OS_SECURITY_REPOSITORY:-false}"
    local P2S_REPOSITORY_REPAIR=none P2S_PACKAGE_LOCK_WAIT_SECONDS="${DP2S_WAIT_FOR_PACKAGE_LOCK_SECONDS:-0}"
    local -a pipeline_status
    if [ -n "${NO_COLOR:-}" ]; then color=never; fi
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help|-h) p2s_usage_print; return 0 ;;
            --check|--check-vuln|--fix|--fix-vuln)
                case "$1" in --check*) value=check ;; *) value=fix ;; esac
                if [ -n "$action" ] && [ "$action" != "$value" ]; then
                    printf '%s\n' 'Choose either --check or --fix.' >&2; return 64
                fi
                action=$value; mode=$value ;;
            --enable-extra-fixes) disruptive=true ;;
            --migrate-php-to-sury) P2S_ALLOW_SURY_MIGRATION=true ;;
            --add-sury-repository) P2S_ALLOW_SURY_REPOSITORY=true ;;
            --migrate-php-to-sury=*) P2S_ALLOW_SURY_MIGRATION=${1#--migrate-php-to-sury=} ;;
            --add-sury-repository=*) P2S_ALLOW_SURY_REPOSITORY=${1#--add-sury-repository=} ;;
            --configure-pending-php-packages) P2S_ALLOW_PENDING_PHP_CONFIGURATION=true ;;
            --reinstall-php-same-version) P2S_ALLOW_EXACT_PHP_REINSTALL=true ;;
            --configure-pending-php-packages=*) P2S_ALLOW_PENDING_PHP_CONFIGURATION=${1#--configure-pending-php-packages=} ;;
            --reinstall-php-same-version=*) P2S_ALLOW_EXACT_PHP_REINSTALL=${1#--reinstall-php-same-version=} ;;
            --refresh-sury-signing-key) refresh_sury_signing_key=true ;;
            --refresh-sury-signing-key=*) refresh_sury_signing_key=${1#--refresh-sury-signing-key=} ;;
            --add-os-security-repository) add_os_security_repository=true ;;
            --add-os-security-repository=*) add_os_security_repository=${1#--add-os-security-repository=} ;;
            --wait-for-package-lock=*) P2S_PACKAGE_LOCK_WAIT_SECONDS=${1#--wait-for-package-lock=} ;;
            --no-color) color=never ;;
            --no-bold) bold=never ;;
            --output|--log-dir|--color|--bold|--wait-for-package-lock)
                option=$1
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                    printf '%s needs a value. See --help.\n' "$option" >&2; return 64
                fi
                value=$2; shift
                case "$option" in
                    --output) output=$value ;;
                    --log-dir) log_root=$value; log_requested=true ;;
                    --color) color=$value ;;
                    --bold) bold=$value ;;
                    --wait-for-package-lock) P2S_PACKAGE_LOCK_WAIT_SECONDS=$value ;;
                esac ;;
            --color=*) color=${1#--color=} ;;
            --bold=*) bold=${1#--bold=} ;;
            --output=*) output=${1#--output=} ;;
            --log-dir=*) log_root=${1#--log-dir=}; log_requested=true ;;
            *) printf '%s\n' 'Unrecognised argument. See --help.' >&2; return 64 ;;
        esac
        shift
    done
    case "$output" in human|machine) ;; *) printf '%s\n' 'Output must be human or machine. See --help.' >&2; return 64 ;; esac
    case "$color" in auto|always|never) ;; *) printf '%s\n' 'Colour must be auto, always or never. See --help.' >&2; return 64 ;; esac
    case "$bold" in auto|always|never) ;; *) printf '%s\n' 'Bold must be auto, always or never. See --help.' >&2; return 64 ;; esac
    if $log_requested && [ -z "$log_root" ]; then
        printf '%s\n' '--log-dir needs a directory. See --help.' >&2; return 64
    fi
    if ! P2S_ALLOW_SURY_MIGRATION=$(p2s_option_boolean "$P2S_ALLOW_SURY_MIGRATION") ||
        ! P2S_ALLOW_SURY_REPOSITORY=$(p2s_option_boolean "$P2S_ALLOW_SURY_REPOSITORY") ||
        ! P2S_ALLOW_PENDING_PHP_CONFIGURATION=$(p2s_option_boolean "$P2S_ALLOW_PENDING_PHP_CONFIGURATION") ||
        ! P2S_ALLOW_EXACT_PHP_REINSTALL=$(p2s_option_boolean "$P2S_ALLOW_EXACT_PHP_REINSTALL") ||
        ! refresh_sury_signing_key=$(p2s_option_boolean "$refresh_sury_signing_key") ||
        ! add_os_security_repository=$(p2s_option_boolean "$add_os_security_repository"); then
        printf '%s\n' 'Method settings must be true/false, yes/no or 1/0.' >&2; return 64
    fi
    if $refresh_sury_signing_key && $add_os_security_repository; then
        printf '%s\n' 'Choose only one of --refresh-sury-signing-key and --add-os-security-repository per attempt.' >&2; return 64
    fi
    if $refresh_sury_signing_key; then P2S_REPOSITORY_REPAIR="sury-key"; fi
    if $add_os_security_repository; then P2S_REPOSITORY_REPAIR=native-security-source; fi
    case "$P2S_PACKAGE_LOCK_WAIT_SECONDS" in ''|*[!0-9]*)
        printf '%s\n' 'Package-lock wait must be an integer from 0 to 600 seconds.' >&2; return 64 ;;
    esac
    if [ "${#P2S_PACKAGE_LOCK_WAIT_SECONDS}" -gt 3 ] || [ "$P2S_PACKAGE_LOCK_WAIT_SECONDS" -gt 600 ]; then
        printf '%s\n' 'Package-lock wait must be an integer from 0 to 600 seconds.' >&2; return 64
    fi
    P2S_PACKAGE_LOCK_WAIT_SECONDS=$((10#$P2S_PACKAGE_LOCK_WAIT_SECONDS))
    if $P2S_ALLOW_SURY_REPOSITORY && ! $P2S_ALLOW_SURY_MIGRATION; then
        printf '%s\n' '--add-sury-repository also requires --migrate-php-to-sury.' >&2; return 64
    fi
    if $P2S_ALLOW_SURY_MIGRATION || $P2S_ALLOW_PENDING_PHP_CONFIGURATION ||
        $P2S_ALLOW_EXACT_PHP_REINSTALL || [ "$P2S_REPOSITORY_REPAIR" != none ]; then
        if ! $disruptive; then printf '%s\n' 'Alternative update and repair methods also require --enable-extra-fixes.' >&2; return 64; fi
    elif $disruptive; then
        printf '%s\n' '--enable-extra-fixes requires a selected migration or repair method.' >&2; return 64
    fi
    if $disruptive; then
        P2S_DISRUPTIVE=true
        if [ -z "$action" ]; then mode=fix; fi
    fi
    # uname -s reports Linux, Darwin, FreeBSD or a Windows POSIX-shell kernel name.
    # Reject other/unknown kernels before logs, inventory or administrative commands.
    case "$(uname -s 2>/dev/null)" in
        Linux) ;;
        *)
            if [ "$output" = machine ]; then
                printf '%s\n' 'dss:error: DePHP2Shell requires Linux. No check or update was started.' \
                    'dss:isvulnerable:beforefix: CVE_2026_109618?' \
                    'dss:isvulnerable:afterfix: CVE_2026_109618?'
            else
                printf '%s\n' 'DePHP2Shell requires Linux. No check or update was started.' >&2
            fi
            return 69 ;;
    esac
    if [ "$output" = machine ] && [ -z "$log_root" ]; then
        p2s_main "--$mode"
        return $?
    fi
    log_root=${log_root:-${HOME:-/root}/dephp2shellinfo/runs}
    # A leading dash is a relative directory, never an option to mkdir or mktemp.
    case "$log_root" in /*|./*|../*) ;; *) log_root="./$log_root" ;; esac
    umask 077
    if [ -L "$log_root" ] || ! mkdir -p -- "$log_root" || [ ! -O "$log_root" ]; then
        printf '%s\n' 'Cannot prepare an owned log directory; no check or update was started.' >&2; return 1
    fi
    # ls -ld emits e.g. drwx------; group/other write access would allow run-directory swaps.
    permissions=$(LC_ALL=C ls -ld -- "$log_root") || return 1
    permissions=${permissions%% *}
    case "$permissions" in
        ?????w*|????????w*)
            printf '%s\n' 'The log directory must not be writable by other users; no check or update was started.' >&2
            return 1 ;;
    esac
    if ! p2s_command_exists tee; then
        printf '%s\n' 'The tee utility is required to save diagnostics; no check or update was started.' >&2; return 1
    fi
    stamp=$(date -u '+%Y%m%dT%H%M%SZ') || return 1
    run_directory=$(p2s_work_directory_create "$log_root/$stamp.") || return 1
    log_file="$run_directory/output.log"
    if ! : > "$log_file"; then
        printf '%s\n' 'Cannot create the detailed log; no check or update was started.' >&2; return 1
    fi
    printf 'Detailed log: %s\n' "$log_file" >&2
    # Foreground pipelines preserve terminal signal delivery and stream progress live.
    # Capture every stage immediately: successful logging must not mask a failed update.
    if [ "$output" = human ]; then
        (p2s_main "--$mode") 2>&1 | tee "$log_file" | p2s_output_print_human "$color" "$bold"
        pipeline_status=("${PIPESTATUS[@]}")
    else
        (p2s_main "--$mode") 2>&1 | tee "$log_file"
        pipeline_status=("${PIPESTATUS[@]}")
    fi
    status=${pipeline_status[0]}
    if [ "${pipeline_status[1]}" -ne 0 ] || [ "${pipeline_status[2]:-0}" -ne 0 ]; then
        printf '%s\n' 'Diagnostics could not be saved or displayed completely. Review the run before retrying.' >&2
        [ "$status" -ne 0 ] || status=1
    elif [ "$status" -ne 0 ] && [ "$output" = human ]; then
        printf '%s\n' 'The run did not complete successfully. Review the messages and detailed log before retrying.' >&2
    fi
    if ! printf '%s\n' "$status" > "$run_directory/exit-status"; then
        printf '%s\n' 'Could not save the final run status.' >&2
        [ "$status" -ne 0 ] || status=1
    fi
    return "$status"
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ] && ! (return 0 2>/dev/null); then
    (p2s_cli "$@")
    exit $?
fi
