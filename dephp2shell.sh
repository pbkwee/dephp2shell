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
# Preserve PHP providers: repository/provider migrations require explicit operator choice.
# See the source-preservation policy and evidence limits in the maintainer reference.

# Output and manifest records

p2s_manifest_record() {
    local key="$1" value="$2" line
    # Prefix every line, including output supplied by packages, to prevent marker injection.
    printf '%s\n' "$value" | LC_ALL=C tr -d '\000-\010\013-\037\177' |
        while IFS= read -r line; do printf 'dss:manifest:%s:%s|%s\n' "$key" "$P2S_PHASE" "$line"; done
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
    record=${record#Before update attempt: }; record=${record#After update attempt: }
    record="$level: $record"
    # Keep both raw inventories, but do not repeat identical customer messages after a blocked preflight.
    if [ "${P2S_INVENTORY_MESSAGES:-false}" = true ]; then
        if [ "$P2S_PHASE" = beforefix ]; then
            printf '%s\n' "$record" >> "$P2S_WORK/messages.before"
        elif [ "${P2S_TRANSACTION_ATTEMPTED:-false}" = false ] && [ "${P2S_RESTART_ATTEMPTED:-false}" = false ] &&
            grep -Fx -e "$record" "$P2S_WORK/messages.before" >/dev/null 2>&1; then
            return 0
        fi
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

p2s_version_sury_backport_fixed() {
    local name="$1" version="$2" arch="$3" source="$4" source_version="$5" revision suffix release branch
    [ "$arch" = amd64 ] || return 1
    # Exact signed source/binary builds reviewed in docs/sury-backport-evidence.md.
    # Do not turn these into >= floors: later EOL backports require another review.
    case "$P2S_DISTRO:$P2S_RELEASE" in
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
    branch=${revision%%-*}; branch=${branch#*:}; branch=${branch%.*}
    [ "$source" = "php$branch" ] && [ "$source_version" = "$version" ] || return 1
    if [ "$P2S_DISTRO" = debian ]; then
        [ "$version" = "$revision+$suffix.gbp$release" ]
    else
        revision=${revision%%+0~*}
        case "$name" in php7.0-*|libapache2-mod-php7.0) revision=7.0.33-92 ;; php7.1-*|libapache2-mod-php7.1) revision=7.1.33-80 ;; esac
        [ "$version" = "$revision+$suffix" ]
    fi
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
        # An older upstream number does not establish whether a vendor package has a backport.
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
        case "$P2S_MAJOR:${version#0:}" in 9:8.0.30-8.el9_8.1)
            case "$name" in php|php-cli|php-common|php-fpm|php-embedded) state=N ;; esac ;;
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

# Package inventory, ownership and provider evidence

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
                *ppa*) printf 'Ubuntu PPA (provider unverified)\n'; return ;;
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
                p2s_fix_block package_query "The Debian package inventory failed; PHP absence cannot be established."
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
            p2s_fix_block package_query "The RPM package inventory failed; PHP absence cannot be established."
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
    local name version arch vendor state path upstream role provider reason upstream_state source_record source_name source_version
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
                                    p2s_message_print info "$provider PHP uses the panel vendor update path."
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
            if [ "$state" = '?' ]; then reason=no_verified_vendor_rule_or_unrecognised_version; fi
            p2s_manifest_record package_assessment "$name|$version|$arch|$vendor|$provider|$state|$reason|upstream=$upstream_state"
            printf '%s|%s\n' "$name" "$state" >> "$P2S_WORK/package-states"
            upstream=$(printf '%s\n' "${version#*:}" | sed 's/[^0-9.].*//')
            [ -n "$upstream" ] || upstream="unrecognised version ($name)"
            case "$name" in
                libapache*-mod-php*) role='Apache module' ;;
                *-cli) role='command line' ;; *-cgi) role=CGI ;; *-fpm) role=PHP-FPM ;;
                *-common) role='runtime libraries' ;; *-phpdbg) role=debugger ;;
                *) role="$name" ;;
            esac
            # Only executable output identifies the embedded PHP version in these product packages.
            case "$name" in
                sw-engine|frankenphp*) p2s_manifest_record embedded_runtime_package "$name|$version|PHP_version=requires_executable_probe" ;;
                *) printf '%s|%s|%s||%s|%s|%s|package\n' "$upstream" "$state" "$role" "$provider" "$version" "$upstream_state" >> "$P2S_WORK/summary-versions" ;;
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
    if ! p2s_command_exists apt-cache || ! p2s_command_run 60 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$@" > "$P2S_WORK/apt-policy" 2>/dev/null; then
        p2s_manifest_record source_gap 'APT package policy unavailable|repository matches unverified'
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
    p2s_manifest_record package_source_scope 'APT matches use cached indexes; matching versions do not prove download history. No match can mean stale/removed sources or a locally installed package.'
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
            if p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/apt-origins" 2>/dev/null; then
                p2s_manifest_record apt_repository_cache "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/apt-origins")"
            else p2s_manifest_record source_gap 'APT cached release metadata unavailable'; fi
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
            p2s_manifest_record package_source_scope 'RPM vendor/build metadata is not repository history. YUM from_repo is recorded only when retained; missing YUM/DNF history does not prove a source build or manual install.' ;;
    esac
}

p2s_package_log_report() {
    # Package-manager failures can contain authenticated URLs. Never print those verbatim.
    LC_ALL=C awk '{ gsub(/(https?|ftp):\/\/[^ \t\r\n\014\013"<>]+/, "[repository URL redacted]"); print }' "$1" |
        while IFS= read -r line; do p2s_manifest_record command "$line"; done
    p2s_package_failure_report "$1"
}

p2s_package_failure_report() {
    local pid details unit
    P2S_PACKAGE_FAILURE=
    if LC_ALL=C grep -Ei 'Could not get lock|Resource temporarily unavailable.*lock|held by process|another (app|copy).*lock|Existing lock' "$1" >/dev/null; then
        P2S_PACKAGE_FAILURE=package_manager_busy
        pid=$(sed -n 's/.*held by process \([0-9][0-9]*\).*/\1/p' "$1" | head -n 1)
        p2s_manifest_record repository_failure package_manager_busy
        p2s_message_print warn "Another package-manager operation is holding a required lock${pid:+ (PID $pid)}. Wait for it to finish, or ask an administrator to investigate a stuck job. This script will not terminate that job or remove lock files."
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
        p2s_message_print warn "The package or panel updater reported a TLS/certificate failure. Review the update log and repair trusted repository access, or ask support to stage verified packages. Certificate verification was not disabled."
    fi
    if LC_ALL=C grep -Ei '404([ :]|$)|Not Found' "$1" >/dev/null; then
        p2s_manifest_record repository_failure http_404
        p2s_message_print warn "A package repository returned a missing-file error. Check obsolete release URLs or stale mirrors; repository URLs were not rewritten."
    fi
    if LC_ALL=C grep -Ei 'Could not resolve|Couldn.t resolve|Name or service not known|Temporary failure resolving' "$1" >/dev/null; then
        p2s_manifest_record repository_failure dns
        p2s_message_print warn "Package-source name resolution failed; check the server DNS and network configuration."
    fi
    if LC_ALL=C grep -Ei 'NO_PUBKEY|GPG error|not signed|signature.*(fail|invalid)|unsigned package' "$1" >/dev/null; then
        p2s_manifest_record repository_failure authentication
        p2s_message_print warn "Package authentication failed. Check the vendor signing keys and repository configuration; signature checks were not disabled."
    fi
}

p2s_package_refresh_failure_report() {
    p2s_package_log_report "$1"
    case "$P2S_PACKAGE_FAILURE" in
        package_manager_busy|disk_full)
            P2S_BLOCKED=true
            p2s_manifest_record blocker "$P2S_PACKAGE_FAILURE|Package metadata could not be refreshed; see the specific diagnostic above." ;;
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
    local name="$1" installed="$2" arch="$3" sury="$4" target candidate observed matches other seen record metadata source source_version expected suite branch old_branch rest installed_source provider
    target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
    if ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/candidate-policy" 2>/dev/null; then
        p2s_fix_block candidate_provider "Could not read the normal APT candidate for $name; no alternative source was selected."; return 1
    fi
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:12|debian:12.*) suite=bookworm ;; debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        ubuntu:26.04) suite=resolute ;; *) suite=unsupported ;;
    esac
    # Global policy binds repository rows to their release identity. Check EVERY source of the
    # candidate version: exact version selection alone does not resolve duplicate origins.
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
            p2s_fix_block candidate_provider "The normal candidate for $name is not exclusively from the existing Sury PHP source for this OS suite; refusing a provider change or ambiguous origin."
            return 1
        fi
    else
        provider=$(p2s_package_provider "$name" '' "$candidate")
        case "$provider" in Sury*) seen=1 ;; esac
        if [ "$seen" -gt 0 ]; then
            p2s_fix_block candidate_provider "The normal candidate would replace non-Sury package $name with a Sury package; an explicit migration is required."
            return 1
        fi
    fi
    # Never override an APT pin by choosing an older or alternative version explicitly.
    dpkg --compare-versions "$candidate" ge "$installed" || { p2s_fix_block package_downgrade "The normal candidate for $name is older than the installed version; refusing a downgrade."; return 1; }
    if ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$candidate" > "$P2S_WORK/candidate-metadata" 2>/dev/null; then
        p2s_fix_block candidate_provider "Candidate package metadata is unavailable for $name."; return 1
    fi
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
    P2S_DEB_CANDIDATE=$candidate
    p2s_manifest_record candidate_selection "$name|$installed|$candidate|$arch|sury_only=$sury|normal_APT_candidate|exact_version_required"
}

# Read installed package state only; reuse before prediction and immediately before APT changes.
p2s_package_deb_preflight() {
    local name
    p2s_command_exists apt-get || { p2s_fix_block apt_missing "apt-get is unavailable; cannot update Debian PHP packages."; return 1; }
    if ! p2s_command_run 30 dpkg --audit > "$P2S_WORK/audit" 2> "$P2S_WORK/audit.err" || [ -s "$P2S_WORK/audit" ]; then
        p2s_manifest_record package_audit "$(cat "$P2S_WORK/audit" "$P2S_WORK/audit.err" | p2s_manifest_redact_repository_urls)"
        p2s_fix_block package_state "dpkg reports an incomplete package operation; resolve it before updating PHP."
        return 1
    fi
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

# P2S-MUTATION: APT update path; refreshes metadata and can install PHP packages.
p2s_package_deb_update() {
    local log="$P2S_WORK/apt.log" name version arch vendor changed sury=false target
    local packages
    packages=()
    while IFS='|' read -r name version arch vendor; do
        if p2s_package_deb_is_sury "$version"; then sury=true; fi
    done < "$P2S_WORK/packages"
    : > "$P2S_WORK/apt-selected"
    while IFS='|' read -r name version arch vendor; do
        case "${P2S_PANEL:-}:$name" in cpanel:cpanel-php*|cpanel:sw-engine*) continue ;; esac
        if $sury; then
            p2s_package_deb_is_sury "$version" || continue
            # Freeze selectors: updating php-cli/php-xml can select a different already-installed branch.
            case "${name%:*}" in php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9]|php-common|php-pear) ;;
                *) p2s_manifest_record source_preservation "$name|selector_or_unreviewed_package_not_selected"; continue ;;
            esac
        fi
        packages[${#packages[@]}]="$name"
        printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/apt-selected"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    p2s_package_deb_preflight || return 1
    if $sury; then
        p2s_package_deb_sury_trust_preflight || return 1
        p2s_manifest_record source_preservation 'APT|sury_only|non_Sury_and_selector_packages_not_selected|no_provider_or_branch_migrations'
    fi
    p2s_message_print info "Refreshing package lists and checking a PHP-only update."
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
    if ! p2s_command_exists apt-cache || ! p2s_command_exists dpkg ||
        ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/candidate-origins" 2>/dev/null; then
        p2s_fix_block candidate_provider "APT candidate origins could not be inspected; refusing an unchecked provider change."
        return 1
    fi
    packages=()
    : > "$P2S_WORK/apt-approved"
    while IFS='|' read -r name version arch vendor; do
        p2s_package_deb_candidate "$name" "$version" "$arch" "$sury" || return 1
        if [ "$P2S_DEB_CANDIDATE" = "$version" ]; then
            p2s_manifest_record candidate_unchanged "$name|$version|not_requested_for_upgrade"
            continue
        fi
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        packages[${#packages[@]}]="$target=$P2S_DEB_CANDIDATE"
        printf '%s|%s|%s|%s\n' "${name%:*}" "$P2S_DEB_CANDIDATE" "$arch" "$name" >> "$P2S_WORK/apt-approved"
    done < "$P2S_WORK/apt-selected"
    if [ "${#packages[@]}" -eq 0 ]; then
        if $P2S_RESTART_PENDING || ${P2S_PANEL_UPDATE_COMPLETED:-false}; then return 0; fi
        p2s_fix_block no_candidate "Your configured package sources do not currently offer an approved PHP update. Ask support to review the available packages or another update method."
        return 1
    fi
    if $sury; then
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
    if ! p2s_command_run 120 apt-get -s --no-remove install --only-upgrade "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"
        p2s_package_deb_policy_collect "${packages[@]}"
        p2s_fix_block transaction_plan "The PHP update simulation failed. Review package pins, holds, missing candidates and dependency conflicts in the run manifest. This APT simulation installed no packages and changed no restrictions; any earlier panel update is reported separately."
        return 1
    fi
    p2s_package_log_report "$log"
    # Inst php8.4-cli [old] (new repository [arch]); do not silently upgrade unrelated dependencies.
    for changed in $(awk '/^Inst / {print $2}' "$log"); do
        case "${P2S_PANEL:-}:$changed" in
            cpanel:cpanel-php*|cpanel:sw-engine*) p2s_fix_block transaction_scope "The website PHP update proposes a panel-managed package ($changed); use the panel updater for it."; return 1 ;;
        esac
        if ! awk -F'|' -v name="$changed" '$1 == name || $1 ":" $3 == name { found=1 } END { exit !found }' "$P2S_WORK/apt-approved"; then
            p2s_fix_block transaction_scope "The proposed update would also change $changed, outside the PHP packages approved for this update. We stopped before installing packages. Ask support to review a compatible update."; return 1
        fi
    done
    # Inst php8.2-cli [old] (new repo [amd64]); the install must use the exact approved version.
    if ! awk -F'|' 'NR==FNR {versions[$1]=$2; versions[$1 ":" $3]=$2; next}
        /^Inst / {split($0,a," "); line=$0; sub(/^[^(]*\(/,"",line); split(line,b,/[ )]/); if (b[1]!=versions[a[2]]) bad=1}
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
    P2S_TRANSACTION_ATTEMPTED=true
    if ! (export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
        # P2S-MUTATION: Installs PHP updates; package maintainer scripts can also change services.
        p2s_command_run 1800 apt-get -y --no-remove -o APT::Get::AllowUnauthenticated=false \
            -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowWeakRepositories=false \
            -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
            -o Dpkg::Options::=--force-confold install --only-upgrade "${packages[@]}" > "$log" 2>&1); then
        p2s_package_log_report "$log"; p2s_fix_block package_update "PHP package installation failed or timed out. Check package-manager state before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "Updated installed PHP packages through APT without permitting removals or replacing local configuration."
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
        p2s_fix_block transaction_scope "The RPM plan could not be confirmed as updates to existing PHP packages only. Additional dependencies, removals or an unrecognised plan format need manual review."
        return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=true
    # P2S-MUTATION: Installs PHP RPM updates; package scriptlets can also change services.
    if ! p2s_command_run 1800 "$manager" -y --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false' update "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block package_update "The RPM PHP update failed or timed out; check the package transaction before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "Updated installed PHP packages through $manager without switching streams or enabling package erasure."
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
                    if (line ~ /^[A-Za-z-]+:/) {
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
    done
}

# Hosting-panel inventory and vendor updates

p2s_panel_inventory_collect() {
    # CageFS is CloudLinux's per-customer filesystem jail; host updates can leave jail copies unchanged.
    local name directory label panel_found=false tool container_tools='' version_file version
    local update_tools
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
                    p2s_fix_block control_panel "Control panel detected: $label. Its version or required update tool could not be matched to a supported recipe (cPanel 110 or later, or Plesk Obsidian 18). Ask an administrator to review it."
                fi ;;
            virtualmin)
                panel_found=true
                p2s_message_print info "Control panel detected: Virtualmin. Fix mode can update package-managed PHP using the existing repositories and supported service restarts. Check each virtual server's selected PHP version and application compatibility; website PHP selections are not changed by this script." ;;
            cloudlinux) p2s_fix_block control_panel "CloudLinux was detected. Its PHP packages and service restarts need a vendor-specific review; automatic updates are disabled for this setup." ;;
            cagefs) P2S_UNKNOWN=true; p2s_fix_block cagefs "CageFS configuration was found. Ask support to check whether applications use separate PHP copies and how to update them before retrying." ;;
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

# P2S-MUTATION: Vendor update path; Plesk can update non-PHP components as well.
p2s_panel_update() {
    local log="$P2S_WORK/panel-update.log" status
    local arguments
    case "$P2S_PANEL" in
        cpanel)
            arguments=("$P2S_PANEL_TOOL" --security)
            p2s_message_print info "Requesting critical cPanel security updates before checking website PHP packages." ;;
        plesk)
            arguments=("$P2S_PANEL_TOOL" installer --select-release-current --upgrade-installed-components)
            p2s_message_print warn "Updating installed Plesk components within the current release. This operation can also update databases, mail and web-server components; check those services and applications afterwards." ;;
        *) return 1 ;;
    esac
    p2s_manifest_record panel_update_command "${arguments[*]}"
    P2S_TRANSACTION_ATTEMPTED=true
    # P2S-MUTATION: Runs the installed vendor updater; do not force a release change or rewrite preferences.
    p2s_command_run 1800 "${arguments[@]}" < /dev/null > "$log" 2>&1
    status=$?
    p2s_package_log_report "$log"
    p2s_manifest_record panel_update_exit "$P2S_PANEL|$status"
    # upcp can continue maintenance after its license check blocks the security update.
    if [ "$P2S_PANEL" = cpanel ] && LC_ALL=C grep -Fi 'Blocker found: No license file found.' "$log" >/dev/null; then
        p2s_manifest_record panel_update_diagnostics 'cpanel|license_unavailable|see_vendor_update_log'
        p2s_fix_block panel_license "cPanel could not find its license, so the update could not finish. Please contact support to check the license before trying again. Some changes may already have been made."
        return 1
    fi
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
    p2s_message_print fixmethod "The $P2S_PANEL vendor update command completed. Installed PHP and running processes are checked again."
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
    # A container command being installed is not evidence that this process belongs to it.
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
        p2s_message_print warn "$remaining $process_label from before the update $verb still running or could not be identified reliably (PIDs: $pids). Updating packages does not replace PHP code already loaded by these tasks. Let those tasks finish, or have their administrator safely stop and rerun them, then run this check again. Restarting cron, Apache or PHP-FPM does not reliably replace these tasks. This script did not terminate them."
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
        # Parent evidence helps plan a restart; parent names alone do not prove safe ownership.
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
            [ -z "$label" ] || p2s_message_print info "$label main process started: ${started:-unknown}."
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
                advice="Ask support or your administrator to review this service, then retry."
                if (unit[key] ~ /^(cron|crond)[.]service$/) advice="Cron launched these PHP tasks, but their package-managed command-line runtime could not be verified. Identify the tasks and PHP installation before updating. Restarting cron does not reliably replace existing tasks; the script will not terminate them."
                if (name[key] ~ /^php.*cgi/) advice="These CGI/FastCGI workers need their launcher or supervising service identified before a restart can be planned. Restarting PHP-FPM alone may not replace them. Automatic updates are blocked until the restart target is verified."
                if (unit[key] ~ /^(supervisor|supervisord)[.]service$/) advice="Supervisor manages these PHP applications or background workers. Restarting PHP-FPM alone will not replace them. Ask your administrator to match the process IDs and parent launchers in the service_mapping and process_parent records to individual programs using supervisorctl status with the correct system configuration. A parent launcher may be RoadRunner (rr). Arrange a maintenance window to update PHP and safely replace those programs and their PHP children, then rerun this check. Do not restart all Supervisor programs. Automatic updates remain blocked because this script has no verified restart procedure for these applications."
                print "Automatic updating is paused: we could not verify a safe restart method for " name[key] " (" count[key] (count[key]==1 ? " process" : " processes") "; service " unit[key] "). " advice
            }
        }' "$P2S_WORK/unmapped-services" |
        while IFS= read -r label; do p2s_fix_block service_mapping "$label"; done
    if [ -s "$P2S_WORK/scheduled-php" ]; then
        p2s_message_print info "Scheduled background PHP tasks are running (launched by cron, the task scheduler). These recognised package-managed tasks do not block PHP package updates or supported web-service restarts. Already-running tasks keep their loaded PHP code until they finish; after a successful package update, new tasks use the updated executable. Task PIDs, user IDs and start times are in the run manifest."
    fi
    sort -u "$P2S_WORK/services" -o "$P2S_WORK/services"
    if [ "$unreadable_executables" -gt 0 ] || [ "$unreadable_maps" -gt 0 ]; then
        p2s_message_print warn "We could not fully check some running PHP or web-server processes. Rerun the check; if this continues, ask support to review process access. Details are recorded in the run log."
    fi
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
    # Package lists also contain directories such as /usr/share/php, not PHP executables.
    [ ! -d "$1" ] || return 0
    # Package file lists contain manuals too: never treat php-fpm8.4.8.gz as an engine.
    case "${1##*/}" in
        php-cgi[0-9]*) suffix=${1##*/}; suffix=${suffix#php-cgi} ;;
        php-fpm[0-9]*) suffix=${1##*/}; suffix=${suffix#php-fpm} ;;
        lsphp[0-9]*) suffix=${1##*/}; suffix=${suffix#lsphp} ;;
    esac
    case "$suffix" in *[!0-9.]*) return ;; esac
    # Match the basename: */php[0-9]* would also match configuration below /etc/php8.4/.
    case "$1" in /*) ;; *) return ;; esac
    case "${1##*/}" in
        php|php[0-9]|php[0-9].[0-9]|php-cgi|php-cgi[0-9]*|php-fpm|php-fpm[0-9]*|lsphp|lsphp[0-9]*|sw-engine|sw-engine-fpm|libphp*.so|frankenphp)
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
            P2S_UNKNOWN=true
            p2s_manifest_record inventory_gap "runtime_file|$path|missing_or_not_regular"
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
        # Match paths, not version numbers: two providers can install the same PHP release.
        # A reference does not prove that a process loaded the current on-disk version or serves a website.
        if [ -s "$P2S_WORK/process-runtime-paths" ] &&
            awk -F'|' -v path="$path" -v resolved="$resolved" '$1 == path || $1 == resolved { found=1 } END { exit !found }' "$P2S_WORK/process-runtime-paths"; then
            observation=running_path
        fi
        p2s_manifest_record runtime_observation "$path|$observation"
        case "$path" in *.so)
            state=$(awk -F'|' -v name="$owner" '$1 == name { print $2; exit }' "$P2S_WORK/package-states" 2>/dev/null)
            if [ -n "$state" ]; then
                actual=$(printf '%s\n' "${package_version#*:}" | sed 's/[^0-9.].*//')
                printf '%s|%s|Apache module||%s|%s|%s|%s\n' "$actual" "$state" "$provider" "$package_version" "$(p2s_version_upstream_state "$package_version")" "$observation" >> "$P2S_WORK/summary-versions"
            else
                P2S_UNKNOWN=true
                p2s_manifest_record inventory_gap "module_version|$path|no_assessed_engine_owner"
                p2s_message_print warn "Could not identify the PHP version in Apache module $path; no assessed PHP engine package owns it."
            fi
            continue ;;
        esac
        if [ ! -x "$path" ]; then
            P2S_UNKNOWN=true
            p2s_manifest_record inventory_gap "runtime_version|$path|not_executable"
            p2s_message_print warn "Cannot read the PHP version: $path is not executable."
            continue
        fi
        # Only runtime executables, never php-config, phpize or package-maintenance helpers.
        case "${path##*/}" in php|php[0-9]|php[0-9].[0-9]|php-cgi|php-cgi[0-9]*|php-fpm|php-fpm[0-9]*|lsphp|lsphp[0-9]*|sw-engine|sw-engine-fpm|frankenphp) ;; *) continue ;; esac
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
                # Missing package-manager support is not evidence that an executable is unpackaged.
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
            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$actual" "$state" "$role" "$built" "$provider" "$package_version" "$upstream_state" "$observation" >> "$P2S_WORK/summary-versions"
        else
            probe_status=$?
            P2S_UNKNOWN=true
            # Keep loader/wrapper errors as data, never as customer or protocol messages.
            p2s_manifest_record runtime_probe "$path|exit=$probe_status"
            p2s_manifest_record runtime_error "$path|$output"
            if [ "$owner" = ea-php-cli ] && [ "$probe_status" -eq 2 ] && [ "$output" = 'Default PHP is not configured!' ]; then
                p2s_message_print warn "cPanel's command-line PHP selector at $path has no default PHP version configured. Review the cPanel CLI PHP selection and check the installed versioned website PHP runtimes separately. This check did not choose a default PHP version."
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
    # A successful service command alone does not prove old workers disappeared.
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
    if [ "${P2S_MODE:-check}" = fix ]; then
        prefix='Initial check: '
        if [ "$P2S_PHASE" = afterfix ] &&
            { ${P2S_TRANSACTION_ATTEMPTED:-false} || ${P2S_RESTART_ATTEMPTED:-false}; }; then
            prefix='After update attempt: '
        fi
    fi
    # Keep providers separate: fixed EasyApache and unverified panel PHP can report the same version.
    # Full package revisions, paths and unabridged version output remain in the manifest.
    [ -s "$P2S_WORK/summary-versions" ] || return 0
    sort -u "$P2S_WORK/summary-versions" | awk -F'|' -v prefix="$prefix" '
        {
            key=$1 SUBSEP $2 SUBSEP $5
            if (!(key in version)) { order[++count]=key; version[key]=$1; state[key]=$2; provider[key]=$5 }
            if (!seen_role[key SUBSEP $3]++) roles[key]=roles[key] (roles[key] ? ", " : "") $3
            if ($7 == "Y") affected_upstream[key]=1
            if ($8 != "") evidence[key SUBSEP $8]=1
        }
        END {
            for (i=1; i<=count; i++) {
                key=order[i]; level="info"; conclusion="fixes verified for both PHP2Shell vulnerabilities."
                if (state[key]=="Y") { level="warn"; conclusion="vulnerable; update these components and restart the services using them." }
                if (state[key]=="?") { level="warn"; conclusion="patch status not verified." }
                split(version[key], parts, "[.]")
                if (state[key]=="?" && version[key] ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ &&
                    (parts[1]<5 || (parts[1]==5 && parts[2]<4)))
                    conclusion="outside this detector\047s verified PHP2Shell coverage; review its security support and migrate applications to maintained, patched PHP."
                text=prefix "PHP " version[key] " (" roles[key] "): " conclusion
                source=provider[key]; sub(/ [(](revision|namespace) hint[)]$/, "", source)
                if (source) text=text " Package label: " source "."
                if (state[key]=="N" && affected_upstream[key]) text=text " Your provider added the security fixes without changing the PHP version."
                if (state[key]=="?" && affected_upstream[key]) text=text " A version number alone cannot confirm a vulnerability; ask support to verify or update this build."
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
                p2s_message_print warn "Result: We could not verify whether all PHP installations include both PHP2Shell fixes. See the checks needing attention below, or contact support."
            fi ;;
        N)
            if [ "$P2S_COUNT" -eq 0 ]; then
                p2s_message_print info "Result: No PHP installation was found in the checked packages and runtime locations. No PHP update was identified by this check."
            else
                p2s_message_print info "Result: All detected PHP installations include both PHP2Shell fixes. No PHP restart is pending."
            fi ;;
    esac
    if [ "$P2S_STATE" != N ] && [ -s "$P2S_WORK/summary-versions" ]; then
        # Parallel PHP branches need explicit site/job migration; an unknown backport is not proof of lost support.
        unresolved_versions=$(sort -u "$P2S_WORK/summary-versions" | awk -F'|' '
            $1 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ {
                split($1, parts, "[.]"); branch=parts[1] "." parts[2]
                if (!seen_branch[branch]++) branches++
                if ($2 != "N" && !seen_version[$1]++) versions=versions (versions ? ", " : "") "PHP " $1
            }
            END { if (branches > 1 && versions != "") print versions }')
        if [ -n "$unresolved_versions" ]; then
            p2s_message_print warn "PHP versions needing attention: $unresolved_versions. If your provider cannot supply a fixed package, move the affected websites, applications and scheduled jobs to a supported, patched PHP version. Test them before removing old PHP packages. Changing the default PHP version alone does not move individual websites."
        fi
    fi
}

# Inventory and fix orchestration

p2s_inventory_collect_and_assess() {
    P2S_INVENTORY_MESSAGES=true
    P2S_COUNT=0; P2S_VULNERABLE=false; P2S_UNKNOWN=${P2S_FIX_FAILED:-false}; P2S_RESTART_PENDING=false
    P2S_SEPARATE_ENVIRONMENT_REVIEW=false; P2S_PACKAGE_POLICY_REVIEW=false
    : > "$P2S_WORK/paths.raw"
    p2s_package_inventory_collect
    p2s_package_sources_collect
    p2s_panel_inventory_collect
    p2s_package_inventory_assess
    p2s_process_inventory_collect
    p2s_web_listener_inventory_collect
    p2s_runtime_inventory_collect
    p2s_process_scheduled_php_verify
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
    P2S_INVENTORY_MESSAGES=false
}

p2s_fix_block() {
    P2S_BLOCKED=true
    p2s_message_print "${3:-warn}" "$2"
    p2s_manifest_record blocker "$1|$2"
}

p2s_fix_check_distro_recipe() {
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
        debian:*) [ "$P2S_MAJOR" -ge 12 ] && return 0 ;;
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
    p2s_fix_block unsupported_os "No automatic update recipe for $P2S_DISTRO $P2S_RELEASE. An unsupported OS may need a maintained support provider or migration; archived repositories do not supply new security fixes."
    return 1
}

# These local probes do not refresh repositories, install packages or restart services.
# Fix mode repeats them because a saved check is not permission to bypass changing prerequisites.
p2s_fix_preflight() {
    local low_space name version arch vendor
    if $P2S_BLOCKED; then return 1; fi
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

p2s_fix_report_patchability() {
    local assessment
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
            p2s_message_print warn "Automatic update: The current script cannot complete a fix on this server as it stands. Review the reported blockers or contact support for another approach. No package installation or service restart was attempted."
        elif [ "$P2S_STATE" = Y ] && ! $P2S_UNKNOWN && ! ${P2S_PACKAGE_POLICY_REVIEW:-false} && p2s_command_exists df; then
            assessment=eligible_to_attempt
            p2s_message_print info "Automatic update: This server appears suitable for an update attempt using its existing PHP package sources. The local prerequisite checks passed. Run the update to find out whether patched packages are available and can be installed safely; successful updates and service restarts still need verification."
        else
            assessment=unknown
            p2s_message_print info "Automatic update: No local blocker was found, but this check cannot predict whether an update will resolve the issue. Running the update will check the package sources and report what can be updated; any remaining unverified PHP installations will still need review."
        fi
    fi
    # Keep fix eligibility separate from CVE state; stale metadata is not evidence of a patch candidate.
    p2s_manifest_record patchability "$assessment|scope=host_php|repositories=not_refreshed|candidate_fixes=not_verified|vulnerability=$P2S_STATE|inventory_unknown=$P2S_UNKNOWN|package_policy_review=${P2S_PACKAGE_POLICY_REVIEW:-false}"
}

# P2S-MUTATION: Orchestrates package updates and service restarts after preflight checks.
p2s_fix_run() {
    P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=false; P2S_PANEL_UPDATE_COMPLETED=false
    # Repeating a host update cannot repair an uninspected container when host PHP is already fixed.
    if ! $P2S_BLOCKED && ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} && ! $P2S_RESTART_PENDING && p2s_state_has_only_fixed_versions; then
        p2s_manifest_record host_update 'not_needed|assessed_host_versions=fixed|separate_environment_review_required'
        p2s_message_print info "No further host PHP package update is needed for the assessed versions. Containers or separate application environments still require review."
        return 0
    fi
    p2s_fix_preflight || return 1
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
    case "${P2S_PANEL:-}" in
        cpanel|plesk)
            # P2S-MUTATION: Runs the panel security/component updater before verifying PHP again.
            p2s_panel_update || update_status=$? ;;
    esac
    # Plesk owns its component transaction. cPanel website PHP still needs its own package update.
    if [ "$update_status" -eq 0 ] && [ "${P2S_PANEL:-}" != plesk ]; then
        # P2S-MUTATION: Dispatches to the APT or RPM PHP package update implementation.
        case "$P2S_BACKEND" in deb) p2s_package_deb_update ;; rpm) p2s_package_rpm_update ;; *) return 1 ;; esac
        update_status=$?
    fi
    # Maintainer scripts may already have replaced workers; still verify the saved services.
    local restart_status=0
    # P2S-MUTATION: Replaces workers after an installation attempt or a pending restart.
    if $P2S_TRANSACTION_ATTEMPTED || $P2S_RESTART_PENDING; then p2s_service_restart_and_verify; restart_status=$?; fi
    p2s_manifest_record fix_commands "update_exit=$update_status|restart_exit=$restart_status|restart_attempted=$P2S_RESTART_ATTEMPTED"
    [ "$update_status" -eq 0 ] && [ "$restart_status" -eq 0 ]
}

# Command-line entry point

p2s_main() {
    # Update the revision when script behaviour changes; the checksum separately identifies the loaded functions.
    local mode=check result=0 command script_revision=2026-10-26.1
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
    # Main runs in a subshell so traps/options never leak into a caller that sources this script.
    trap 'rm -rf "$P2S_WORK"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export LC_ALL=C
    p2s_manifest_record schema 'php2shell-v1|CVE_2026_109618|covers=CVE-2026-109618,CVE-2026-109619|rules=2026-10-25'
    p2s_manifest_record script_revision "$script_revision"
    p2s_manifest_record source_preservation 'policy=explicit_provider_migrations_only|script_repository_changes=none|APT_Sury_candidates=provider_branch_architecture_and_exact_version_guarded|other_providers_and_panel_transactions_require_separate_review'
    p2s_manifest_record bash "$BASH_VERSION"
    # SSH can deliver source on stdin; $0 would identify Bash, not the delivered script.
    # Fingerprint loaded functions instead; cksum is optional and is not an integrity proof.
    if p2s_command_exists cksum; then
        p2s_manifest_record function_checksum "$(declare -f | cksum)"
    else
        p2s_manifest_record function_checksum unavailable
    fi
    for command in timeout sleep perl mktemp dpkg-query dpkg apt-get apt-cache rpm dnf yum pacman vercmp wget curl systemctl service; do
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
    p2s_fix_check_distro_recipe
    if [ "$mode" = check ]; then p2s_fix_report_patchability; fi
    printf 'dss:isvulnerable:beforefix: CVE_2026_109618%s\n' "$P2S_STATE"
    if [ "$mode" = fix ] && [ "$P2S_STATE" != N ]; then
        # Share the legacy lock so scripts deployed under either name cannot patch concurrently.
        if ! mkdir /var/run/rh-php2shell.lock 2>/dev/null; then
            p2s_fix_block lock "Another PHP update may be running, or its lock remains at /var/run/rh-php2shell.lock. Check before retrying."
            result=1
        else
            trap 'rmdir /var/run/rh-php2shell.lock; rm -rf "$P2S_WORK"' EXIT
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
        if ! $P2S_TRANSACTION_ATTEMPTED && ! $P2S_RESTART_ATTEMPTED; then
            if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} && p2s_state_has_only_fixed_versions; then
                p2s_message_print warn "Automatic changes were skipped. The assessed host PHP versions have verified fixes, but containers or separate application environments still require review. No PHP package installation or service restart was attempted. Review those environments and any other reported blockers; rerunning a host package update alone will not resolve the separate-environment check."
            else
                p2s_message_print error "We could not apply an automatic update. No PHP package installation or service restart was attempted. Review the messages above or contact support."
            fi
            p2s_manifest_record fix_outcome 'blocked|package_install_attempted=false|service_restart_attempted=false'
        else
            if [ "$result" -eq 0 ] && [ "$P2S_STATE" = '?' ]; then
                p2s_message_print error "The update attempt finished, but we could not verify that all PHP installations are patched. Review the warnings or contact support."
            else
                p2s_message_print error "The update could not be completed or verified. Packages or services may have changed. Review the messages and check your websites before retrying, or contact support."
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
Usage: dephp2shell.sh [--check|--fix|--disruptive] [options]

  --check           Check PHP without package changes or service restarts (default).
  --fix             Attempt supported updates through existing package sources or panels.
  --disruptive      Reserved for future approaches; currently makes no changes.
  --output FORMAT   human (default) or machine (structured records for integrations).
  --log-dir DIR     Save full diagnostics in a private timestamped subdirectory of DIR.
  --color WHEN      auto (default), always or never; only human console accents.
  --no-color        Disable colour; bold is controlled separately.
  --bold WHEN       auto (default), always or never; emphasise labels and results.
  --no-bold         Disable bold emphasis.
  --help, -h        Show this help without inspecting or changing the server.

Linux only. Other operating systems exit before inventory or log creation.
DP2S_OUTPUT, DP2S_LOG_DIR, DP2S_COLOR and DP2S_BOLD set defaults.
Nonempty NO_COLOR disables colour by default; explicit options take precedence.
Auto styling leaves pipes plain; machine output is always unstyled.
Human output saves logs under $HOME/dephp2shellinfo/runs by default.
Machine output creates no persistent logs unless a log directory is specified.

Updates and service restarts can interrupt applications. Plesk's updater can
also update non-PHP components. No repositories are added, PHP providers switched,
operating systems upgraded, reboots performed or applications shut down by this tool.
EOF
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
            --disruptive) disruptive=true ;;
            --no-color) color=never ;;
            --no-bold) bold=never ;;
            --output|--log-dir|--color|--bold)
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
    if $disruptive; then
        printf '%s\n' 'Disruptive updates are not implemented yet. Stay tuned. No changes were made.' >&2
        return 69
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
