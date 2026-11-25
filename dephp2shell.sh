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
# DePHP2Shell: the default checks October PHP2Shell. --november-2026 selects the November release.
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

p2s_vulnerability_result() {
    local issue=CVE_2026_109618
    if ${P2S_NOVEMBER:-false}; then issue=CVE_2026_126714; fi
    printf 'dss:isvulnerable:%s: %s%s\n' "$1" "$issue" "$2"
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
            # APT also embeds a PHP LTS subscription URL path in local index filenames.
            gsub(/php[.]freexian[.]com_c_[^ \t\r\n\014\013]+/, "[Freexian PHP LTS index name redacted]", line)
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
        if ${P2S_NOVEMBER:-false}; then
            # https://www.php.net/archive/2026.php (19 November security releases and 8.6.0 GA)
            case "$minor" in 0|1) printf 'Y\n'; return ;; 2) floor=36 ;; 3) floor=37 ;; 4) floor=28 ;; 5) floor=13 ;; 6) floor=0 ;; *) printf '?\n'; return ;; esac
        else
            case "$minor" in 0|1) printf 'Y\n'; return ;; 2) floor=35 ;; 3) floor=36 ;; 4) floor=27 ;; 5) floor=12 ;; *) printf '?\n'; return ;; esac
        fi
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
    # Jammy mirror builds share the reviewed Debian revision/hash, unlike the PPA builds.
    case "$P2S_DISTRO:$P2S_RELEASE:${3:-}" in
        ubuntu:22.04:*+0~*) suffix='ubuntu22.04~1' ;;
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
    if [ "$P2S_DISTRO" = debian ] || [ "$suffix" = ubuntu22.04~1 ]; then
        printf '%s\n' "$revision+$suffix.gbp$release"
    else
        revision=${revision%%+0~*}
        case "$name" in php7.0-*|libapache2-mod-php7.0) revision=7.0.33-92 ;; php7.1-*|libapache2-mod-php7.1) revision=7.1.33-80 ;; esac
        printf '%s\n' "$revision+$suffix"
    fi
}

p2s_version_sury_backport_fixed() {
    local fixed=${6:-} source=${1#libapache2-mod-} branch suffix serial build
    source=${source%%-*}
    [ "$4" = "$source" ] && [ "$5" = "$2" ] || return 1
    if [ -z "$fixed" ]; then
        fixed=$(p2s_version_sury_fixed_build_output "$1" "$3" "$2") || return 1
        [ "$2" = "$fixed" ]
        return
    fi
    # November: compare revisions within the same branch, epoch and repository's build format.
    # Example: 7.3.33-43+debsuryorg13.1+2 can follow 7.3.33-42+debsuryorg13.1+1.
    [ "$2" != "$fixed" ] || return 0
    branch=${fixed%%-*}; branch=${branch%.*}
    suffix=${fixed#*+}; suffix=${suffix%+*}
    serial=${2##*+}
    case "$serial" in ''|*[!0-9]*) return 1 ;; esac
    case "$2" in "$branch".*"+$suffix+$serial") ;; *) return 1 ;; esac
    build=${2%"+$suffix+$serial"}
    printf '%s\n' "${build#"$branch".}" | LC_ALL=C grep -Eq '^[0-9]+-[0-9]+(\.[0-9]+)*$' || return 1
    p2s_command_exists dpkg && dpkg --compare-versions "$2" ge "$fixed"
}

p2s_version_sury_november_build_output() {
    local name=$1 arch=$2 version=$3 branch release layout=mirror revision suffix=+php
    p2s_package_is_engine "$name" || return 1
    branch=${name#libapache2-mod-}; branch=${branch%%-*}
    case "$P2S_DISTRO:$P2S_RELEASE:$version" in
        ubuntu:22.04:*+deb.sury.org+[0-9]*|ubuntu:24.04:*+deb.sury.org+[0-9]*) layout=ppa; release=$P2S_RELEASE ;;
        debian:12:*|debian:12.*:*) release=12 ;;
        debian:13:*|debian:13.*:*) release=13 ;;
        ubuntu:22.04:*|ubuntu:24.04:*|ubuntu:26.04:*) release=$P2S_RELEASE ;;
        *) return 1 ;;
    esac
    # The current mirror rebuilds have no +php suffix. Keep the earlier reviewed revisions below.
    case "$layout:$arch:$version" in
        mirror:amd64:*"+debsuryorg$release.1+"[0-9]*|mirror:arm64:*"+debsuryorg$release.1+"[0-9]*|mirror:armhf:*"+debsuryorg$release.1+"[0-9]*)
            case "$branch" in
                php5.6) revision=5.6.40-110 ;;
                php7.0) revision=7.0.33-98 ;;
                php7.1) revision=7.1.33-86 ;;
                php7.2) revision=7.2.34-71 ;;
                php7.3) revision=7.3.33-42 ;;
                php7.4) revision=1:7.4.33-38 ;;
                php8.0) revision=1:8.0.30-32 ;;
                php8.1) revision=8.1.34-15 ;;
                *) return 1 ;;
            esac
            printf '%s\n' "$revision+debsuryorg$release.1+1"
            return ;;
    esac
    case "$layout:$release:$arch" in
        *:amd64|*:arm64|ppa:*:armhf|ppa:*:ppc64el|mirror:12:armhf|mirror:13:armhf|mirror:26.04:armhf) ;;
        *) return 1 ;;
    esac
    # Earlier signed builds checked against their source patch series. See docs/sury-backport-evidence.md.
    case "$layout:$branch" in
        ppa:php5.6) revision=5.6.40-109 ;;
        ppa:php7.0) revision=7.0.33-97 ;;
        ppa:php7.1) revision=7.1.33-85 ;;
        mirror:php5.6) revision=5.6.40-110; suffix='' ;;
        mirror:php7.0) revision=7.0.33-98; suffix='' ;;
        mirror:php7.1) revision=7.1.33-86; suffix='' ;;
        ppa:php7.2) revision=7.2.34-70 ;;
        ppa:php7.3|mirror:php7.3)
            case "$layout:$release" in ppa:*|mirror:12|mirror:13) ;; *) return 1 ;; esac
            revision=7.3.33-41 ;;
        *:php7.4) revision=1:7.4.33-37 ;;
        *:php8.0) revision=1:8.0.30-31 ;;
        *:php8.1) revision=8.1.34-14 ;;
        *) return 1 ;;
    esac
    if [ "$layout" = ppa ]; then printf '%s\n' "$revision+ubuntu$release.1+deb.sury.org+1"
    else printf '%s\n' "$revision+debsuryorg$release.1$suffix+1"; fi
}

p2s_backports_suite() {
    [ "${P2S_BACKEND:-}" = deb ] || return 1
    case "$P2S_DISTRO:${P2S_RELEASE%%.*}:$P2S_RELEASE" in
        debian:6:*) printf 'squeeze\n' ;; debian:7:*) printf 'wheezy\n' ;; debian:8:*) printf 'jessie\n' ;;
        debian:9:*) printf 'stretch\n' ;; debian:10:*) printf 'buster\n' ;;
        ubuntu:*:14.04) printf 'trusty\n' ;; ubuntu:*:16.04) printf 'xenial\n' ;;
        ubuntu:*:18.04) printf 'bionic\n' ;; ubuntu:*:20.04) printf 'focal\n' ;;
        *) return 1 ;;
    esac
}

p2s_backports_source() {
    local name=${1%:*}
    case "$name" in libapache2-mod-php*) name=${name#libapache2-mod-}; name=${name%filter} ;; libphp*-embed) name=${name#lib} ;; esac
    name=${name%%-*}
    case "$name" in php5|php[0-9].[0-9]) printf '%s\n' "$name" ;; *) return 1 ;; esac
}

# Exact standard builds reviewed from v2026.11.25. Updating these requires reviewing the signed indexes and source.
p2s_backports_build() {
    local suite=$1 source=$2 arch=$3 revision release
    case "$arch:$suite" in amd64:*|all:*|arm64:buster|arm64:focal) ;; *) return 1 ;; esac
    case "$suite:$source" in
        squeeze:php5) printf '5.4.45-1+animaa6~squeeze|debian7\n'; return ;;
        wheezy:php5) printf '5.4.45-0+deb7u30+animaa4|debian\n'; return ;;
        jessie:php5) printf '5.6.40+dfsg-0+deb8u23+animaa3|debian\n'; return ;;
        jessie:php5.6|jessie:php7.1) release=debian8 ;;
        stretch:php5.6|stretch:php7.3|stretch:php7.4) release=debian9 ;;
        buster:php5.6|buster:php7.4) release=debian10 ;;
        trusty:php5.6|trusty:php7.4) release=ubuntu14.04 ;;
        xenial:php5.6|xenial:php7.3|xenial:php7.4) release=ubuntu16.04 ;;
        bionic:php5.6|bionic:php7.2|bionic:php7.4) release=ubuntu18.04 ;;
        focal:php5.6|focal:php7.2|focal:php7.4) release=ubuntu20.04 ;;
        *) return 1 ;;
    esac
    case "$source" in
        php5.6) revision=5.6.40-110 ;; php7.1) revision=7.1.33-86 ;; php7.2) revision=7.2.34-71 ;;
        php7.3) revision=7.3.33-42 ;; php7.4) revision=1:7.4.33-38 ;;
    esac
    printf '%s+debsuryorg12.1+1+%s+animaa1|sury\n' "$revision" "$release"
}

p2s_backports_installed_fixed() {
    local source suite build
    source=$(p2s_backports_source "$1") && [ "$source" = "$4" ] && [ "$2" = "$5" ] &&
        suite=$(p2s_backports_suite) && build=$(p2s_backports_build "$suite" "$source" "$3") || return 1
    [ "$2" = "${build%%|*}" ] && return 0
    case "$suite:$source:$3:$2" in
        squeeze:php5:amd64:5.4.45-1+animaa6~compat1~squeeze|wheezy:php5:amd64:5.4.45-0+deb7u30+animaa4~compat1) return 0 ;;
    esac
    return 1
}

# Exact source revisions reviewed from the signed StackX main indexes of 25 November 2026.
# Review the effective source before adding or advancing a revision.
p2s_stackx_published_build() {
    local revision
    case "$1:$2" in
        stretch:php5.6) revision='5.6.40-60+0~20220627.67+debian9~1.gbp1f7ffd+sxphp.20261124.1' ;;
        stretch:php7.0) revision='7.0.33-60+0~20220627.68+debian9~1.gbp3d361a+sxphp.20261124.1' ;;
        stretch:php7.1) revision='7.1.33-47+0~20220627.68+debian9~1.gbp1fc917+sxphp.20261124.1' ;;
        stretch:php7.2) revision='7.2.34-32+0~20220627.74+debian9~1.gbpc7fa3c+sxphp.20261124.1' ;;
        stretch:php7.3) revision='7.3.33-4+0~20220627.98+debian9~1.gbp40b3e4+sxphp.20261124.1' ;;
        stretch:php7.4) revision='1:7.4.30-3+0~20220627.69+debian9~1.gbpf2b381+sxphp.20261124.1' ;;
        stretch:php8.0) revision='1:8.0.20-2+0~20220625.38+debian9~1.gbpde2407+sxphp.20261124.1' ;;
        stretch:php8.1) revision='8.1.7-2+0~20220625.22+debian9~1.gbp4d1949+sxphp.20261124.1' ;;
        buster:php5.6) revision='5.6.40-77+0~20240606.85+debian10~1.gbpd4d5eb+sxphp.20261124.1' ;;
        buster:php7.0) revision='7.0.33-75+0~20240606.88+debian10~1.gbpce193b+sxphp.20261124.1' ;;
        buster:php7.1) revision='7.1.33-63+0~20240606.93+debian10~1.gbpa08c53+sxphp.20261124.1' ;;
        buster:php7.2) revision='7.2.34-50+0~20240606.95+debian10~1.gbpf31532+sxphp.20261124.1' ;;
        buster:php7.3) revision='7.3.33-19+0~20240606.119+debian10~1.gbp87e0d7+sxphp.20261124.1' ;;
        buster:php7.4) revision='1:7.4.33-13+0~20240606.93+debian10~1.gbp3bbf86+sxphp.20261124.1' ;;
        buster:php8.0) revision='1:8.0.30-7+0~20240606.65+debian10~1.gbpe57fd4+sxphp.20261124.1' ;;
        buster:php8.1) revision='8.1.29-1+0~20240606.65+debian10~1.gbp2ddf4e+sxphp.20261124.1' ;;
        buster:php8.2) revision='8.2.20-2+0~20240608.57+debian10~1.gbp6b5ea6+sxphp.20261124.1' ;;
        buster:php8.3) revision='8.3.8-2+0~20240608.35+debian10~1.gbp4d7dbc+sxphp.20261124.1' ;;
        bullseye:php5.6) revision='5.6.40-105+0~20261022.135+debian11~1.gbp37a17e+sxphp.20261124.1' ;;
        bullseye:php7.0) revision='7.0.33-93+0~20261022.119+debian11~1.gbp952195+sxphp.20261124.1' ;;
        bullseye:php7.1) revision='7.1.33-81+0~20261022.128+debian11~1.gbpa88ccf+sxphp.20261124.1' ;;
        bullseye:php7.2) revision='7.2.34-66+0~20261021.122+debian11~1.gbpe0bcd4+sxphp.20261124.1' ;;
        bullseye:php7.3) revision='7.3.33-35+0~20261021.144+debian11~1.gbpecf76f+sxphp.20261124.1' ;;
        bullseye:php7.4) revision='1:7.4.33-31+0~20261021.121+debian11~1.gbpe9c428+sxphp.20261124.1' ;;
        bullseye:php8.0) revision='1:8.0.30-25+0~20261021.88+debian11~1.gbpabebea+sxphp.20261124.1' ;;
        bullseye:php8.1) revision='8.1.34-9+0~20261021.82+debian11~1.gbp4e430a+sxphp.20261124.1' ;;
        bullseye:php8.2) revision='8.2.35-1+0~20261021.94+debian11~1.gbp8bff78+sxphp.20261124.1' ;;
        bullseye:php8.3) revision='8.3.36-1+0~20261021.88+debian11~1.gbp250f7c+sxphp.20261124.1' ;;
        bullseye:php8.4) revision='8.4.27-1+0~20261021.57+debian11~1.gbp7636b9+sxphp.20261124.1' ;;
        bullseye:php8.5) revision='8.5.12-1+0~20261021.27+debian11~1.gbp1a3e8a+sxphp.20261124.1' ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$revision"
}

p2s_version_is_stackx() {
    case "$1" in *+sxphp.*|*+sxphp2shell*) return 0 ;; esac
    return 1
}

p2s_stackx_suite() {
    case "$P2S_BACKEND:$P2S_DISTRO:${P2S_RELEASE%%.*}" in
        deb:debian:9) printf 'stretch\n' ;;
        deb:debian:10) printf 'buster\n' ;;
        deb:debian:11) printf 'bullseye\n' ;;
        *) return 1 ;;
    esac
}

p2s_stackx_scope() {
    ${P2S_NOVEMBER:-false} && [ "${P2S_PANEL:-none}" = none ] && p2s_stackx_suite >/dev/null
}

p2s_stackx_reviewed_november_build() {
    local suite
    [ "$2" = amd64 ] && suite=$(p2s_stackx_suite) && p2s_stackx_published_build "$suite" "$1"
}

p2s_version_november_package_reference() {
    local name=$1 version=$2 vendor=$3 arch=$4 provider upstream release='' branch family affected='' fixed=''
    provider=$(p2s_package_provider "$name" "$vendor" "$version")
    case "$P2S_BACKEND:$P2S_DISTRO:$provider" in
        deb:debian:StackX*)
            branch=$(p2s_backports_source "$name") && fixed=$(p2s_stackx_reviewed_november_build "$branch" "$arch") ;;
        deb:*:debian-php-backports*)
            branch=$(p2s_backports_source "$name") && release=$(p2s_backports_suite) &&
                fixed=$(p2s_backports_build "$release" "$branch" "$arch") && fixed=${fixed%%|*} ;;
        deb:debian:Debian)
            # DLA-4916-1 and DSA-6641-1 cover the November update in the native security archives.
            case "${P2S_RELEASE%%.*}:$name:$version" in
                12:php8.2-*:*~deb12u*|12:libapache2-mod-php8.2:*~deb12u*)
                    affected=8.2.35-1~deb12u1; fixed=8.2.36-1~deb12u1 ;;
                13:php8.4-*:*~deb13u*|13:libapache2-mod-php8.4:*~deb13u*)
                    affected=8.4.27-1~deb13u1; fixed=8.4.28-1~deb13u1 ;;
                # Freexian Extended LTS builds require separate signed APT origin evidence.
                11:php7.4-*:*+deb11u*|11:libapache2-mod-php7.4:*+deb11u*)
                    affected=7.4.33-1+deb11u14; fixed=7.4.33-1+deb11u15 ;;
                10:php7.3-*:*~deb10u*|10:libapache2-mod-php7.3:*~deb10u*)
                    affected=7.3.31-1~deb10u16; fixed=7.3.31-1~deb10u17 ;;
                9:php7.0-*:*+deb9u*|9:libapache2-mod-php7.0:*+deb9u*)
                    affected=7.0.33-0+deb9u26; fixed=7.0.33-0+deb9u27 ;;
            esac ;;
        deb:ubuntu:Ubuntu)
            case "$version" in *ubuntu*)
                affected=$(p2s_version_deb_fixed_floor "$name")
                # Canonical's accepted security uploads document all applicable November fixes.
                # Jammy's earlier session upload progress disable covers CVE-2026-115560.
                case "$P2S_RELEASE:$name" in
                    26.10:php8.5-*|26.10:libapache2-mod-php8.5) fixed=8.5.9-0ubuntu2.2 ;;
                    26.04:php8.5-*|26.04:libapache2-mod-php8.5) fixed=8.5.4-0ubuntu1.6 ;;
                    24.04:php8.3-*|24.04:libapache2-mod-php8.3) fixed=8.3.6-0ubuntu0.24.04.14 ;;
                    22.04:php8.1-*|22.04:libapache2-mod-php8.1) fixed=8.1.2-1ubuntu2.29 ;;
                    # Canonical's November ESM builds. APT origin permission is assessed separately.
                    20.04:php7.4-*|20.04:libapache2-mod-php7.4) fixed=7.4.3-4ubuntu2.29+esm6 ;;
                    18.04:php7.2-*|18.04:libapache2-mod-php7.2) fixed=7.2.24-0ubuntu0.18.04.17+esm15 ;;
                    16.04:php7.0-*|16.04:libapache2-mod-php7.0) fixed=7.0.33-0ubuntu0.16.04.16+esm23 ;;
                    14.04:php5-*|14.04:libapache2-mod-php5|14.04:libapache2-mod-php5filter) fixed=5.5.9+dfsg-1ubuntu4.29+esm19 ;;
                esac ;;
            esac ;;
        deb:*:Sury/*)
            # October's reviewed legacy backports lack the separate CVE-2026-126714 session-file fix.
            affected=$(p2s_version_sury_fixed_build_output "$name" "$arch" "$version") || affected=
            fixed=$(p2s_version_sury_november_build_output "$name" "$arch" "$version") || fixed= ;;
        rpm:almalinux:AlmaLinux|rpm:rocky:Rocky\ Linux)
            case "$provider:$vendor" in
                AlmaLinux:AlmaLinux|'Rocky Linux:Rocky Enterprise Software Foundation') ;;
                *) printf '|\n'; return ;;
            esac
            case "$provider:$P2S_MAJOR:$arch" in
                *:*:x86_64|*:*:aarch64|*:*:ppc64le|*:*:s390x|AlmaLinux:10:x86_64_v2|'Rocky Linux:10:riscv64') ;;
                *) printf '|\n'; return ;;
            esac
            # The EL10 php8.4 family is distinct from the default php package family.
            case "$name" in
                php|php-cli|php-common|php-cgi|php-fpm|php-embedded|php-phpdbg) family=php ;;
                php8.4|php8.4-cli|php8.4-common|php8.4-cgi|php8.4-fpm|php8.4-embedded|php8.4-phpdbg) family=php8.4 ;;
                *) printf '|\n'; return ;;
            esac
            release=${version#0:}; upstream=${release%%-*}; branch=${upstream%.*}
            # https://almalinux.org/blog/2026-11-19-php-security-release/
            # The reviewed Alma 7.4 and 8.0 builds retain the unconditional session upload progress disable.
            case "$provider:$P2S_MAJOR:$family:$branch" in
                AlmaLinux:8:php:7.2) affected=7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1 ;;
                AlmaLinux:8:php:7.3) affected=7.3.20-1.module_el8.10.0+4316+90ea5fe5.alma.1 ;;
                AlmaLinux:8:php:7.4)
                    affected=7.4.33-8.module_el8.10.0+4321+cf5fd4bb
                    # ALSA-2026:100991 and the preceding Alma build apply the November fixes for this stream.
                    # https://errata.almalinux.org/8/ALSA-2026-100991.html
                    # https://git.almalinux.org/rpms/php/src/commit/22a520b3518479c6c26e02677afc2a4c73dd6cb8/SPECS/php.spec
                    case "$release" in
                        *.alma.*) fixed=7.4.33-8.module_el8.10.0+4379+4cffe92b.alma.1 ;;
                        *) fixed=7.4.33-9.module_el8.10.0+4385+9e3d9df0 ;;
                    esac ;;
                AlmaLinux:8:php:8.0) affected=8.0.30-1.module_el8.10.0+4319+26f10322.alma.1 ;;
                AlmaLinux:8:php:8.2)
                    affected=8.2.33-1.module_el8.10.0+4320+c30d6dbb.alma.1
                    fixed=8.2.35-1.module_el8.10.0+4381+cf144917.alma.1 ;;
                AlmaLinux:9:php:8.0)
                    affected=8.0.30-8.el9_8.alma.1
                    # The stock rebuild and the earlier Alma backport have separate fixed floors.
                    # https://errata.almalinux.org/9/ALSA-2026-102297.html
                    # https://git.almalinux.org/rpms/php/src/commit/7d508466d7b36e1fa43c0bfedefe2e1cc27b7c0a/SPECS/php.spec
                    case "$release" in
                        *.alma.*) fixed=8.0.30-8.el9_8.1.alma.1 ;;
                        *)
                            if [ "$release" = 8.0.30-8.el9_8.1 ]; then affected=$release; fi
                            fixed=8.0.30-8.el9_9.2 ;;
                    esac ;;
                AlmaLinux:9:php:8.1) affected=8.1.32-1.module_el9.8.0+326+528679fc.alma.1 ;;
                AlmaLinux:9:php:8.2)
                    affected=8.2.33-1.module_el9.8.0+327+37dfd4b4.alma.1
                    fixed=8.2.35-1.module_el9.9.0+360+bfa5da00.alma.1 ;;
                AlmaLinux:9:php:8.3)
                    affected=8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1
                    fixed=8.3.36-1.module_el9.9.0+361+ab310fe6.alma.1 ;;
                AlmaLinux:9:php:8.4)
                    affected=8.4.27-1.module_el9.9.0+340+d5af24ac
                    fixed=8.4.27-1.module_el9.9.0+362+e3c29387.alma.1 ;;
                AlmaLinux:10:php:8.3)
                    affected=8.3.33-1.el10_2.alma.1
                    if [ "$release" = 8.3.36-1.el10_2 ]; then affected=$release; fi
                    fixed=8.3.36-1.el10_2.alma.1 ;;
                AlmaLinux:10:php8.4:8.4) affected=8.4.27-2.el10_3.1; fixed=8.4.27-2.el10_3.1.alma.1 ;;
            esac
            # Rocky's AppStream RPM changelogs identify the November backport floors.
            # https://download.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/Packages/p/
            # https://download.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/p/
            case "$provider:$arch:$P2S_MAJOR:$family:$branch" in
                'Rocky Linux:x86_64:8:php:7.2'|'Rocky Linux:aarch64:8:php:7.2')
                    affected=7.2.24-1.module+el8.4.0+413+c9202dda ;;
                'Rocky Linux:x86_64:8:php:7.3'|'Rocky Linux:aarch64:8:php:7.3')
                    affected=7.3.20-1.module+el8.4.0+414+2e7afcdd ;;
                'Rocky Linux:x86_64:8:php:8.0'|'Rocky Linux:aarch64:8:php:8.0')
                    affected=8.0.30-1.module+el8.10.0+1605+02e07af7 ;;
                'Rocky Linux:x86_64:8:php:7.4'|'Rocky Linux:aarch64:8:php:7.4')
                    affected=7.4.33-8.module+el8.10.0+40393+c071e357
                    case "$release" in
                        7.4.33-9.module+el8.10.0+40479+a65e1b9e) fixed=$release ;;
                        *) fixed=7.4.33-8.module+el8.10.0+40472+363a2c29.0.1 ;;
                    esac ;;
                'Rocky Linux:x86_64:8:php:8.2'|'Rocky Linux:aarch64:8:php:8.2')
                    affected=8.2.35-1.module+el8.10.0+40394+d21b33fb
                    fixed=8.2.35-1.module+el8.10.0+40473+6f592aac.0.1 ;;
                'Rocky Linux:'*:9:php:8.0)
                    # RLSA-2026:102297 keeps PHP 8.0.30 and backports the November fixes.
                    # https://apollo.build.resf.org/RLSA-2026:102297
                    affected=8.0.30-8.el9_8.1
                    fixed=8.0.30-8.el9_9.2 ;;
                'Rocky Linux:'*:9:php:8.1)
                    affected=8.1.32-1.module+el9.7.0+40003+454ed3c4 ;;
                'Rocky Linux:'*:9:php:8.2)
                    affected=8.2.35-1.module+el9.8.0+40395+2f706e64
                    fixed=8.2.35-1.module+el9.9.0+40474+554e1069.0.1 ;;
                'Rocky Linux:'*:9:php:8.3)
                    affected=8.3.36-1.module+el9.8.0+40396+4e680bb7
                    fixed=8.3.36-1.module+el9.9.0+40475+972eba12.0.1 ;;
                'Rocky Linux:'*:9:php:8.4)
                    affected=8.4.27-1.module+el9.9.0+40418+929a11b6
                    fixed=8.4.27-1.module+el9.9.0+40476+dc5d3092.0.1 ;;
                'Rocky Linux:'*:10:php:8.3)
                    # https://apollo.build.resf.org/RLSA-2026:102300
                    affected=8.3.36-1.el10_2
                    fixed=8.3.37-1.el10_3 ;;
                'Rocky Linux:'*:10:php8.4:8.4)
                    # https://apollo.build.resf.org/RLSA-2026:100821
                    affected=8.4.27-2.el10_3.1
                    fixed=8.4.28-1.el10_3 ;;
            esac ;;
        rpm:*:'Remi (revision hint)')
            case "$P2S_DISTRO" in rocky|almalinux|centos|rhel|ol) ;; *) printf '|\n'; return ;; esac
            case "$P2S_MAJOR:$arch" in [89]:x86_64|[89]:aarch64|10:x86_64|10:aarch64) ;; *) printf '|\n'; return ;; esac
            case "$vendor" in
                "Remi's RPM repository <https://rpms.remirepo.net/>"|"Remi's RPM repository <https://rpms.remirepo.net/> "*) ;;
                *) printf '|\n'; return ;;
            esac
            release=${version#0:}; upstream=${release%%-*}; branch=${upstream%.*}
            family=php${branch/./}-php
            # Compare exact reviewed RPMs, including installation type and the EL major.
            # php-cli 0:8.1.34-7.module_php.8.1.el8.remi and php81-php-cli 0:8.1.34-7.el8.remi.
            case "$name" in
                php|php-cli|php-common|php-cgi|php-fpm|php-embedded|php-phpdbg)
                    family=".module_php.$branch.el$P2S_MAJOR.remi" ;;
                "$family"|"$family"-cli|"$family"-common|"$family"-cgi|"$family"-fpm|"$family"-embedded|"$family"-phpdbg)
                    family=".el$P2S_MAJOR.remi" ;;
                *) printf '|\n'; return ;;
            esac
            # Remi's older-branch backports use the November fixes and session mitigation from PHP 8.2.36.
            # https://blog.remirepo.net/post/2026/01/08/PHP-8.1-is-retired
            case "$P2S_MAJOR:$branch" in
                8:7.2) affected=7.2.34-31$family; fixed=7.2.34-32$family ;;
                8:7.3) affected=7.3.33-24$family; fixed=7.3.33-25$family ;;
                *:7.4) affected=7.4.33-31$family; fixed=7.4.33-32$family ;;
                *:8.0) affected=8.0.30-21$family; fixed=8.0.30-22$family ;;
                *:8.1) affected=8.1.34-6$family; fixed=8.1.34-7$family ;;
            esac
            # EL10 rebuilt these fixed branches against its new libpq.
            case "$P2S_MAJOR:$release" in
                "10:7.4.33-33$family"|"10:8.0.30-23$family"|"10:8.1.34-8$family") fixed=$release ;;
            esac ;;
        rpm:centos:CentOS)
            case "$name" in
                php|php-cli|php-common|php-cgi|php-fpm|php-embedded|php-phpdbg) family=php ;;
                php8.4|php8.4-cli|php8.4-common|php8.4-cgi|php8.4-fpm|php8.4-embedded|php8.4-phpdbg) family=php8.4 ;;
                *) printf '|\n'; return ;;
            esac
            release=${version#0:}
            case "$arch" in x86_64|aarch64|ppc64le|s390x) ;; *) printf '|\n'; return ;; esac
            case "$P2S_MAJOR:$family:$release" in
                # Stock CentOS archives predate this release. These exact builds have no November backport.
                # https://vault.centos.org/7.9.2009/os/x86_64/Packages/
                # https://vault.centos.org/8.5.2111/AppStream/x86_64/os/Packages/
                # https://vault.centos.org/8-stream/AppStream/x86_64/os/Packages/
                7:php:5.4.16-48.el7|\
                8:php:7.2.24-1.module_el8.2.0+313+b04d0a66|8:php:7.3.20-1.module_el8.2.0+498+4deef2f1|\
                8:php:7.4.19-1.module_el8.5.0+815+1c4fd2e5|8:php:7.4.33-1.module_el8+782+1d7d8122|\
                8:php:8.0.30-1.module_el8+783+92a67490|8:php:8.2.13-1.module_el8+765+677b369c)
                    if [ "$arch" = x86_64 ]; then affected=$release; fi ;;
                # CentOS Stream has its own build identifiers and release schedule.
                # https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/Packages/
                9:php:8.0.30-9.el9|9:php:8.1.27-1.module_el9+790+4812d76d|\
                9:php:8.2.35-1.module_el9+1447+c2e1e9ab|9:php:8.3.36-1.module_el9+1448+8542a8fd|\
                9:php:8.4.27-1.module_el9+1449+ae7b4724) affected=$release ;;
                # https://mirror.stream.centos.org/10-stream/AppStream/x86_64/os/Packages/
                10:php:8.3.36-1.el10) affected=$release; fixed=8.3.37-1.el10 ;;
                10:php:8.3.37-1.el10) fixed=$release ;;
                10:php8.4:8.4.27-2.el10) affected=$release; fixed=8.4.28-1.el10 ;;
                10:php8.4:8.4.28-1.el10) fixed=$release ;;
            esac ;;
        rpm:*:'cPanel internal')
            case "$name:$arch:${version#0:}" in
                cpanel-php81:x86_64:*~el[789])
                    # The official November EL7/8/9 RPM changelogs list the applicable fixes.
                    affected=8.1.34-2.cp110~${version##*~}
                    fixed=8.1.34-3.cp110~${version##*~} ;;
            esac ;;
        rpm:*:'cPanel EasyApache')
            # EA4 25.98 and the official EL7/8 RPM indexes identify the exact stock backport.
            case "$vendor:$arch:$P2S_MAJOR" in 'cPanel, Inc.:x86_64:'[78])
                case "$name" in
                    ea-php74-php|ea-php74-php-cli|ea-php74-php-common|ea-php74-php-fpm|ea-php74-php-litespeed)
                        fixed=7.4.34-3.3.1.cpanel
                        case "$P2S_MAJOR" in
                            7) affected=7.4.34-2.2.5.cpanel ;;
                            8) affected=7.4.34-2.2.3.cpanel ;;
                        esac ;;
                esac ;;
            esac
            case "$P2S_DISTRO:$vendor:$arch:$P2S_MAJOR:$name" in
                cloudlinux:CloudLinux:x86_64:[789]:ea-php74-php*) release=1:7.4.34-2 ;;
                cloudlinux:CloudLinux:x86_64:[789]:ea-php80-php*) release=1:8.0.31-2 ;;
                cloudlinux:CloudLinux:x86_64:[789]:ea-php81-php*) release=1:8.1.35-2 ;;
            esac
            if [ -n "$release" ]; then
                affected=$release.el$P2S_MAJOR.cloudlinux.1
                fixed=$release.el$P2S_MAJOR.cloudlinux.2
            fi ;;
        rpm:cloudlinux:'CloudLinux/TuxCare alt-PHP (namespace hint)')
            # CloudLinux's EL8/9 source RPMs and November bulletin identify these legacy builds.
            case "$vendor:$arch:$P2S_MAJOR:$name" in
                CloudLinux:x86_64:[89]:alt-php74-*) fixed=7.4.33-84.el$P2S_MAJOR ;;
                CloudLinux:x86_64:[89]:alt-php80-*) fixed=8.0.30-72.el$P2S_MAJOR ;;
                CloudLinux:x86_64:[89]:alt-php81-*) fixed=8.1.34-43.el$P2S_MAJOR ;;
            esac ;;
    esac
    printf '%s|%s\n' "$affected" "$fixed"
}

p2s_version_november_rpm_at_least() {
    local version=$1 fixed=$2 branch layout suffix='' result
    branch=${fixed%%-*}; branch=${branch%.*}; branch=${branch/./[.]}
    # Keep the stock and Alma rebuild series separate, even when RPM sorts a stock revision higher.
    case "$fixed" in *.alma.*) suffix='\.alma\.[0-9]+' ;; esac
    case "$fixed" in
        *.module+el*) layout="module\\+el$P2S_MAJOR\\.[0-9]+\\.0\\+[0-9]+\\+[0-9a-f]{8}(\\.[0-9]+)*" ;;
        *.module_el*) layout="module_el$P2S_MAJOR\\.[0-9]+\\.0\\+[0-9]+\\+[0-9a-f]{8}$suffix" ;;
        *.el*) layout="el${P2S_MAJOR}(_[0-9]+)?(\\.[0-9]+)*$suffix" ;;
        *) return 1 ;;
    esac
    # Match the native RPM release format before passing package metadata to Lua.
    printf '%s\n' "$version" | LC_ALL=C grep -Eq "^$branch\\.[0-9]+-[0-9]+(\\.[0-9]+)*\\.$layout$" || return 1
    case "$version" in *[!0-9A-Za-z.+_-]*) return 1 ;; esac
    # RPM 4.14 compares version or release segments individually, rather than a full EVR.
    result=$(p2s_command_run 10 rpm --eval "%{lua: local cmp = rpm.vercmp('${version%%-*}', '${fixed%%-*}'); if cmp == 0 then cmp = rpm.vercmp('${version#*-}', '${fixed#*-}') end; print(cmp)}" 2>/dev/null) || return 1
    [ "$result" = 0 ] || [ "$result" = 1 ]
}

p2s_version_november_package_state() {
    local name=$1 version=$2 vendor=$3 arch=$4 upstream=$5 reference affected fixed comparison=eq series serial source
    reference=$(p2s_version_november_package_reference "$name" "$version" "$vendor" "$arch")
    affected=${reference%%|*}; fixed=${reference#*|}
    # Compare later native Ubuntu revisions in the same packaging series.
    case "$P2S_BACKEND:$P2S_DISTRO:$(p2s_package_provider "$name" "$vendor" "$version")" in
        deb:*:Sury/*)
            if [ -n "$fixed" ] && p2s_version_sury_backport_fixed "$name" "$version" "$arch" "${6:-}" "${7:-}" "$fixed"; then
                printf 'N\n'; return
            fi
            fixed='' ;;
        deb:debian:Debian|deb:ubuntu:Ubuntu)
            case "$P2S_DISTRO:${P2S_RELEASE%%.*}" in
                debian:9|debian:10|debian:11)
                    source=${name#libapache2-mod-}; source=${source%%-*}
                    if [ "${6:-}" != "$source" ] || [ "${7:-}" != "$version" ]; then
                        fixed=''; affected=''
                    fi ;;
            esac
            if [ -n "$fixed$affected" ] && p2s_command_exists dpkg; then
                if [ "$P2S_DISTRO" = debian ] && [ "${P2S_RELEASE%%.*}" -ge 12 ]; then
                    comparison=ge
                elif [ -n "$fixed" ]; then
                    case "$P2S_DISTRO:$fixed" in
                        debian:*) series="${fixed%u*}u" ;;
                        ubuntu:*+esm*) series="${fixed%+esm*}+esm" ;;
                        *) series="${fixed%.*}." ;;
                    esac
                    case "$version" in
                        "$series"*)
                            serial=${version#"$series"}
                            case "$serial" in ''|*[!0-9]*) ;; *) comparison=ge ;; esac ;;
                    esac
                fi
                if [ -n "$fixed" ] && dpkg --compare-versions "$version" "$comparison" "$fixed"; then
                    printf 'N\n'; return
                fi
                if [ -n "$affected" ] && dpkg --compare-versions "$version" le "$affected"; then
                    printf 'Y\n'; return
                fi
            fi ;;
        rpm:almalinux:AlmaLinux|rpm:rocky:Rocky\ Linux)
            if [ "$upstream" != N ] && [ -n "$fixed" ] &&
                [ "${version#0:}" != "$fixed" ] && [ "${version#0:}" != "$affected" ] &&
                p2s_version_november_rpm_at_least "${version#0:}" "$fixed"; then
                printf 'N\n'; return
            fi ;;
    esac
    [ "$P2S_BACKEND" != rpm ] || version=${version#0:}
    if [ -n "$fixed" ] && [ "$version" = "$fixed" ]; then
        printf 'N\n'
    elif [ -n "$affected" ] && [ "$version" = "$affected" ]; then
        printf 'Y\n'
    elif [ "$upstream" = N ]; then
        printf 'N\n'
    else
        printf '?\n'
    fi
}

p2s_version_package_state() {
    local name="$1" version="$2" vendor="$3" arch="${4:-unknown}" state floor release source
    if [ "$P2S_BACKEND" = deb ] && p2s_version_is_stackx "$version"; then
        if ${P2S_NOVEMBER:-false} && source=$(p2s_backports_source "$name") &&
            [ "$source" = "${5:-}" ] && [ "$version" = "${6:-}" ] &&
            floor=$(p2s_stackx_reviewed_november_build "$source" "$arch") && [ "$version" = "$floor" ]; then
            printf 'N\n'
        else
            printf '?\n'
        fi
        return
    fi
    state=$(p2s_version_upstream_state "$version")
    case "$version" in *+animaa*)
        if p2s_backports_installed_fixed "$name" "$version" "$arch" "${5:-}" "${6:-}"; then printf 'N\n'
        elif ${P2S_NOVEMBER:-false} && [ "${6:-}" = "$version" ] &&
            release=$(p2s_backports_suite) && source=$(p2s_backports_source "$name") && [ "$source" = "${5:-}" ] &&
            p2s_backports_build "$release" "$source" "$arch" >/dev/null &&
            p2s_backports_legacy_affected "$release" "$source" "$version"; then printf 'Y\n'
        else printf '?\n'; fi
        return ;;
    esac
    if ${P2S_NOVEMBER:-false}; then
        state=$(p2s_version_november_package_state "$name" "$version" "$vendor" "$arch" "$state" "${5:-}" "${6:-}")
        if [ "$state" = '?' ] && [ "${6:-}" = "$version" ] && p2s_command_exists dpkg &&
            release=$(p2s_backports_suite) && source=$(p2s_backports_source "$name") && [ "$source" = "${5:-}" ] &&
            p2s_backports_build "$release" "$source" "$arch" >/dev/null && p2s_backports_legacy_affected "$release" "$source" "$version"; then state=Y; fi
        printf '%s\n' "$state"
        return
    fi
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
            if p2s_version_is_stackx "$3"; then printf 'StackX (revision hint)\n'; return; fi
            case "$3" in
                *+rhphp2shell*) printf 'RimuHosting PHP2Shell backport (revision hint)\n'; return ;;
                *+animaa*) printf 'debian-php-backports (revision hint)\n'; return ;;
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
        StackX*) printf 'https://www.christophe-casalegno.com/en/contributions/stackx-php-maintenance-and-fixes-for-debian-9-10-11/\n' ;;
        Freexian*) printf 'https://www.freexian.com/lts/php/\n' ;;
        debian-php-backports*) printf 'https://github.com/animaartificialis/debian-php-backports\n' ;;
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
    local name="$1" file evidence="$P2S_WORK/backport-evidence" cves='109618|109619'
    if ${P2S_NOVEMBER:-false}; then cves='115560|126714|129182|129289|129291|129474|129481|129496'; fi
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
    LC_ALL=C awk -v cves="CVE-2026-($cves)" '$0 ~ cves { print; count++; if (count==20) exit }' "$evidence" |
        while IFS= read -r file; do p2s_manifest_record backport_mention "$name|$file"; done
}

p2s_november_package_build_report() {
    local name=$1 version=$2 arch=$3 vendor=$4 state=$5 reference previous='' comparison=initial
    reference=$(p2s_version_november_package_reference "$name" "$version" "$vendor" "$arch")
    if [ "$P2S_PHASE" = afterfix ] && [ -r "$P2S_WORK/packages.before" ]; then
        previous=$(awk -F'|' -v n="$name" -v a="$arch" '$1==n && $3==a { print $2; exit }' "$P2S_WORK/packages.before")
        if [ -z "$previous" ]; then comparison=previously_unobserved
        elif [ "$version" = "$previous" ]; then comparison=unchanged
        else comparison=changed; fi
    fi
    p2s_manifest_record package_build_status "$name|architecture=$arch|installed=$version|previous=${previous:-unavailable}|known_affected=${reference%%|*}|verified_fixed=${reference#*|}|comparison=$comparison|state=$state"
    case "$comparison:$state" in
        unchanged:Y) p2s_message_print warn "$name ($arch) is still on affected build $version." ;;
        changed:'?')
            if p2s_version_is_stackx "$version"; then
                p2s_message_print info "$name ($arch) changed from $previous to $version. See the StackX release notes for this build."
            else
                p2s_message_print warn "$name ($arch) changed from $previous to $version. Its November fixes still need verification from the package publisher."
            fi ;;
    esac
}

p2s_installed_deb_native_release() {
    local name=$1 version=$2 arch=$3 provider=$4 source=$5 source_version=$6 target family release marker
    [ "$P2S_BACKEND" = deb ] && [ "$version" = "$source_version" ] &&
        [ "$source" = "$(p2s_backports_source "$name")" ] &&
        [ -s "$P2S_WORK/package-release-mismatches" ] || return 1
    target=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" -v p="$provider" '
        $1==n && $2==v && $3==a && $4==p && $6=="native_ubuntu_version_series" {print "ubuntu|" $5; next}
        $1==n && $2==v && $3==a && $4==p && $6=="binary_version_marker" {print $4 "|" $5}
    ' "$P2S_WORK/package-release-mismatches") || return 1
    family=${target%%|*}; release=${target#*|}
    case "$family:$release" in
        ubuntu:[0-9][0-9].[0-9][0-9]) printf '%s\n' "$target"; return ;;
        Ubuntu:[0-9][0-9].[0-9][0-9])
            marker="^[0-9]+([.][0-9]+)+-0ubuntu0[.]${release/./[.]}[.][0-9]+([+]esm[0-9]+)?"; family=ubuntu ;;
        Debian:[0-9]|Debian:[0-9][0-9])
            marker="^([0-9]+:)?[0-9]+([.][0-9]+)+([+]dfsg[0-9]*)?-[0-9]+([.][0-9]+)*[+~]deb${release}u[0-9]+"; family=debian ;;
        *) return 1 ;;
    esac
    # Restrict the installed-only override to stock revision formats.
    printf '%s\n' "$version" | LC_ALL=C grep -Eq "$marker\$" || return 1
    printf '%s|%s\n' "$family" "$release"
}

p2s_package_inventory_assess() {
    local name version arch vendor state path upstream role provider reason upstream_state source_record source_name source_version required
    local fixed_build comparison summary_reason assessment_release assessment_distro
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
            assessment_distro=$P2S_DISTRO; assessment_release=$P2S_RELEASE
            # sw-engine and FrankenPHP version their containing product, not the embedded PHP engine.
            case "$name" in sw-engine|frankenphp*) state='?'; upstream_state='?' ;;
                *) source_record=
                   if [ -r "$P2S_WORK/deb-source-records" ]; then
                       source_record=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4 FS $5]++ {print $4 "|" $5}' "$P2S_WORK/deb-source-records")
                   fi
                   source_name=${source_record%%|*}; source_version=${source_record#*|}
                   if ${P2S_NOVEMBER:-false} &&
                       required=$(p2s_installed_deb_native_release "$name" "$version" "$arch" "$provider" "$source_name" "$source_version"); then
                       assessment_distro=${required%%|*}; assessment_release=${required#*|}
                       p2s_manifest_record package_advisory_release "$name|$version|$arch|build=$assessment_distro $assessment_release|host=$P2S_DISTRO $P2S_RELEASE|scope=installed_assessment"
                   fi
                   state=$(P2S_DISTRO=$assessment_distro P2S_RELEASE=$assessment_release \
                       p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$source_name" "$source_version")
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
            if ${P2S_NOVEMBER:-false}; then
                case "$name" in sw-engine|frankenphp*) ;; *)
                    P2S_DISTRO=$assessment_distro P2S_RELEASE=$assessment_release \
                        p2s_november_package_build_report "$name" "$version" "$arch" "$vendor" "$state" ;;
                esac
            else case "$P2S_BACKEND:$provider" in deb:Sury/*)
                fixed_build=$(p2s_version_sury_fixed_build_output "$name" "$arch" "$version")
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
            esac; fi
            printf '%s|%s\n' "$name" "$state" >> "$P2S_WORK/package-states"
            upstream=$(printf '%s\n' "${version#*:}" | sed 's/[^0-9.].*//')
            [ -n "$upstream" ] || upstream="unrecognised version ($name)"
            if [ "$P2S_PHASE" = afterfix ] && ${P2S_PANEL_UPDATE_COMPLETED:-false} && [ "$state" != N ]; then
                case "$P2S_PANEL:$name" in
                    cpanel:cpanel-php84|cpanel:cpanel-php81)
                        required='8.4.27 or later in the PHP 8.4 branch'
                        if [ "$name" = cpanel-php81 ]; then required='cPanel PHP 8.1.34-2.cp110'; fi
                        if ${P2S_NOVEMBER:-false}; then
                            required='8.4.28 or later in the PHP 8.4 branch'
                            if [ "$name" = cpanel-php81 ]; then required='the reviewed cPanel PHP 8.1.34-3.cp110 x86_64 RPM'; fi
                        fi
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
                *) printf '%s|%s|%s||%s|%s|%s|package|%s|%s|%s|%s\n' "$upstream" "$state" "$role" "$provider" "$version" "$upstream_state" "$summary_reason" "$name" "$fixed_build" "$arch" >> "$P2S_WORK/summary-versions" ;;
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
    local record kind missing file note=''
    : > "$P2S_WORK/apt-policy-records"
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
            if ($2 ~ /^https?:\/\/php[.]freexian[.]com\/c\// && role!="other_available")
                print "freexian_php_lts|" name "|" version "|" role "|cached_index_match"
        }
        END { candidate() }' "$P2S_WORK/apt-policy" | p2s_manifest_redact_repository_urls > "$P2S_WORK/apt-policy-records"
    while IFS='|' read -r kind record; do
        case "$kind" in
            candidate) p2s_manifest_record apt_package_candidate "$record" ;;
            priority) p2s_manifest_record apt_version_priority "$record" ;;
            repository_match) p2s_manifest_record package_repository_match "$record" ;;
            freexian_php_lts) p2s_manifest_record freexian_php_lts_package "$record" ;;
        esac
    done < "$P2S_WORK/apt-policy-records"
    missing=$(awk -F'|' '$1=="missing" { printf "%s%s", separator, $2; separator=", " }' "$P2S_WORK/apt-policy-records")
    if [ -n "$missing" ]; then
        P2S_PACKAGE_POLICY_REVIEW=true
        if grep '^missing|.*|1$' "$P2S_WORK/apt-policy-records" >/dev/null; then
            note=' Negative APT priorities were reported for at least one of these packages; they prohibit matching versions and can also block dependent PHP components.'
        fi
        for file in /etc/apt/preferences.d/debian-virtualmin-restricted-packages /etc/apt/preferences.d/ubuntu-virtualmin-restricted-packages; do
            if [ -f "$file" ]; then
                note="$note Review $file as well as other APT preferences."
                if grep '^missing|libapache2-mod-php[^|]*|1$' "$P2S_WORK/apt-policy-records" >/dev/null; then
                    p2s_message_print warn "Virtualmin's configuration tool normally creates $file to prevent installation of Apache's embedded PHP module (mod_php), favouring PHP-FPM and separate website users. An installed mod_php package now has no candidate and a negative APT priority; this can also hold back other PHP security updates. Inspect the file and effective package priorities before changing policy."
                    p2s_message_print warn "Manual path: check every website's PHP handler in Virtualmin. PHP-FPM may already be running, but that alone does not prove every website uses it. Move any remaining mod_php sites to a supported, patched FPM version and test them; if all sites already use FPM, review removal of the unused mod_php packages while keeping Virtualmin's restriction. Check Apache configuration and .htaccess files for php_value, php_flag and php_admin_* directives before disabling or removing the module; review an apt-get -s remove simulation with the exact unused package names first."
                    p2s_message_print warn "Alternative: if mod_php is still required, an administrator can add a narrow APT exception for its installed package names and intended Debian/Ubuntu source, then retry --fix. Changing the pin alone does not change website handlers; it allows mod_php package updates, and Virtualmin configuration can recreate its restriction. Adding Sury does not remove an APT pin. No package removal, PHP handler change or pin override is automatic."
                    p2s_message_print info "Read-only checks: apache2ctl -M; apache2ctl -S; apt-cache policy 'libapache2-mod-php*'; apt-mark showhold. Virtualmin's PHP execution-mode guidance: https://www.virtualmin.com/docs/server-components/php-execution-modes/"
                fi
            fi
        done
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
        function release(version, name, label) {
            series=0
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
                    } else {
                        sub(/:.*/, "", name); sub(/^libapache2-mod-/, "", name); sub(/filter$/, "", name)
                        # Published Ubuntu archive series with no release number in the revision.
                        # 7.4.3-4ubuntu2.29+esm6 identifies Ubuntu 20.04.
                        if (name ~ /^php5(-|$)/ && version ~ /^5[.]5[.]9[+]dfsg-1ubuntu4([.][0-9]+)?([+]esm[0-9]+)?$/) label="14.04"
                        if (name ~ /^php7[.]4(-|$)/ && version ~ /^7[.]4[.]3-4ubuntu2([.][0-9]+)?([+]esm[0-9]+)?$/) label="20.04"
                        if (name ~ /^php8[.]1(-|$)/ && version ~ /^8[.]1[.]2-1ubuntu2([.][0-9]+)?([+]esm[0-9]+)?$/) label="22.04"
                        if (name ~ /^php8[.]5(-|$)/ && version ~ /^8[.]5[.]4-0ubuntu1([.][0-9]+)?$/) label="26.04"
                        if (name ~ /^php8[.]5(-|$)/ && version ~ /^8[.]5[.]9-0ubuntu2([.][0-9]+)?$/) label="26.10"
                        series=(label!="")
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
            revision=$2; target=release(revision, $1); evidence=(series ? "native_ubuntu_version_series" : "binary_version_marker")
            if (target=="" && ($1 FS $2 FS $3) in source) {
                revision=source[$1 FS $2 FS $3]; target=release(revision, $1); evidence="source_version_marker"
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
    # One warning per OS release; show each build once with at most two example package names.
    # php7.1-cli/common/json at version 7.1.33-45 -> 7.1.33-45 (php7.1-cli, php7.1-common and 1 other).
    awk -F'|' '{
        release=$4 FS $5; build=$2
        if ($6=="source_version_marker") build=build "; source " $7
        key=release FS build
        if (!(release in seen_release)) {seen_release[release]=1; releases[++release_count]=release}
        if (!(key in count)) {order[++build_count]=key; labels[key]=build; targets[key]=release}
        if (!seen[key FS $1]++ && ++count[key]<=2) names[key]=names[key] (names[key] ? ", " : "") $1
    } END {
        for (i=1;i<=build_count;i++) {
            key=order[i]; release=targets[key]; extra=count[key]-2
            if (extra>0) names[key]=names[key] " and " extra (extra==1 ? " other" : " others")
            details[release]=details[release] (details[release] ? "; " : "") labels[key] " (" names[key] ")"
        }
        for (i=1;i<=release_count;i++) print releases[i] FS details[releases[i]]
    }' "$P2S_WORK/package-release-mismatches" |
        while IFS='|' read -r family target details; do
            case "$P2S_DISTRO:$family" in
                debian:Ubuntu|ubuntu:Debian)
                    p2s_message_print warn "PHP packages built for another distribution are installed: $details. Their build labels identify $family $target; this server runs $P2S_DISTRO $P2S_RELEASE. Full package lists are in the diagnostic report. Review replacements built for this server's distribution and release. Use apt-cache policy PACKAGE to inspect installed and candidate versions and their sources." ;;
                *) p2s_message_print warn "PHP packages from an older OS release are still installed: $details. Their build labels identify $family $target; this server runs $P2S_DISTRO $P2S_RELEASE. Full package lists are in the diagnostic report. Review these packages and the PHP installations using them before choosing an update or migration." ;;
            esac
        done
    return 0
}

p2s_deb_leftover_removal_preview() {
    local installation=$1 package_list=$2 package extra
    local plan="$P2S_WORK/leftover-removal-plan" engine=false
    local -a names
    [ "$P2S_BACKEND" = deb ] && [ "${P2S_MODE:-check}" = check ] &&
        p2s_command_exists apt-get || return 0
    IFS=', ' read -r -a names <<< "$package_list"
    [ "${#names[@]}" -gt 0 ] || return 0
    for package in "${names[@]}"; do
        case "$package" in [a-z0-9]*) ;; *) return 0 ;; esac
        case "$package" in *[!a-z0-9.+:-]*) return 0 ;; esac
        if p2s_package_is_engine "${package%:*}"; then engine=true; fi
    done
    $engine || return 0
    if ! p2s_command_run 30 apt-get -s -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
        -o APT::Get::AutomaticRemove=false remove -- "${names[@]}" > "$plan" 2>&1; then
        p2s_manifest_record package_release_removal_preview "$installation|simulation_failed"
        return 0
    fi
    p2s_manifest_record package_release_removal_preview "$installation|simulation_only
$(awk '/^(Remv|Purg|Inst|Conf) /' "$plan")"
    extra=$(awk -v requested="$package_list" '
        BEGIN {gsub(/,/, " ", requested); n=split(requested,names); for(i=1;i<=n;i++) selected[names[i]]=1}
        /^(Remv|Purg|Inst) / && (!($2 in selected) || $1=="Inst") {
            if (!seen[$2]++ && ++count<=5) print $2
        }
    ' "$plan" | paste -sd, -)
    if [ -n "$extra" ]; then
        p2s_message_print warn "APT's removal preview for $installation includes other package changes ($extra). Review the proposed changes and migrate any dependent applications before removing these packages."
    fi
}

# A process snapshot can show use, but cannot prove that websites or future jobs no longer need PHP.
p2s_package_release_usage_report() {
    local path name family target installation usage references packages package_summary label qualifier complete=false
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
            if (!seen_package[key FS $1]++ && ++package_count[key]<=2)
                examples[key]=examples[key] (examples[key] ? ", " : "") $1
        }
        END {for (i=1;i<=count;i++) {
            key=order[i]; stem=group[key]; use="unverified"; evidence="none"
            if (running[stem]) {use="running"; evidence=references[stem]}
            else if (configured[stem]) {use="configured"; evidence=config[stem]}
            else if (complete=="true" && !incomplete && known[key] && observed[stem]) use="no_running_use_observed"
            extra=package_count[key]-2
            summary=examples[key] (extra>0 ? " and " extra (extra==1 ? " other" : " others") : "")
            print key FS use FS evidence FS packages[key] FS summary
        }}' "$P2S_WORK/release-usage-observations" "$P2S_WORK/package-release-mismatches" |
        while IFS='|' read -r family target installation usage references packages package_summary; do
            p2s_manifest_record package_release_usage "installation=$installation|target=$family $target|usage=$usage|packages=$packages|evidence=$references|usage_assessment_complete=$complete"
            case "$usage" in
                no_running_use_observed|unverified) p2s_deb_leftover_removal_preview "$installation" "$packages" ;;
            esac
            packages=$package_summary
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
        p2s_message_print warn "Another package-manager operation is holding a required lock${pid:+ (PID $pid)}. Ask an administrator to investigate the owning operation's progress and logs before retrying. This script will not terminate that job or remove lock files."
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
        p2s_message_print warn "The package manager could not resolve the update with its current settings. Review the package rules and available versions in the run manifest."
        # APT: php8.2-common : Breaks: php8.2-apcu (< 5.1.23-1~) but 5.1.22+4.0.11-2 is to be installed.
        # Accept package relationships only. Other diagnostics may contain private repository data.
        LC_ALL=C awk '
            /^[ \t]+[a-z0-9][a-z0-9+.:_-]* : (Breaks|Conflicts|Depends|PreDepends): [a-z0-9][a-z0-9+.:_-]*( \([<>=]+ [a-zA-Z0-9.+:~_-]+\))? but ([a-zA-Z0-9.+:~_-]+ is to be installed|it is not (going to be installed|installable))$/ {
                sub(/^[ \t]+/, "")
                if (!seen[$0]++) { print; if (++count == 3) exit }
            }' "$1" | while IFS= read -r details; do
            p2s_message_print warn "APT reported a dependency problem. $details."
        done
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
            p2s_message_print warn "$2"
            P2S_BLOCKED=true
            p2s_manifest_record blocker "$P2S_PACKAGE_FAILURE|Package metadata could not be refreshed. See the repository diagnostics." ;;
        authentication:deb)
            p2s_message_print warn "$2"
            reason="repository signature verification failed"
            if LC_ALL=C grep -F NO_PUBKEY "$1" >/dev/null; then
                reason="a repository signing key is missing (NO_PUBKEY)"
            fi
            p2s_fix_block repositories "Package-list refresh stopped because $reason. APT may retain old indexes for the failed repository even when other lists are current. Use the reported repository and possible source files to investigate the signing error in the detailed log. Repair that repository's signing configuration, or disable it if no longer needed, then retry." ;;
        *) p2s_fix_block repositories "$2" ;;
    esac
}

# Guarded Debian and RPM package updates

p2s_package_deb_is_sury() {
    # Revision families, not generic +0~/PPA hints or Debian maintainer names.
    # Sury mirror revisions include +0~20261021.82+ubuntu22.04~1.gbp4e430a,
    # +debsuryorg12.1+php+1, +debsuryorg12.1+1 and +0~deb.sury.org.1+debian12.
    # PPA ends in +deb.sury.org+1.
    printf '%s\n' "$1" | LC_ALL=C awk '
        /\+deb[.]sury[.]org\+[0-9]+$/ {ok=1}
        /\+0~[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][.][0-9]+\+(debian[0-9]+|ubuntu[0-9][0-9][.][0-9][0-9])~[0-9]+[.]gbp[0-9a-f]+$/ {ok=1}
        /\+debsuryorg[0-9]+([.][0-9]+)+(\+php)?\+[0-9]+$/ {ok=1}
        /\+0~deb[.]sury[.]org[.][0-9]+\+(debian[0-9]+|ubuntu[0-9][0-9][.][0-9][0-9])$/ {ok=1}
        END {exit !ok}'
}

p2s_package_deb_sury_trust_preflight() {
    local file kind key value line blocked=false
    # APT normally verifies repository signatures. Explicit trust overrides defeat that guarantee.
    p2s_command_exists apt-config && p2s_command_run 30 apt-config dump > "$P2S_WORK/apt-config" 2>/dev/null || {
        p2s_fix_block source_authentication "apt-config dump failed or apt-config is missing. Check the APT configuration before refreshing package lists."; return 1;
    }
    # apt-config dump: APT::Get::AllowUnauthenticated "true"; -> authentication_override|key|true
    # The dump has effective values, not the names of the files that supplied them.
    if ! awk '{
        key=tolower($1); value=$0; sub(/^[^ \t]+[ \t]+"/,"",value); sub(/";[ \t\r]*$/,"",value)
        normal=tolower(value); kind=""
        if (key ~ /(allowunauthenticated|allowinsecurerepositories|allowweakrepositories|allowdowngradetoinsecurerepositories)$/ && normal ~ /^(1|true|yes|on|enable)$/) kind="authentication_override"
        if (key ~ /verify-(peer|host)$/ && normal ~ /^(0|false|no|off|disable)$/) kind="authentication_override"
        if (key=="dir" && normal!="/") kind="custom_source_paths"
        if (key=="dir::etc" && normal!="etc/apt" && normal!="/etc/apt") kind="custom_source_paths"
        if (key=="dir::etc::sourcelist" && normal!="sources.list" && normal!="/etc/apt/sources.list") kind="custom_source_paths"
        if (key=="dir::etc::sourceparts" && normal!="sources.list.d" && normal!="/etc/apt/sources.list.d") kind="custom_source_paths"
        if (kind!="") {
            display_key=$1
            if (display_key !~ /^[a-zA-Z0-9:._+\/-]+$/) display_key="[nonstandard APT key redacted]"
            gsub(/[\001-\037\177|]/,"?",value)
            print kind "|" display_key "|" value
        }
        }' "$P2S_WORK/apt-config" > "$P2S_WORK/apt-trust-settings"; then
        p2s_fix_block source_authentication "Could not read authentication settings from apt-config dump. Review the APT configuration before retrying."
        return 1
    fi
    if ! p2s_manifest_redact_repository_urls < "$P2S_WORK/apt-trust-settings" > "$P2S_WORK/apt-trust-settings.redacted"; then
        p2s_fix_block source_authentication "Could not write the redacted APT authentication report. Check temporary disk space and permissions."
        return 1
    fi
    while IFS='|' read -r kind key value; do
        p2s_manifest_record apt_trust_setting "effective_config|reason=$kind|key=$key|value=$value|origin_file=unverified"
        case "$kind" in
            authentication_override) p2s_fix_block source_authentication "Effective APT setting $key=$value weakens package/repository authentication or TLS verification. Review /etc/apt/apt.conf, /etc/apt/apt.conf.d and any APT_CONFIG file; apt-config dump does not identify the defining file. No trust settings were changed." ;;
            custom_source_paths) p2s_fix_block source_authentication "Effective APT setting $key=$value redirects source lookup outside the paths checked by this script. A custom path is not itself evidence of disabled authentication. Review /etc/apt/apt.conf, /etc/apt/apt.conf.d and any APT_CONFIG file; the defining file is unverified. No source paths were changed." ;;
        esac
        blocked=true
    done < "$P2S_WORK/apt-trust-settings.redacted"
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        # sources.list: deb [trusted=yes] https://packages.sury.org/php bookworm main
        # Deb822 php.sources can also fold "Trusted:" onto a following indented "yes".
        # Report only the option and its line, never source contents, credentials or signing keys.
        if ! awk '
            /^[ \t]*#/ {next}
            /^[ \t]*$/ {key=""; next}
            {
                line=tolower($0); sub(/\r$/,"",line)
                rest=line
                while (match(rest,/(^|[ \t\[])(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)[ \t]*=[ \t]*(yes|true|1|on|enable)([ \t\]]|$)/)) {
                    option=substr(rest,RSTART,RLENGTH); gsub(/[ \t\[\]]/,"",option); split(option,parts,"=")
                    print NR "|" parts[1] "|" parts[2]; rest=substr(rest,RSTART+RLENGTH)
                }
                if (line ~ /^[a-z-]+:/) {
                    key=line; sub(/:.*/,"",key); key_line=NR; sub(/^[^:]*:[ \t]*/,"",line)
                } else if (line !~ /^[ \t]/) key=""
                sub(/^[ \t]*/,"",line)
                if (key ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)$/ && line ~ /^(yes|true|1|on|enable)([ \t]|$)/) {
                    sub(/[ \t].*$/,"",line); print key_line "|" key "|" line
                }
            }
            ' "$file" > "$P2S_WORK/apt-source-trust-settings"; then
            p2s_manifest_record apt_trust_setting "$file|read_or_assessment_failed"
            p2s_fix_block source_authentication "Could not read authentication settings in APT source file $file. Check the file and rerun the check."
            return 1
        fi
        while IFS='|' read -r line key value; do
            p2s_manifest_record apt_trust_setting "$file|line=$line|reason=source_override|key=$key|value=$value"
            p2s_fix_block source_authentication "APT source $file line $line sets $key=$value, bypassing part of repository authentication. Review this definition and its publisher key; replacing a signing key alone does not remove this override. No trust settings were changed."
            blocked=true
        done < "$P2S_WORK/apt-source-trust-settings"
    done
    ! $blocked
}

p2s_freexian_suite() {
    case "${P2S_NOVEMBER:-false}:$P2S_DISTRO:${P2S_RELEASE%%.*}" in
        true:debian:9) printf 'stretch|php7.0\n' ;;
        true:debian:10) printf 'buster|php7.3\n' ;;
        true:debian:11) printf 'bullseye|php7.4\n' ;;
        *) return 1 ;;
    esac
}

p2s_freexian_native_scope() {
    local scope branch engine_branch name version arch vendor found=false
    scope=$(p2s_freexian_suite) || return 1
    branch=${scope#*|}
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 1 ;; esac
    [ "${P2S_BACKEND:-}" = deb ] && [ -r "$P2S_WORK/packages" ] || return 1
    while IFS='|' read -r name version arch vendor; do
        case "${name%:*}" in php|php-cli|php-cgi|php-fpm|php-phpdbg|php[0-9].[0-9]|libapache2-mod-php) continue ;; esac
        p2s_package_is_engine "$name" || continue
        if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ]; then
            engine_branch=$(p2s_backports_source "$name") && grep -Fxq -- "$engine_branch" "$P2S_APT_PHASE_BRANCHES" || continue
        fi
        case "${name%:*}" in "$branch"-*|libapache2-mod-"$branch") ;; *) return 1 ;; esac
        case "$branch:$arch" in
            *:amd64|*:i386|*:armhf|php7.3:arm64|php7.4:arm64) ;; *) return 1 ;;
        esac
        [ "$(p2s_package_provider "$name" "$vendor" "$version")" = Debian ] || return 1
        found=true
    done < "$P2S_WORK/packages"
    $found
}

p2s_freexian_signed_indexes() {
    local scope suite release keyring lists signature
    local fingerprint=AB597C4F6F3380BD4B2BEBC2A07310D369055D5A
    scope=$(p2s_freexian_suite) || return 1
    suite=${scope%%|*}
    P2S_FREEXIAN_SIGNED_SUITES=' '
    lists=$(p2s_command_run 30 apt-config shell lists Dir::State::lists/d 2>/dev/null) || return 1
    [ "$lists" = "lists='/var/lib/apt/lists/'" ] && p2s_command_exists gpgv || return 1
    for release in "$suite" "$suite-lts"; do
        signature=/var/lib/apt/lists/deb.freexian.com_extended-lts_dists_${release}_InRelease
        [ -f "$signature" ] || continue
        for keyring in /usr/share/keyrings/*freexian*.gpg /etc/apt/keyrings/*freexian*.gpg /etc/apt/trusted.gpg.d/*freexian*.gpg; do
            [ -f "$keyring" ] || continue
            if p2s_command_run 20 gpgv --homedir "$P2S_WORK" --keyring "$keyring" --status-fd 1 "$signature" \
                > "$P2S_WORK/freexian-signature" 2>/dev/null &&
                awk -v key="$fingerprint" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==key || $NF==key) {ok=1} END {exit !ok}' "$P2S_WORK/freexian-signature"; then
                P2S_FREEXIAN_SIGNED_SUITES="$P2S_FREEXIAN_SIGNED_SUITES$release "
                p2s_manifest_record freexian_repository "$release|signature=$fingerprint"
                break
            fi
        done
    done
    [ "$P2S_FREEXIAN_SIGNED_SUITES" != ' ' ]
}

p2s_backports_signed_index() {
    local suite=$1 lists keyring signature
    lists=$(p2s_command_run 30 apt-config shell lists Dir::State::lists/d 2>/dev/null) || return 1
    [ "$lists" = "lists='/var/lib/apt/lists/'" ] && p2s_command_exists gpgv || return 1
    signature=/var/lib/apt/lists/animaartificialis.github.io_debian-php-backports_dists_${suite}_InRelease
    [ -f "$signature" ] || return 1
    for keyring in /usr/share/keyrings/*debian-php-backports*.gpg /etc/apt/keyrings/*debian-php-backports*.gpg; do
        [ -f "$keyring" ] || continue
        p2s_backports_verify_release "$suite" "$signature" "$keyring" && return 0
    done
    return 1
}

p2s_backports_verify_release() {
    local suite=$1 signature=$2 keyring=$3 fingerprint=32E998308C448BF6CC57BD7BFEE348611F66C3D6
    local release="$P2S_WORK/backports-release"
    rm -f -- "$release" || return 1
    p2s_command_run 20 gpgv --homedir "$P2S_WORK" --keyring "$keyring" --status-fd 1 --output "$release" "$signature" > "$P2S_WORK/backports-signature" 2>/dev/null &&
        awk -v key="$fingerprint" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==key || $NF==key) {ok=1} END {exit !ok}' "$P2S_WORK/backports-signature" &&
        grep -Fxq "Suite: $suite" "$release" && grep -Fxq "Codename: $suite" "$release" &&
        grep -Fxq 'Origin: debian-php-backports' "$release" || return 1
    p2s_manifest_record debian_php_backports_repository "$suite|signature=$fingerprint"
}

# The uncompressed Packages digests from the reviewed v2026.11.25 snapshot
# bind each Package/Architecture/Version tuple to its binary SHA256.
p2s_backports_index_sha256() {
    awk -F'|' -v suite="$1" -v component="$2" -v arch="$3" '
        $1==suite && $2==component && $3==arch {print $4; found=1}
        END {exit !found}
    ' <<'EOF'
bionic|sury|amd64|9c79fbc0544c2ddf797b420c6cb16e30c82daa3e7716394bf2d0a743200e0cd1
buster|sury|amd64|393869ce9bda2830f676e467110deeaab4a6a5ae6b4f5743de5b7be7d941c0dc
buster|sury|arm64|67d6d27992d0b0856f86611a30eb4d4b0e50c807183068d8772a3d81696071e2
focal|sury|amd64|15d368cd557329d5069336a892929249bbaa7eae299f0c646738d4cdf28acecf
focal|sury|arm64|90d63f1555ff3615bc08e106889bbf64c233691631f07c484ab6e4602f1266e2
jessie|debian|amd64|a9a0aed2df0671006bb3d9e5a1ed27bedbe3dbe22f83fae7d9251ebdd87dcb3a
jessie|sury|amd64|a955e85dd95cca85fa7710da8e5472f5d6eeb0a844aa2189d49e89cfe8b18b0b
squeeze|debian7-compat|amd64|f7826ad51aff0b8600acc88745a0524a36999242e52898a92d7e29d2c9944623
squeeze|debian7|amd64|6c2802f0be8f97381d88b98c043378b3a59af2fbade442009534c849e2d70dd3
stretch|sury|amd64|c20d3dc111235f7af6406a1a6cb1b2a6025421ee2f83d2feec5e79bc29798eb9
trusty|sury|amd64|0f38e1f9cddb6f555ecec77bd9d8569fb78712cf0b70427a1bcd4883326a4bd1
wheezy|debian-compat|amd64|64d04293d0dbcf438de96986ed40deae43c0e48f1f5e018bbe3e12175a0aceb6
wheezy|debian|amd64|38bc2692ac5f961212360820d0f026d552e40e4b8d46778e2e1ce7e244bcd17c
xenial|sury|amd64|3335ec5d3cf192152944ee80d9a2198b7f6e26a67e7c067d9ca3777a091101ee
EOF
}

# Hash the C-sorted Package|Version|Architecture|Component|SHA256 rows
# for each reviewed cohort, excluding unrelated versions and index metadata.
p2s_backports_artifact_sha256() {
    awk -F'|' -v suite="$1" -v component="$2" -v arch="$3" '
        $1==suite && $2==component && $3==arch {print $4; found=1}
        END {exit !found}
    ' <<'EOF'
bionic|sury|amd64|f2fa472375798261b4de956acca2caaa11cc240f26bc4270bfead9b6862e7fee
buster|sury|amd64|be2a7f1f1b4a6e9d1da0a4f6e174a582c7c0caf74a61da830077604e24f02a00
buster|sury|arm64|ef91af8670c94ffabedd4027bdfad9b2c7cc903c9a228b32bb31359450d19ad9
focal|sury|amd64|8001c4ca0b4094236ec7ffd3692c7a0b40feedcbb98cd5da96d08fae2719f29e
focal|sury|arm64|3a6b49fb907d1fb20716c292be6e5187eb41f28d7290bdd6a2dcb552e353dca4
jessie|debian|amd64|142b204d128cc8a9da298a3e4b6e42d55a8e5b249b1dfd59ffe61ee932866871
jessie|sury|amd64|b9f727f5be8ef6d6ef253e7930508e7112f5f2a8067c6783c145b827ae91d9d3
squeeze|debian7|amd64|29c16d5e8b263b67371cb71fbd96515f4fbe4bd477728d151b6ab3968ae54b1f
squeeze|debian7-compat|amd64|72c14b8a863db347a09b2988faa9c700e0790bf3849f3e8f74c4131dc52f8946
stretch|sury|amd64|8911c78fad32176804ba0befa0e65ddc3c8ea35b6104a2d7460e357e90de9f6d
trusty|sury|amd64|cd950517f4affb2ef47f6e9a06839c05d06104cb9b5a99d40e71f4c17bdd5175
wheezy|debian|amd64|74c0f856f4beffd998bc748f55ce3e02b801928b1bc2e34f9344208870c031f2
wheezy|debian-compat|amd64|e86c1bb05f39502680ed3657d53894526d1660280079ec4704a247cbbfb37f54
xenial|sury|amd64|fefb4041c39b291312c730bd236324f66df719d022f4c9e1c64d0a886638cc22
EOF
}

p2s_apt_read_binary_index() {
    case "$1" in
        *_Packages) cat "$1" ;;
        *.gz) p2s_command_run 30 gzip -dc -- "$1" ;;
        *.xz) p2s_command_run 30 xz -dc -- "$1" ;;
        *.lz4|*.zst) p2s_command_run 30 /usr/lib/apt/apt-helper cat-file "$1" ;;
        *) return 1 ;;
    esac
}

p2s_apt_binary_index_hashes() {
    awk -v component="$1" '
        function emit() {
            if (n!="" && v!="" && a!="" && length(h)==64 && h !~ /[^0-9a-f]/)
                print n "|" v "|" a "|" component "|" h
            n=v=a=h=""
        }
        /^Package: / {n=$2}
        /^Version: / {v=$2}
        /^Architecture: / {a=$2}
        /^SHA256: / {h=$2}
        /^$/ {emit()}
        END {emit()}
    ' "$2"
}

p2s_stackx_verify_index() {
    local suite=$1 lists prefix signature keyring index observed expected
    local release="$P2S_WORK/stackx-release"
    local fingerprint=AF97ED98AACE4CE129A03B6E2C9736B593BABF7F
    if [ -n "${2:-}" ]; then
        prefix=$2
    else
        lists=$(p2s_command_run 30 apt-config shell lists Dir::State::lists/d 2>/dev/null) || return 1
        [ "$lists" = "lists='/var/lib/apt/lists/'" ] || return 1
        prefix="/var/lib/apt/lists/mirrors.scalarx.net_stackx-php_${suite}_repo_._"
    fi
    signature="${prefix}InRelease"
    keyring=${P2S_STACKX_KEYRING:-/etc/apt/keyrings/stackx-php.gpg}
    [ -f "$signature" ] && [ -f "$keyring" ] || return 1
    rm -f "$release" || return 1
    p2s_command_run 20 gpgv --homedir "$P2S_WORK" --keyring "$keyring" --status-fd 1 --output "$release" "$signature" \
        > "$P2S_WORK/stackx-signature" 2>"$P2S_WORK/stackx-signature.err" &&
        awk -v key="$fingerprint" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==key || $NF==key) {ok=1} END {exit !ok}' \
            "$P2S_WORK/stackx-signature" || return 1
    if ! { grep -Fxq 'Origin: ScalarX PHP' "$release" && grep -Fxq 'Label: ScalarX PHP' "$release" &&
        grep -Fxq "Suite: $suite" "$release"; }; then
        # The Bullseye feed also published this release identity at the canonical URI.
        [ "$suite" = bullseye ] && grep -Fxq 'Origin: StackX' "$release" &&
            grep -Fxq 'Suite: bullseye-local' "$release" && grep -Fxq 'Codename: bullseye' "$release" || return 1
    fi
    expected=$(awk '
        /^SHA256:$/ {sha=1; next}
        /^[^[:space:]]/ {sha=0}
        sha && $3=="Packages" && length($1)==64 && $1 !~ /[^0-9a-f]/ {hash=$1; count++}
        END {if (count!=1) exit 1; print hash}
    ' "$release") || return 1
    for index in "${prefix}Packages" "${prefix}Packages".*; do
        [ -f "$index" ] || continue
        p2s_apt_read_binary_index "$index" > "$P2S_WORK/stackx-index" || return 1
        observed=$(p2s_command_run 30 sha256sum "$P2S_WORK/stackx-index") || return 1
        [ "${observed%% *}" = "$expected" ] || return 1
        p2s_apt_binary_index_hashes stackx "$P2S_WORK/stackx-index" > "$P2S_WORK/backports-binary-hashes" || return 1
        [ -s "$P2S_WORK/backports-binary-hashes" ] || return 1
        p2s_manifest_record stackx_repository "$suite|signature=$fingerprint|packages_sha256=$expected"
        return 0
    done
    return 1
}

p2s_backports_verify_indexes() {
    local suite=$1 index component arch expected observed
    local prefix=${2:-/var/lib/apt/lists/animaartificialis.github.io_debian-php-backports_dists_${1}_}
    : > "$P2S_WORK/backports-binary-hashes" || return 1
    for index in "$prefix"*_binary-*_Packages "$prefix"*_binary-*_Packages.*; do
        [ -f "$index" ] || continue
        component=${index#"$prefix"}; component=${component%%_binary-*}
        arch=${index#*_binary-}; arch=${arch%%_Packages*}
        if ! expected=$(p2s_backports_index_sha256 "$suite" "$component" "$arch"); then
            p2s_fix_block candidate_checksum "The $suite/$component $arch Backports package index has no reviewed SHA256 pin."
            return 1
        fi
        p2s_apt_read_binary_index "$index" > "$P2S_WORK/backports-index-content" || {
            p2s_fix_block candidate_checksum "Could not read the $suite/$component $arch Backports package index."
            return 1
        }
        observed=$(p2s_command_run 30 sha256sum "$P2S_WORK/backports-index-content") || return 1
        observed=${observed%% *}
        if [ -s "$P2S_WORK/backports-release" ] && ! awk -v path="$component/binary-$arch/Packages" -v hash="$observed" '
            /^SHA256:$/ {sha=1; next}
            /^[^[:space:]]/ {sha=0}
            sha && $1==hash && $3==path {found=1}
            END {exit !found}
        ' "$P2S_WORK/backports-release"; then
            p2s_fix_block candidate_checksum "The $suite/$component $arch Backports index does not match the signed release."
            return 1
        fi
        if [ "$expected" != "$observed" ]; then
            p2s_manifest_record backports_index_checksum "$suite|$component|$arch|expected=$expected|observed=$observed"
            if [ -s "$P2S_WORK/backports-release" ] && p2s_backports_reviewed_artifacts "$suite" "$component" "$arch"; then
                continue
            fi
            p2s_fix_block candidate_checksum "The signed $suite/$component $arch Backports index differs from the reviewed SHA256 snapshot and the reviewed package set could not be verified. Review the publisher's new metadata before using it."
            return 1
        fi
        p2s_manifest_record backports_index_checksum "$suite|$component|$arch|verified=$observed"
        p2s_apt_binary_index_hashes "$component" "$P2S_WORK/backports-index-content" >> "$P2S_WORK/backports-binary-hashes" || return 1
    done
    if [ ! -s "$P2S_WORK/backports-binary-hashes" ]; then
        p2s_fix_block candidate_checksum "APT has no readable reviewed Backports binary index for $suite. Check the configured components and available architectures."
        return 1
    fi
}

p2s_backports_reviewed_artifacts() {
    local suite=$1 component=$2 arch=$3 source build expected observed
    local hashes="$P2S_WORK/backports-index-rows" reviewed="$P2S_WORK/backports-reviewed-rows"
    expected=$(p2s_backports_artifact_sha256 "$suite" "$component" "$arch") || return 1
    p2s_apt_binary_index_hashes "$component" "$P2S_WORK/backports-index-content" > "$hashes" || return 1
    {
        for source in php5 php5.6 php7.1 php7.2 php7.3 php7.4; do
            build=$(p2s_backports_build "$suite" "$source" "$arch") || continue
            if [ "${build#*|}" = "$component" ]; then printf '%s\n' "${build%%|*}"; fi
        done
        case "$suite:$component:$arch" in
            bionic:sury:amd64) printf '%s\n' '2:106~exp1+debsuryorg12.1+1+animaa1' ;;
            squeeze:debian7-compat:amd64) printf '%s\n' '5.4.45-1+animaa6~compat1~squeeze' ;;
            wheezy:debian-compat:amd64) printf '%s\n' '5.4.45-0+deb7u30+animaa4~compat1' ;;
        esac
    } | awk -F'|' 'FILENAME=="-" {versions[$0]=1; next} $2 in versions' - "$hashes" |
        LC_ALL=C sort > "$reviewed" || return 1
    [ -s "$reviewed" ] || return 1
    observed=$(p2s_command_run 30 sha256sum "$reviewed") || return 1
    [ "${observed%% *}" = "$expected" ] || return 1
    cat "$reviewed" >> "$P2S_WORK/backports-binary-hashes" || return 1
    p2s_manifest_record backports_artifact_set "$suite|$component|$arch|verified=$expected"
}

p2s_backports_candidate_sha256() {
    awk -F'|' -v n="$1" -v v="$2" -v a="$3" -v c="$4" '
        $1==n && $2==v && $3==a && $4==c {if (sha!="" && sha!=$5) bad=1; sha=$5}
        END {if (bad || sha=="") exit 1; print sha}
    ' "$P2S_WORK/backports-binary-hashes"
}

# APT passes the actual archive paths to a version-1 Pre-Install-Pkgs hook.
p2s_backports_prepare_archive_guard() {
    local plan=$1 native_lookup=${2:-false} name version arch target digest
    rm -f "$P2S_WORK/backports-archive-guard-started" "$P2S_WORK/backports-archive-guard-passed" || return 1
    awk -F'|' '
        FILENAME==ARGV[1] { row[$1]=row[$1 ":" $3]=$0; next }
        /^Inst / { split($0, fields, " "); if (fields[2] in row) print row[fields[2]]; else bad=1 }
        END {exit bad}
    ' "$P2S_WORK/apt-approved" "$plan" > "$P2S_WORK/backports-downloads" || return 1
    : > "$P2S_WORK/backports-download-sha256" || return 1
    while IFS='|' read -r name version arch target; do
        digest=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '
            $1==n && $2==v && $3==a {print $4}
        ' "$P2S_WORK/backports-approved-sha256") || return 1
        if [ -z "$digest" ]; then
            $native_lookup || awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '
                $1==n && $2==v && $3==a {found=1} END {exit !found}
            ' "$P2S_WORK/dependency-approved" || return 1
            target=$name; [ "$arch" = all ] || target="$name:$arch"
            p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$version" > "$P2S_WORK/backports-dependency-sha256" || return 1
            digest=$(awk '
                /^SHA256: / && length($2)==64 && $2 !~ /[^0-9a-f]/ {if (sha!="" && sha!=$2) bad=1; sha=$2}
                END {if (bad || sha=="") exit 1; print sha}
            ' "$P2S_WORK/backports-dependency-sha256") || return 1
        fi
        printf '%s\n' "$digest" >> "$P2S_WORK/backports-download-sha256" || return 1
    done < "$P2S_WORK/backports-downloads"
    [ -s "$P2S_WORK/backports-download-sha256" ] &&
        LC_ALL=C sort -o "$P2S_WORK/backports-download-sha256" "$P2S_WORK/backports-download-sha256" || return 1
    cat > "$P2S_WORK/backports-archive-guard" <<'EOF'
set -e
work=${0%/*}
: > "$work/backports-archive-guard-started"
: > "$work/backports-observed-sha256"
while IFS= read -r archive; do
    checksum=$(sha256sum -- "$archive")
    printf '%s\n' "${checksum%% *}" >> "$work/backports-observed-sha256"
done
LC_ALL=C sort -o "$work/backports-observed-sha256" "$work/backports-observed-sha256"
if ! cmp -s "$work/backports-download-sha256" "$work/backports-observed-sha256"; then
    printf '%s\n' 'The downloaded packages differ from the reviewed SHA256 transaction. Packages were not passed to dpkg.' >&2
    exit 1
fi
: > "$work/backports-archive-guard-passed"
printf '%s\n' 'The archive guard confirms all downloaded packages matched the approved SHA256 transaction.'
EOF
}

p2s_backports_legacy_affected() {
    local suite=$1 source=$2 version=$3 limit distro_release
    case "$suite:$source:$version" in
        # Published October community builds for native PHP predate the November fixes.
        squeeze:php5:5.4.45-1+animaa2~squeeze|wheezy:php5:5.4.45-0+deb7u14+animaa2|jessie:php5:5.6.40+dfsg-0+deb8u12+animaa2) return 0 ;;
        jessie:php5:5.6.*+dfsg-*+deb8u[0-9]*|wheezy:php5:5.4.*-*+deb7u[0-9]*)
            # A stock revision ends in a numeric Debian update number.
            case "${version##*u}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac ;;
    esac
    distro_release=$P2S_DISTRO$P2S_RELEASE
    if [ "$P2S_DISTRO" = debian ]; then distro_release=debian${P2S_RELEASE%%.*}; fi
    # Exact source build numbers and date stamps in the v2026.10.26.1 release.
    case "$suite" in squeeze|wheezy) ;; buster|trusty) limit=animaa1 ;; *) limit=animaa2 ;; esac
    case "$source:$version" in
        php5.6:"5.6.40-105+0~20261022.135+$distro_release~1+$limit"|php7.1:"7.1.33-81+0~20261022.128+$distro_release~1+$limit"|\
        php7.2:"7.2.34-66+0~20261021.122+$distro_release~1+$limit"|php7.3:"7.3.33-35+0~20261021.144+$distro_release~1+$limit"|\
        php7.4:"1:7.4.33-31+0~20261021.121+$distro_release~1+$limit") return 0 ;;
    esac
    p2s_package_deb_is_sury "$version" || return 1
    case "$version" in *"+$distro_release~"*) ;; *) return 1 ;; esac
    # Last reviewed pre-November Sury source revisions for these branches.
    case "$source" in
        php5.6) limit=5.6.40-105 ;; php7.1) limit=7.1.33-81 ;; php7.2) limit=7.2.34-66 ;;
        php7.3) limit=7.3.33-35 ;; php7.4) limit=1:7.4.33-31 ;; *) return 1 ;;
    esac
    dpkg --compare-versions "${version%%+*}" le "$limit"
}

p2s_backports_select_branches() {
    local suite=$1 source version arch vendor name row installed_source source_version build state
    [ -s "$P2S_WORK/deb-source-records" ] && p2s_command_exists dpkg || return 1
    : > "$P2S_WORK/backports-branches"
    while IFS='|' read -r name version arch vendor; do
        p2s_package_is_engine "$name" || continue
        source=$(p2s_backports_source "$name") && build=$(p2s_backports_build "$suite" "$source" "$arch") || continue
        if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ] && ! grep -Fxq -- "$source" "$P2S_APT_PHASE_BRANCHES"; then continue; fi
        row=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4,$5]++ {print $4 "|" $5}' "$P2S_WORK/deb-source-records")
        installed_source=${row%%|*}; source_version=${row#*|}
        [ "$source" = "$installed_source" ] && [ "$source_version" = "$version" ] || continue
        build=${build%%|*}
        # Old native package names may also identify a different PHP branch (Squeeze PHP 5.3).
        if [ "$(printf '%s\n' "${version#*:}" | cut -d. -f1,2)" != "$(printf '%s\n' "${build#*:}" | cut -d. -f1,2)" ]; then continue; fi
        state=$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$source" "$source_version")
        if [ "$state" = Y ]; then
            printf '%s\n' "$source" >> "$P2S_WORK/backports-branches"
        fi
    done < "$P2S_WORK/packages"
    [ -s "$P2S_WORK/backports-branches" ]
}

# The reviewed Bionic PHP cohort requires php-common (>= 1:81~).
p2s_backports_package_build() {
    local suite=$1 name=${2%:*} arch=$3 installed=$4 source
    case "$suite:$name:$arch:$installed" in
        bionic:php-common:all:1:60ubuntu1)
            printf '%s\n' '2:106~exp1+debsuryorg12.1+1+animaa1|sury' ;;
        *)
            source=$(p2s_backports_source "$name") && p2s_backports_build "$suite" "$source" "$arch" ;;
    esac
}

p2s_backports_source_selection() {
    local suite=$1 scope=$2 name version arch vendor source
    : > "$P2S_WORK/apt-selected" || return 1
    while IFS='|' read -r name version arch vendor; do
        p2s_backports_package_build "$suite" "$name" "$arch" "$version" >/dev/null || continue
        if [ "$name" = php-common ]; then
            source=php-defaults
        else
            source=$(p2s_backports_source "$name") && grep -Fxq -- "$source" "$scope" || continue
        fi
        awk -F'|' -v n="$name" -v v="$version" -v a="$arch" -v s="$source" '
            $1==n && $2==v && $3==a {
                if ($4==s && ($5==v || (s=="php-defaults" && $5=="60ubuntu1"))) yes=1; else bad=1
            } END {exit (!yes || bad)}
        ' "$P2S_WORK/deb-source-records" || {
            if [ "$name" = php-common ] || p2s_package_is_engine "$name"; then return 1; fi
            continue
        }
        printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/apt-selected" || return 1
    done < "$P2S_WORK/packages"
}

# The exact version must come exclusively from one reviewed publisher at APT's selected priority.
p2s_freexian_candidate() {
    local name="$1" installed="$2" vendor="$3" arch="$4" normal_priority="$5" native="$6" elts="$7"
    local source entry version priority chosen='' origin
    local -a versions
    source=${name#libapache2-mod-}; source=${source%%-*}
    for origin in Debian Freexian; do
        if [ "$origin" = Debian ]; then read -r -a versions <<< "$native"; else read -r -a versions <<< "$elts"; fi
        for entry in "${versions[@]}"; do
            version=${entry%@*}; priority=${entry##*@}
            case "$version" in ''|*[!a-zA-Z0-9.+:~_-]*) continue ;; esac
            [ "$priority" = "$normal_priority" ] && [ "$priority" -gt 0 ] || continue
            dpkg --compare-versions "$version" ge "$installed" || continue
            [ "$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$source" "$version")" = N ] || continue
            if [ -z "$chosen" ] || dpkg --compare-versions "$version" gt "$chosen"; then chosen=$version; fi
        done
        if [ -n "$chosen" ]; then
            if [ "$origin" = Freexian ] && [ "$chosen" != "$installed" ]; then
                P2S_FREEXIAN_SELECTED=true
                p2s_manifest_record freexian_candidate "$name|$arch|$installed|$chosen|source=$source"
            fi
            P2S_DEB_CANDIDATE=$chosen
            return 0
        fi
    done
    p2s_fix_block candidate_fix "No reviewed fixed build of $name at APT's selected priority came exclusively from signed Debian or Freexian Extended LTS sources for this release."
    return 1
}

p2s_package_deb_candidate() {
    local name="$1" installed="$2" arch="$3" sury="$4" target candidate observed matches other seen record metadata source source_version expected suite branch old_branch rest installed_source provider query_status=0
    local origin_details origin_reason native_origin native_matches native_versions alternate expected_source vendor="${5:-}"
    local version_priority candidate_priority probe_version current_source_candidate='' prefer_native=false freexian_versions freexian_seen
    local backports_suite='' backports_component='' backports_build='' backports_version='' backports_priority backports_seen preferred_versions sury_versions digest installed_provider
    local stackx_matches stackx_version stackx_uri=''
    if ${P2S_STACKX_ACTIVE:-false}; then stackx_uri="https://mirrors.scalarx.net/stackx-php/$stackx_suite/repo"; fi
    # Explicit migration must reach Sury; a native candidate can still lack the requested security fixes.
    if ${P2S_SURY_MIGRATION_ACTIVE:-false}; then sury=true; fi
    target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
    if ${P2S_BACKPORTS_ACTIVE:-false}; then
        backports_suite=$(p2s_backports_suite) &&
            backports_build=$(p2s_backports_package_build "$backports_suite" "$name" "$arch" "$installed") || return 1
        if [ "$name" = php-common ]; then expected_source=php-defaults
        else expected_source=$(p2s_backports_source "$name") || return 1; fi
        backports_version=${backports_build%%|*}; backports_component=${backports_build#*|}
    fi
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/candidate-policy" 2> "$P2S_WORK/candidate-query.err" || query_status=$?
    if [ "$query_status" -ne 0 ]; then
        p2s_manifest_record apt_candidate_error "$name|operation=policy|exit=$query_status
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-query.err")"
        p2s_fix_block candidate_provider "Could not read the normal APT candidate for $name; no alternative source was selected."; return 1
    fi
    p2s_manifest_record apt_candidate_policy "$name|installed=$installed|architecture=$arch
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-policy")"
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:9|debian:9.*) suite=stretch ;; debian:10|debian:10.*) suite=buster ;;
        debian:11|debian:11.*) suite=bullseye ;;
        debian:12|debian:12.*) suite=bookworm ;; debian:13|debian:13.*) suite=trixie ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        ubuntu:26.04) suite=resolute ;;
        *) suite=unsupported
            if ${P2S_APT_NOVEMBER_POLICY:-false}; then
                case "$P2S_DISTRO:$P2S_RELEASE" in ubuntu:26.10) suite=stonking ;; *) suite=$(p2s_backports_suite) || suite=unsupported ;; esac
            fi ;;
    esac
    case "$P2S_DISTRO" in debian) native_origin=Debian ;; ubuntu) native_origin=Ubuntu ;; *) native_origin='' ;; esac
    # Global policy binds repository rows to their release identity. Check EVERY source of the
    # candidate version: inspect every origin of the exact selected version for duplicate sources.
    # apt-cache policy: 500 https://packages.sury.org/php bookworm/main amd64 Packages
    #                  release o=deb.sury.org,a=bookworm,n=bookworm,l=deb.sury.org,c=main,b=amd64
    # A per-package duplicate can be: 500 file:/local/repo bookworm/main amd64 Packages
    awk -v suite="$suite" -v native_origin="$native_origin" -v signed_elts="${P2S_FREEXIAN_SIGNED_SUITES:-}" -v november_policy="${P2S_APT_NOVEMBER_POLICY:-false}" \
        -v backports_suite="$backports_suite" -v component="$backports_component" -v reviewed="$backports_version" -v stackx_uri="$stackx_uri" '
        function uri_kind(uri) {
            if (uri ~ /^https?:\/\/packages[.]sury[.]org\/php\/?$/) return 1
            if (uri ~ /^https?:\/\/ppa[.]launchpad(content)?[.]net\/ondrej\/php\/ubuntu\/?$/) return 2
            return 0
        }
        NR==FNR {
            if ($1 ~ /^-?[0-9]+$/ && $2 ~ /:\/\// && $5=="Packages") {key=$2 "|" $3 "|" $4; kind=uri_kind($2); next}
            if ($1=="release" && key!="") {
                line="," $2 ","
                release_identity[key]=$2
                split(key, fields, "[|]")
                if (native_origin!="" && index(line,",o=" native_origin ",") &&
                    (signed_elts=="" || fields[1] ~ /^https?:\/\/(deb[.]debian[.]org|security[.]debian[.]org|archive[.]debian[.]org)\/(debian|debian-security)\/?$/) &&
                    (index(line,",n=" suite ",") || index(line,",n=" suite "-security,") ||
                     index(line,",n=" suite "-updates,"))) native[key]=1
                if (november_policy=="true" && native_origin=="Ubuntu" &&
                    fields[1] ~ /^https:\/\/esm[.]ubuntu[.]com\/(apps|infra)\/ubuntu\/?$/ &&
                    (index(line,",o=UbuntuESM,") || index(line,",o=UbuntuESMApps,")) &&
                    (index(line,",n=" suite ",") || index(line,",n=" suite "-infra-security,") ||
                     index(line,",n=" suite "-infra-updates,") || index(line,",n=" suite "-apps-security,") ||
                     index(line,",n=" suite "-apps-updates,"))) native[key]=1
                # Official ELTS APT policy: release o=Freexian,a=buster-lts,n=buster-lts,l=Freexian-Extended-LTS,c=main,b=amd64
                if (fields[1] ~ /^https:\/\/deb[.]freexian[.]com\/extended-lts\/?$/ &&
                    index(line,",o=Freexian,") && index(line,",l=Freexian-Extended-LTS,")) {
                    for (i=1; i<=split(signed_elts, releases, " "); i++)
                        if ((releases[i]==suite || releases[i]==suite "-lts") &&
                            fields[2]==releases[i] "/main" && index(line,",a=" releases[i] ",") &&
                            index(line,",n=" releases[i] ",") && index(line,",c=main,")) elts[key]=1
                }
                if (index(line,",o=Freexian,") || index(line,",l=Freexian-Extended-LTS,")) freexian[key]=1
                if (index(line,",o=debian-php-backports,") || index(line,",l=debian-php-backports,")) community[key]=1
                if (backports_suite!="" && fields[1] ~ /^https:\/\/animaartificialis[.]github[.]io\/debian-php-backports\/?$/ &&
                    fields[2]==backports_suite "/" component && index(line,",o=debian-php-backports,") &&
                    index(line,",l=debian-php-backports,") && index(line,",a=" backports_suite ",") &&
                    index(line,",n=" backports_suite ",") && index(line,",c=" component ",")) backports[key]=1
                if (backports_suite!="" && !community[key] &&
                    (index(line,",n=" backports_suite ",") || index(line,",n=" backports_suite "-security,") ||
                     index(line,",n=" backports_suite "-lts,")) &&
                    (uri_kind(fields[1]) || index(line,",o=" native_origin ",") || freexian[key] ||
                     fields[1] ~ /^https:\/\/esm[.]ubuntu[.]com\//)) preferred[key]=1
                if (kind && index(line,",n=" suite ",") &&
                    ((kind==1 && index(line,",o=deb.sury.org,")) || (kind==2 && index(line,",o=LP-PPA-ondrej-php,")))) approved[key]=1
                key=""
            }
            next
        }
        $1=="Installed:" {installed=$2; next}
        $1=="Candidate:" {candidate=$2; next}
        $1=="***" {version=$2; priority[version]=$3; next}
        NF==2 && $2 ~ /^-?[0-9]+$/ {version=$1; priority[version]=$2; next}
        $1 ~ /^-?[0-9]+$/ && NF>=2 && version!="" {
            if ($2=="/var/lib/dpkg/status") next
            key=$2 "|" $3 "|" $4
            origins[version]++
            if ($5=="Packages" && native[key]) native_count[version]++
            if ($5=="Packages" && elts[key]) elts_count[version]++
            if ($5=="Packages" && backports[key]) backports_count[version]++
            if ($5=="Packages" && preferred[key]) preferred_count[version]++
            if ($5=="Packages" && approved[key]) sury_count[version]++
            if (version!=candidate) next
            if (uri_kind($2)) seen++
            if (freexian[key] || $2 ~ /^https?:\/\/([^\/@]+@)?(deb|php|security)[.]freexian[.]com(\/|$)/) freexian_seen++
            # Flat feed policy row: 500 https://mirrors.scalarx.net/stackx-php/buster/repo ./ Packages
            if (($2==stackx_uri || $2==stackx_uri "/") && $3=="./" && $4=="Packages") stackx_matches++
            if (community[key] || $2 ~ /^https?:\/\/animaartificialis[.]github[.]io\/debian-php-backports(\/|$)/) backports_seen++
            if ($5=="Packages" && native[key]) native_matches++
            if ($5=="Packages" && approved[key]) {matches++; verdict="matching"} else {other++; verdict="unverified"}
            details=details (details ? "; " : "") verdict ": " $0 " (release " (release_identity[key] ? release_identity[key] : "identity unavailable") ")"
        }
        END {
            for (v in native_count) if (native_count[v]==origins[v]) versions=versions " " v "@" priority[v]
            for (v in elts_count) if (elts_count[v]==origins[v]) elts_versions=elts_versions " " v "@" priority[v]
            for (v in preferred_count) if (preferred_count[v]==origins[v] && priority[v]+0>0) preferred_versions=preferred_versions " " v
            for (v in sury_count) if (sury_count[v]==origins[v]) sury_versions=sury_versions " " v "@" priority[v]
            if (backports_count[reviewed]>0 && backports_count[reviewed]==origins[reviewed]) backports_priority=priority[reviewed]
            print candidate "|" installed "|" matches+0 "|" other+0 "|" seen+0 "|" native_matches+0 "|" priority[candidate] "|" versions "|" elts_versions "|" freexian_seen+0 "|" backports_seen+0 "|" backports_priority "|" preferred_versions "|" sury_versions "|" stackx_matches+0
            print (details ? details : "No repository rows; the candidate may exist only in installed dpkg status.")
        }
    ' "$P2S_WORK/candidate-origins" "$P2S_WORK/candidate-policy" > "$P2S_WORK/candidate-source-check" || return 1
    record=$(head -n 1 "$P2S_WORK/candidate-source-check")
    origin_details=$(tail -n +2 "$P2S_WORK/candidate-source-check" | p2s_manifest_redact_repository_urls)
    candidate=${record%%|*}; record=${record#*|}; observed=${record%%|*}; record=${record#*|}
    matches=${record%%|*}; record=${record#*|}; other=${record%%|*}; record=${record#*|}
    seen=${record%%|*}; record=${record#*|}; native_matches=${record%%|*}; record=${record#*|}
    candidate_priority=${record%%|*}; record=${record#*|}
    native_versions=${record%%|*}; record=${record#*|}
    freexian_versions=${record%%|*}; record=${record#*|}; freexian_seen=${record%%|*}; record=${record#*|}
    backports_seen=${record%%|*}; record=${record#*|}; backports_priority=${record%%|*}; record=${record#*|}
    preferred_versions=${record%%|*}; record=${record#*|}
    sury_versions=${record%%|*}; stackx_matches=${record#*|}
    case "$candidate" in ''|'(none)'|*[!a-zA-Z0-9.+:~_-]*) p2s_fix_block no_candidate "APT found no usable candidate for $name (installed build $installed). Run apt-cache policy $target to inspect available versions and priorities."; return 1 ;; esac
    [ "$observed" = "$installed" ] || { p2s_fix_block candidate_provider "Installed package state changed or could not be matched for $name."; return 1; }
    if ${P2S_STACKX_ACTIVE:-false}; then
        expected_source=$(p2s_backports_source "$name") &&
            stackx_version=$(p2s_stackx_published_build "$stackx_suite" "$expected_source") || return 1
        if ! p2s_version_is_stackx "$candidate" || [ "$candidate" != "$stackx_version" ] ||
            [ "${candidate_priority:-0}" -le 0 ] ||
            [ "$stackx_matches" -eq 0 ] || [ "$stackx_matches" -ne "$((matches + other))" ]; then
            p2s_fix_block candidate_provider "APT must select a StackX build of $name matching reviewed revision $stackx_version, exclusively from the signed $stackx_suite feed. Review package priorities and other sources."
            return 1
        fi
        backports_component=stackx; sury=false
    elif ${P2S_BACKPORTS_ACTIVE:-false}; then
        if p2s_package_is_engine "$name"; then
            for probe_version in $preferred_versions; do
                if dpkg --compare-versions "$probe_version" ge "$installed" &&
                    [ "$(p2s_version_package_state "$name" "$probe_version" "$native_origin" "$arch" "$expected_source" "$probe_version")" = N ]; then
                    p2s_fix_block candidate_provider "A preferred PHP security build is available for $name ($probe_version). Review that source before using Debian PHP Backports."; return 1
                fi
            done
            if [ "$installed" != "$backports_version" ] &&
                [ "$(p2s_version_package_state "$name" "$installed" "$vendor" "$arch" "$expected_source" "$installed")" != Y ]; then
                p2s_fix_block candidate_provider "The installed build of $name is fixed or unverified. Review this mixed-revision PHP branch before switching sources."; return 1
            fi
        fi
        if [ "$name" != php-common ] &&
            [ "$(printf '%s\n' "${installed#*:}" | cut -d. -f1,2)" != "$(printf '%s\n' "${backports_version#*:}" | cut -d. -f1,2)" ]; then
            p2s_fix_block candidate_branch "The Debian PHP Backports build of $name would change PHP branches."; return 1
        fi
        if [ "${backports_priority:-0}" -le 0 ] || [ "$backports_priority" != "$candidate_priority" ]; then
            p2s_fix_block candidate_fix "No exact reviewed Debian PHP Backports build of $name ($backports_version) is available exclusively from the signed source at the selected APT priority."; return 1
        fi
        candidate=$backports_version; sury=false
    elif ${P2S_FREEXIAN_ACTIVE:-false}; then
        p2s_freexian_candidate "$name" "$installed" "$vendor" "$arch" "$candidate_priority" "$native_versions" "$freexian_versions" || return 1
        candidate=$P2S_DEB_CANDIDATE
    else
    if ${P2S_APT_NOVEMBER_POLICY:-false} && [ "$sury" = true ] && { [ "$matches" -eq 0 ] || [ "$other" -ne 0 ]; }; then
        # A co-configured source at the same priority can mask the signed Sury build.
        for alternate in $sury_versions; do
            probe_version=${alternate%@*}; version_priority=${alternate##*@}
            [ "$version_priority" = "$candidate_priority" ] && [ "${version_priority:-0}" -gt 0 ] || continue
            p2s_package_deb_is_sury "$probe_version" && dpkg --compare-versions "$probe_version" ge "$installed" || continue
            if [ -z "$current_source_candidate" ] || dpkg --compare-versions "$probe_version" gt "$current_source_candidate"; then
                current_source_candidate=$probe_version
            fi
        done
        if [ -n "$current_source_candidate" ]; then
            candidate=$current_source_candidate; matches=1; other=0; seen=1; backports_seen=0
        fi
    fi
    if ! ${P2S_APT_NOVEMBER_POLICY:-false} && { [ "$backports_seen" -gt 0 ] || [[ "$candidate" == *+animaa* ]]; } && [ "$candidate" != "$installed" ]; then
        p2s_fix_block candidate_fix "APT selected a Debian PHP Backports build for $name ($candidate). An explicit, verified last-resort update is required."
        return 1
    fi
    origin_reason="Expected only the official Sury/ondrej PHP source for $P2S_DISTRO $P2S_RELEASE (suite $suite); matching repository rows: $matches; other or unverified rows: $other."
    if [ "$suite" = unsupported ]; then origin_reason="This script has no reviewed automatic Sury/ondrej update path for $P2S_DISTRO $P2S_RELEASE; its source identity could not be approved."; fi
    if ! p2s_package_deb_is_sury "$candidate"; then origin_reason="$origin_reason The candidate version does not identify a Sury/ondrej build."; fi
    if ${P2S_SURY_MIGRATION_ACTIVE:-false}; then
        origin_reason="$origin_reason Sury migration requires a normal candidate from its matching repository. If that source is absent, explicitly select --add-sury-repository with the migration options; otherwise review the source and APT policy."
    fi
    if [ "$sury" = false ]; then
        provider=$(p2s_package_provider "$name" '' "$candidate")
        case "$provider" in Sury*) seen=1 ;; esac
        # The ordinary path looks for an alternative only to preserve a native installation.
        if { [ "$seen" -gt 0 ] || [ "$freexian_seen" -gt 0 ]; } &&
            [ "$(p2s_package_provider "$name" "$vendor" "$installed")" = "$native_origin" ]; then
            prefer_native=true
        fi
    fi
    if { ${P2S_APT_CURRENT_PROVIDER_ONLY:-false} || $prefer_native; } &&
        { ${P2S_APT_NATIVE_FALLBACK:-false} || ! p2s_package_deb_is_sury "$installed"; }; then
        expected_source=$(p2s_backports_source "$name") || expected_source=${name%%-*}
        for alternate in $native_versions; do
            probe_version=${alternate%@*}; version_priority=${alternate##*@}
            case "$probe_version" in ''|*[!a-zA-Z0-9.+:~_-]*) continue ;; esac
            dpkg --compare-versions "$probe_version" ge "$installed" || continue
            if p2s_package_is_engine "$name" &&
                [ "$(p2s_version_package_state "$name" "$probe_version" "$vendor" "$arch" "$expected_source" "$probe_version")" = N ] &&
                { ${P2S_SURY_MIGRATION_ACTIVE:-false} ||
                    { [ "$native_matches" -ne "$((matches + other))" ] && [ "$version_priority" != "$candidate_priority" ]; }; }; then
                p2s_fix_block candidate_provider "A native PHP security build for $name ($probe_version) is available. Review APT package priorities before changing providers."; return 1
            fi
            if [ "$version_priority" = "$candidate_priority" ] && [ "${version_priority:-0}" -gt 0 ] &&
                { [ -z "$current_source_candidate" ] || dpkg --compare-versions "$probe_version" gt "$current_source_candidate"; }; then
                current_source_candidate=$probe_version
            fi
        done
    fi
    if [ "$sury" = true ]; then
        if ! p2s_package_deb_is_sury "$candidate" || [ "$matches" -eq 0 ] || [ "$other" -ne 0 ]; then
            p2s_fix_block candidate_provider "Cannot safely update $name ($arch): installed $installed; APT candidate $candidate. $origin_reason Candidate sources: $origin_details. Review apt-cache policy $target and apt-cache policy before changing sources or pins."
            return 1
        fi
    else
        if { ${P2S_APT_CURRENT_PROVIDER_ONLY:-false} || $prefer_native; } && [ "$candidate" != "$installed" ] &&
            { [ "$native_matches" -eq 0 ] || [ "$native_matches" -ne "$((matches + other))" ] ||
                [ "$seen" -gt 0 ] || [ "$freexian_seen" -gt 0 ]; }; then
            if [ -n "$current_source_candidate" ] && { [ "$seen" -eq 0 ] || $prefer_native || ${P2S_APT_NATIVE_FALLBACK:-false}; }; then
                p2s_manifest_record candidate_provider_preference "$name|APT_candidate=$candidate|current_publisher_candidate=$current_source_candidate|same_priority=$candidate_priority"
                candidate=$current_source_candidate
                seen=0
                freexian_seen=0
                P2S_DEB_NATIVE_PREFERENCE=true
            elif ${P2S_APT_CURRENT_PROVIDER_ONLY:-false}; then
                if [ "$seen" -gt 0 ] && [ "$matches" -gt 0 ] && [ "$other" -eq 0 ]; then return 2; fi
                p2s_fix_block candidate_provider "The normal candidate for $name ($candidate) cannot be attributed exclusively to the installed distribution publisher. Candidate sources: $origin_details."; return 1
            fi
        fi
        if [ "$freexian_seen" -gt 0 ] && [ "$candidate" != "$installed" ]; then
            p2s_fix_block candidate_provider "APT selected a Freexian build for $name ($candidate). Use the Extended LTS option if the check offers it for this native Debian branch. For Freexian PHP LTS subscription packages, follow the vendor's update instructions."
            return 1
        fi
        if [ "$seen" -gt 0 ] && ! ${P2S_SURY_MIGRATION_ACTIVE:-false}; then
            p2s_fix_block candidate_provider "APT selected the Sury build $candidate for $name (installed build $installed). Run apt-cache policy $target to review the available builds. Switching to Sury requires explicit migration."
            return 1
        fi
        if [ "$seen" -gt 0 ]; then
            # Opt-in changes the permitted package publisher, never the identity of the package being replaced.
            if ! p2s_package_deb_is_sury "$candidate" || [ "$matches" -eq 0 ] || [ "$other" -ne 0 ]; then
                p2s_fix_block candidate_provider "Cannot safely migrate $name ($arch): installed $installed; APT candidate $candidate. $origin_reason Candidate sources: $origin_details. Review apt-cache policy $target and apt-cache policy before changing sources or pins."
                return 1
            fi
            sury=true
        fi
    fi
    fi
    if ! ${P2S_STACKX_ACTIVE:-false} && [ "$candidate" != "$installed" ] && p2s_version_is_stackx "$candidate"; then
        p2s_fix_block candidate_provider "APT selected a StackX build for $name ($candidate). Select the StackX update option to approve that publisher change."
        return 1
    fi
    # Honour APT priorities and never downgrade an installed package.
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
    if ${P2S_NOVEMBER:-false} && p2s_package_is_engine "$name"; then
        record=unchanged
        if dpkg --compare-versions "$candidate" gt "$installed"; then record=newer; fi
        p2s_manifest_record candidate_build_status "$name|architecture=$arch|installed=$installed|candidate=$candidate|comparison=$record"
    fi
    if ${P2S_BACKPORTS_ACTIVE:-false} && [ "$name" = php-common ]; then
        if [ "$metadata" != "php-defaults|${candidate#*:}" ]; then
            p2s_fix_block candidate_provider "The Backports php-common dependency does not match the reviewed php-defaults source revision."
            return 1
        fi
    elif ${P2S_FREEXIAN_ACTIVE:-false} || ${P2S_BACKPORTS_ACTIVE:-false}; then
        expected=${name#libapache2-mod-}; expected=${expected%%-*}
        if ${P2S_BACKPORTS_ACTIVE:-false}; then expected=$expected_source; fi
        source=${metadata%%|*}; source_version=${metadata#*|}
        if [ "$source" != "$expected" ] || [ "$(p2s_version_package_state "$name" "$candidate" "$vendor" "$arch" "$source" "$source_version")" != N ]; then
            p2s_fix_block candidate_fix "The selected build of $name lacks a verified source package and November security revision."
            return 1
        fi
    fi
    if ${P2S_STACKX_ACTIVE:-false} && [ "$metadata" != "$expected_source|$candidate" ]; then
        p2s_fix_block candidate_provider "The StackX source package and full revision for $name could not be matched."
        return 1
    fi
    if ${P2S_BACKPORTS_ACTIVE:-false} || ${P2S_STACKX_ACTIVE:-false}; then
        if ! digest=$(p2s_backports_candidate_sha256 "${name%:*}" "$candidate" "$arch" "$backports_component") ||
            [ "$(sed -n 's/^SHA256: //p' "$P2S_WORK/candidate-metadata" | sort -u)" != "$digest" ]; then
            p2s_fix_block candidate_checksum "APT's SHA256 for $name=$candidate does not match the approved $backports_component package index."
            return 1
        fi
        printf '%s|%s|%s|%s\n' "${name%:*}" "$candidate" "$arch" "$digest" >> "$P2S_WORK/backports-approved-sha256" || return 1
        p2s_manifest_record backports_package_checksum "$name|$candidate|$arch|verified=$digest"
    fi
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
            if ${P2S_NOVEMBER:-false}; then
                p2s_fix_block candidate_fix "We could not verify the November fixes in the Sury candidate for $name ($candidate) on this release and architecture. Check the complete package build against Sury's advisory."
            else
                p2s_fix_block candidate_fix "The Sury candidate for $name has no reviewed fix for both CVEs on this branch, suite and architecture."
            fi
            return 1
        fi
        [ "$(p2s_version_upstream_state "$candidate")" != '?' ] || { p2s_fix_block candidate_fix "The Sury candidate's PHP branch could not be identified for $name."; return 1; }
        rest=${installed#*:}; old_branch=${rest%%.*}; rest=${rest#*.}; old_branch="$old_branch.${rest%%.*}"
        rest=${candidate#*:}; branch=${rest%%.*}; rest=${rest#*.}; branch="$branch.${rest%%.*}"
        [ "$old_branch" = "$branch" ] || {
            p2s_fix_block candidate_branch "The candidate for $name changes PHP branches; migration review is required."; return 1;
        }
    fi
    if ! ${P2S_BACKPORTS_ACTIVE:-false} && { ${P2S_APT_CURRENT_PROVIDER_ONLY:-false} || [ "$candidate" = "$current_source_candidate" ]; } &&
        [ "$sury" = false ] && p2s_package_is_engine "$name"; then
        if [ "${metadata%%|*}" != "$expected_source" ]; then
            p2s_fix_block candidate_provider "The source-package identity for the current-publisher candidate for $name could not be verified."; return 1
        fi
        if [ "$(p2s_version_package_state "$name" "$candidate" "$vendor" "$arch" "${metadata%%|*}" "${metadata#*|}")" != N ]; then
            return 2
        fi
    fi
    if ${P2S_SURY_MIGRATION_ACTIVE:-false} || ${P2S_FREEXIAN_ACTIVE:-false} || ${P2S_STACKX_ACTIVE:-false} ||
        ${P2S_BACKPORTS_ACTIVE:-false} || ${P2S_APT_NATIVE_FALLBACK:-false}; then
        case "${name%:*}" in php[0-9].[0-9]-cli|php[0-9].[0-9]-fpm|php[0-9].[0-9]-cgi|php[0-9].[0-9]-phpdbg|libapache2-mod-php[0-9].[0-9]|php5-cli|php5-fpm|php5-cgi|php5-phpdbg|libapache2-mod-php5|libapache2-mod-php5filter)
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
            if ${P2S_BACKPORTS_ACTIVE:-false}; then branch=$expected_source; fi
            printf '%s\n' "$branch" >> "$P2S_WORK/migration-api-branches" ;;
        esac
    fi
    P2S_DEB_CANDIDATE=$candidate
    record=normal_APT_candidate
    if [ "$candidate" = "$current_source_candidate" ]; then record=equal_priority_current_publisher; fi
    p2s_manifest_record candidate_selection "$name|$installed|$candidate|$arch|sury_only=$sury|$record|exact_version_required"
    if [ "$candidate" != "$installed" ] && p2s_package_is_engine "$name"; then
        provider=
        installed_provider=$(p2s_package_provider "$name" "$vendor" "$installed")
        if ${P2S_STACKX_ACTIVE:-false}; then
            case "$installed_provider" in StackX*) ;; *) provider=StackX ;; esac
        elif ${P2S_BACKPORTS_ACTIVE:-false}; then
            case "$installed_provider" in debian-php-backports*) ;; *) provider=debian-php-backports ;; esac
        elif ${P2S_APT_NATIVE_FALLBACK:-false}; then provider=$native_origin
        elif ${P2S_SURY_MIGRATION_ACTIVE:-false} && ! p2s_package_deb_is_sury "$installed"; then provider=Sury/ondrej
        fi
        if [ -n "$provider" ]; then
            record=candidate_verified
            if ${P2S_STACKX_ACTIVE:-false}; then
                record='candidate_authenticated|security_evidence=vendor_reported'
                if [ "$(p2s_version_package_state "$name" "$candidate" '' "$arch" "${metadata%%|*}" "${metadata#*|}")" = N ]; then
                    record='candidate_authenticated|security_evidence=source_reviewed'
                fi
            fi
            p2s_manifest_record provider_switch "$name|$arch|$installed|$candidate|from=$installed_provider|to=$provider|authorization=${P2S_PROVIDER_AUTHORIZATION:-configured_source_policy}|$record"
        fi
    fi
}

# Explicit Sury migration methods keep exact binary names, versioned branches and architectures.
# Unversioned selectors and third-party native extensions remain at their installed versions.
p2s_disruptive_sury_platform_preflight() {
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:11|debian:11.*|debian:12|debian:12.*|debian:13|debian:13.*|ubuntu:22.04|ubuntu:24.04) ;;
        ubuntu:26.04) ${P2S_NOVEMBER:-false} || {
            p2s_fix_block provider_migration "The Sury migration for Ubuntu 26.04 requires the November PHP assessment."; return 1;
        } ;;
        *) p2s_fix_block provider_migration "No equivalent-package Sury migration is implemented for $P2S_DISTRO $P2S_RELEASE. Upgrade or migrate the OS rather than using another release's repository."; return 1 ;;
    esac
    case "${P2S_PANEL:-}" in ''|none) ;;
        cpanel) p2s_fix_block provider_migration "Sury/ondrej packages do not replace cPanel's EasyApache or internal PHP. Update the affected PHP packages through cPanel; this script does not switch them to Sury."; return 1 ;;
        plesk) p2s_fix_block provider_migration "Custom Sury/ondrej PHP on Plesk requires separate PHP handler registration and website settings. This script does not migrate Plesk PHP to Sury/ondrej. Update Plesk-provided PHP through Plesk."; return 1 ;;
        *) p2s_fix_block provider_migration "Switching PHP package sources to Sury is not implemented for this control panel; its package and PHP handler settings need a separate procedure."; return 1 ;;
    esac
    p2s_package_deb_sury_trust_preflight
}

p2s_disruptive_sury_validate_equivalents() {
    local name version arch vendor source branch engines=0
    p2s_disruptive_sury_platform_preflight || return 1
    while IFS='|' read -r name version arch vendor; do
        branch=${name#libapache2-mod-}; branch=${branch%%-*}
        if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ] && ! grep -Fxq -- "$branch" "$P2S_APT_PHASE_BRANCHES"; then continue; fi
        case "${name%:*}" in
            php|php[0-9]|php[0-9].[0-9]|php-common|php-pear|php-cli|php-cgi|php-fpm|php-phpdbg|libapache2-mod-php) continue ;;
            php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9])
                [ "$arch" = amd64 ] || { p2s_fix_block provider_migration "Sury package equivalence is reviewed only for amd64; $name uses $arch."; return 1; }
                source=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4]++ {print $4}' "$P2S_WORK/deb-source-records")
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

# Emit one record per Backports definition for this suite. Keep signed-by paths
# internal so a source definition with credentials or malformed options stays redacted.
p2s_backports_configured_sources() {
    local suite=$1 file stackx_uri=${2:-}
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        case "${file##*/}" in *[!a-zA-Z0-9_.-]*) continue ;; esac
        awk -v suite="$suite" -v file="$file" -v stackx_uri="$stackx_uri" \
            -v apt_keys="/etc/apt/keyrings/" -v share_keys="/usr/share/keyrings/" '
            function has(list, item) { return index(" " list " ", " " item " ") > 0 }
            function emit(uri, components, key, state, configured_suite,    count, names, i, key_name) {
                sub(/\/$/, "", uri)
                if (stackx_uri!="") {
                    if (uri !~ /mirrors[.]scalarx[.]net.*stackx-php/) return
                    if (uri!=stackx_uri || configured_suite!="./" || components !~ /^[ \t]*$/) state="conflict"
                    key_name=""
                    if (index(key, apt_keys)==1) key_name=substr(key,length(apt_keys)+1)
                    if (index(key, share_keys)==1) key_name=substr(key,length(share_keys)+1)
                    if (key_name !~ /^[a-zA-Z0-9_.-]+[.]gpg$/) key="-"
                    print state "|flat|" key "|" file
                    return
                }
                if (uri !~ /animaartificialis[.]github[.]io.*debian-php-backports/) return
                if (uri != "https://animaartificialis.github.io/debian-php-backports") state="conflict"
                if (key !~ /^\/(etc\/apt\/keyrings|usr\/share\/keyrings)\/[a-zA-Z0-9_.-]*debian-php-backports[a-zA-Z0-9_.-]*[.]gpg$/) key="-"
                count=split(components, names, /[ \t]+/)
                for (i=1; i<=count; i++) {
                    if (names[i] ~ /^[a-z0-9-]+$/) print state "|" names[i] "|" key "|" file
                }
            }
            function stanza(    uris, i, n, state) {
                if ((has(fields["types"], "deb") || has(fields["types"], "deb-src")) &&
                        (stackx_uri!="" || has(fields["suites"], suite))) {
                    state="source"
                    if (tolower(fields["enabled"]) == "no") state="disabled"
                    else if (has(fields["types"], "deb")) state="active"
                    n=split(fields["uris"], uris, " ")
                    for (i=1; i<=n; i++) emit(uris[i], fields["components"], fields["signed-by"], state, fields["suites"])
                }
                for (key in fields) delete fields[key]
                key=""
            }
            {
                sub(/\r$/, "")
                if ($0 ~ /^[ \t]*#/) next
                if (file ~ /[.]sources$/) {
                    if ($0 ~ /^[ \t]*$/) { stanza(); next }
                    if ($0 ~ /^[ \t]/) { value=$0; sub(/^[ \t]+/, "", value) }
                    else {
                        key=$0; sub(/:.*/, "", key); key=tolower(key)
                        value=$0; sub(/^[^:]*:[ \t]*/, "", value)
                    }
                    gsub(/[ \t]+/, " ", value); sub(/ $/, "", value)
                    if (fields[key] != "") fields[key]=fields[key] " "
                    fields[key]=fields[key] value
                    next
                }
                sub(/#.*/, "")
                if ($1 != "deb" && $1 != "deb-src") next
                rest=$0; sub(/^[ \t]*[^ \t]+[ \t]+/, "", rest)
                signed=""
                if (rest ~ /^\[/) {
                    end=index(rest, "]")
                    if (!end) next
                    n=split(substr(rest, 2, end-2), options, /[ \t]+/)
                    for (i=1; i<=n; i++) if (options[i] ~ /^signed-by=/) signed=substr(options[i], 11)
                    rest=substr(rest, end+1); sub(/^[ \t]+/, "", rest)
                }
                n=split(rest, parts, /[ \t]+/)
                if (stackx_uri=="" && parts[2] != suite) next
                components=""
                for (i=3; i<=n; i++) components=components " " parts[i]
                state=($1=="deb" ? "active" : "source")
                emit(parts[1], components, signed, state, parts[2])
            }
            END { if (file ~ /[.]sources$/) stanza() }
        ' "$file" || return 1
    done
}

p2s_backports_missing_components() {
    local suite=$1 requested component state key file definitions active disabled missing=''
    shift
    [ "$suite" = "$(p2s_backports_suite)" ] || return 1
    definitions=$(p2s_backports_configured_sources "$suite") || return 1
    for requested in "$@"; do
        case "$requested" in debian|debian7|debian-compat|debian7-compat|sury) ;; *) return 1 ;; esac
        active=false; disabled=false
        while IFS='|' read -r state component key file; do
            case "$state:$component" in
                conflict:*) p2s_fix_block source_authentication "Backports has a conflicting URI in $file for $suite. Review that definition before adding components." >&2; return 1 ;;
                "active:$requested") active=true ;;
                "disabled:$requested") disabled=true ;;
            esac
        done <<< "$definitions"
        if ! $active; then
            if $disabled; then
                p2s_fix_block source_authentication "A disabled Backports entry already lists $suite/$requested. Review the entry and enable it explicitly to use that component." >&2
                return 1
            fi
            missing="${missing:+$missing }$requested"
        fi
    done
    printf '%s\n' "$missing"
}

p2s_backports_verify_key() {
    local input=$1 observed expected=${2:-32E998308C448BF6CC57BD7BFEE348611F66C3D6}
    # Import into an empty temporary keyring for older GnuPG without --show-keys.
    mkdir -p "$P2S_WORK/backports-key-inspection" || return 1
    rm -f "$P2S_WORK/backports-key-inspection/inspection.gpg" || return 1
    p2s_command_run 30 gpg --no-options --batch --homedir "$P2S_WORK/backports-key-inspection" \
        --no-default-keyring --keyring "$P2S_WORK/backports-key-inspection/inspection.gpg" \
        --import "$input" > "$P2S_WORK/backports-key-import.log" 2>&1 || return 1
    p2s_command_run 30 gpg --no-options --batch --homedir "$P2S_WORK/backports-key-inspection" \
        --no-default-keyring --keyring "$P2S_WORK/backports-key-inspection/inspection.gpg" \
        --with-colons --fingerprint > "$P2S_WORK/backports-key-details" 2>/dev/null || return 1
    observed=$(awk -F: '$1=="pub" {primary=1} $1=="sub" {primary=0} $1=="fpr" && primary {print $10; primary=0}' "$P2S_WORK/backports-key-details")
    [ "$observed" = "$expected" ]
}

# P2S-MUTATION: Publish an entire managed file without replacing a pre-existing path.
p2s_backports_publish_file() {
    local input=$1 target=$2 staged record=${3:-$P2S_WORK/backports-created}
    staged=$(mktemp "${target%/*}/.dephp2shell.XXXXXX") || return 1
    if ! cat "$input" > "$staged" || ! chmod 0644 "$staged" || ! ln -T -- "$staged" "$target"; then
        rm -f -- "$staged"
        return 1
    fi
    rm -f -- "$staged"
    if ! printf '%s|%s\n' "$input" "$target" >> "$record"; then
        rm -f -- "$target"
        return 1
    fi
}

# P2S-MUTATION: Remove this run's unchanged files on pre-install failure.
p2s_disruptive_backports_cleanup_added_repository() {
    ${P2S_BACKPORTS_TRANSACTION_ATTEMPTED:-false} || p2s_apt_cleanup_added_files Backports "$P2S_WORK/backports-created"
}

p2s_stackx_cleanup_added_repository() {
    ${P2S_STACKX_TRANSACTION_ATTEMPTED:-false} || p2s_apt_cleanup_added_files StackX "$P2S_WORK/stackx-created"
}

p2s_apt_cleanup_added_files() {
    local provider=$1 record=$2 input target
    [ -f "$record" ] || return 0
    while IFS='|' read -r input target; do
        if [ ! -L "$target" ] && cmp -s -- "$input" "$target" && rm -f -- "$target"; then
            p2s_manifest_record repository_change "$provider|new_file_removed|no_installation_attempt|file=$target"
        fi
    done < <(tac "$record")
    rm -f -- "$record"
}

p2s_stackx_configured_key() {
    local uri=$1 definitions state key file found=''
    definitions=$(p2s_backports_configured_sources ./ "$uri") || return 1
    while IFS='|' read -r state _ key file; do
        case "$state" in
            '') continue ;;
            source) continue ;;
            active)
                if [ "$key" != '-' ] && [ -r "$key" ] && [ -z "$found" ]; then found=$key; continue; fi ;;
        esac
        p2s_fix_block source_authentication "Review the existing StackX definition in $file. Use one enabled flat source for this suite with a dedicated Signed-By keyring." >&2
        return 1
    done <<< "$definitions"
    printf '%s\n' "$found"
}

p2s_apt_source_download() {
    if p2s_command_exists curl; then
        p2s_command_run 30 curl --fail --silent --show-error --proto '=https' --connect-timeout 8 --max-time 25 --output "$2" "$1"
    elif p2s_command_exists wget; then
        p2s_command_run 30 wget --timeout=8 --tries=1 --max-redirect=0 -O "$2" "$1"
    else
        return 1
    fi
}

p2s_backports_preview_source() {
    local suite=$1 component=$2 scope=$3 name installed arch vendor build index
    local uri=https://animaartificialis.github.io/debian-php-backports
    local keyring=$P2S_BACKPORTS_ADD_KEYRING prefix="$P2S_WORK/backports-preview-$suite-$component-"
    if [ -z "$keyring" ]; then
        keyring="$P2S_WORK/backports-preview.gpg"
        if [ ! -s "$keyring" ]; then
            p2s_apt_source_download "$uri/debian-php-backports.asc" "$P2S_WORK/backports-preview.asc" &&
                p2s_backports_verify_key "$P2S_WORK/backports-preview.asc" &&
                p2s_command_run 30 gpg --no-options --batch --dearmor < "$P2S_WORK/backports-preview.asc" +                    > "$keyring.tmp" && mv -- "$keyring.tmp" "$keyring" || return 1
        fi
    fi
    if [ ! -s "${prefix}InRelease" ]; then
        p2s_apt_source_download "$uri/dists/$suite/InRelease" "${prefix}InRelease.tmp" &&
            mv -- "${prefix}InRelease.tmp" "${prefix}InRelease" || return 1
    fi
    if ! p2s_backports_verify_release "$suite" "${prefix}InRelease" "$keyring"; then
        p2s_fix_block source_authentication "Could not verify the published Backports release for $suite with the reviewed signing key."
        return 1
    fi
    if ! p2s_backports_source_selection "$suite" "$scope"; then
        p2s_fix_block candidate_provider "Could not match the installed source packages in the selected $suite Backports branch."
        return 1
    fi
    while IFS= read -r arch; do
        index="${prefix}${component}_binary-${arch}_Packages.gz"
        if [ ! -s "$index" ]; then
            p2s_apt_source_download "$uri/dists/$suite/$component/binary-$arch/Packages.gz" "$index.tmp" &&
                mv -- "$index.tmp" "$index" || return 1
        fi
    done < <(awk -F'|' '$3!="all" {print $3}' "$P2S_WORK/apt-selected" | sort -u)
    p2s_backports_verify_indexes "$suite" "$prefix" || return 1
    [ -s "$P2S_WORK/apt-selected" ] || return 1
    while IFS='|' read -r name installed arch vendor; do
        build=$(p2s_backports_package_build "$suite" "$name" "$arch" "$installed") || return 1
        [ "${build#*|}" = "$component" ] || continue
        if ! dpkg --compare-versions "${build%%|*}" ge "$installed" ||
            ! p2s_backports_candidate_sha256 "${name%:*}" "${build%%|*}" "$arch" "$component" >/dev/null; then
            p2s_fix_block candidate_fix "The signed Backports index has no eligible equivalent for $name ($arch)."
            return 1
        fi
    done < "$P2S_WORK/apt-selected"
}

# Prepare a new flat source using the signed package index before publishing any files.
p2s_stackx_prepare_source() {
    local suite=$1 uri=$2 preferences transport apt_version key stage="$P2S_WORK/stackx-preview-"
    local keyring=/etc/apt/keyrings/stackx-php.gpg
    local source_file=/etc/apt/sources.list.d/dephp2shell-stackx.list
    local pin_file=/etc/apt/preferences.d/dephp2shell-stackx.pref
    local record="$P2S_WORK/stackx-created" name installed arch vendor branch floor available version
    P2S_STACKX_KEYRING=$(p2s_stackx_configured_key "$uri") || return 1
    [ -z "$P2S_STACKX_KEYRING" ] || return 0
    for key in "$source_file" "$pin_file"; do
        if [ -e "$key" ] || [ -L "$key" ]; then
            p2s_fix_block source_authentication "The managed StackX path $key already exists. Review it before adding the repository."; return 1
        fi
    done
    preferences=$(p2s_command_run 30 apt-config shell main Dir::Etc::Preferences/f parts Dir::Etc::PreferencesParts/d 2>/dev/null) &&
        transport=$(p2s_command_run 30 apt-config shell method Dir::Bin::Methods/d 2>/dev/null) &&
        apt_version=$(p2s_command_run 30 dpkg-query -W -f='${Version}' apt 2>/dev/null) || return 1
    if [ "$preferences" != "main='/etc/apt/preferences'
parts='/etc/apt/preferences.d/'" ] || [ "$transport" != "method='/usr/lib/apt/methods/'" ] ||
        [ ! -x /usr/lib/apt/methods/https ] || ! dpkg --compare-versions "$apt_version" ge '1.1~'; then
        p2s_fix_block source_authentication "Adding StackX requires the standard APT preferences paths, working APT HTTPS transport and support for Signed-By."; return 1
    fi
    if [ -e "$keyring" ] || [ -L "$keyring" ]; then
        if [ -L "$keyring" ] || ! p2s_backports_verify_key "$keyring" AF97ED98AACE4CE129A03B6E2C9736B593BABF7F; then
            p2s_fix_block source_authentication "The existing StackX keyring could not be matched to ScalarX's signing fingerprint. Review $keyring."; return 1
        fi
        P2S_STACKX_KEYRING=$keyring
    else
        if ! p2s_apt_source_download https://mirrors.scalarx.net/stackx-php/stackx-repository.asc "$P2S_WORK/stackx.asc" ||
            ! p2s_backports_verify_key "$P2S_WORK/stackx.asc" AF97ED98AACE4CE129A03B6E2C9736B593BABF7F ||
            ! p2s_command_run 30 gpg --no-options --batch --dearmor < "$P2S_WORK/stackx.asc" > "$P2S_WORK/stackx.gpg"; then
            p2s_fix_block source_authentication "Could not download and verify the StackX signing key. Check HTTPS access to mirrors.scalarx.net."; return 1
        fi
        P2S_STACKX_KEYRING="$P2S_WORK/stackx.gpg"
    fi
    if ! p2s_apt_source_download "$uri/InRelease" "${stage}InRelease" ||
        ! p2s_apt_source_download "$uri/Packages.gz" "${stage}Packages.gz" ||
        ! p2s_stackx_verify_index "$suite" "$stage"; then
        p2s_fix_block source_authentication "Could not verify the signed StackX package index for Debian $suite."; return 1
    fi
    while IFS='|' read -r name installed arch vendor; do
        branch=$(p2s_backports_source "$name") && floor=$(p2s_stackx_published_build "$suite" "$branch") || return 1
        available=false
        while IFS= read -r version; do
            if [ "$version" = "$floor" ] &&
                dpkg --compare-versions "$version" ge "$installed"; then
                available=true; break
            fi
        done < <(awk -F'|' -v n="${name%:*}" -v a="$arch" '$1==n && $3==a {print $2}' "$P2S_WORK/backports-binary-hashes")
        if ! $available; then
            p2s_fix_block candidate_fix "The signed StackX feed has no eligible equivalent for $name ($arch)."; return 1
        fi
    done < "$P2S_WORK/apt-selected"

    if [ "${P2S_MODE:-check}" != fix ]; then
        P2S_STACKX_PREVIEW_ONLY=true
        return 0
    fi
    {
        awk -F'|' '{
            name=$1; sub(/:[^:]+$/, "", name)
            if (name !~ /^[a-z0-9][a-z0-9+.-]*$/ || ($3!="all" && $3!="amd64")) {bad=1; next}
            print "Package: " name ":" ($3=="all" ? "any" : $3) "\nPin: origin \"mirrors.scalarx.net\"\nPin-Priority: 500\n"
        } END {exit bad}' "$P2S_WORK/apt-selected" &&
        # APT::Default-Release can override the generic pin. The pattern pins each unselected version.
        printf 'Package: /^.+$/:any\nPin: origin "mirrors.scalarx.net"\nPin-Priority: -1\n\n'
        printf 'Package: *\nPin: origin "mirrors.scalarx.net"\nPin-Priority: -1\n'
    } > "$P2S_WORK/stackx.pref" || return 1
    printf 'deb [arch=amd64 signed-by=%s] %s ./\n' "$keyring" "$uri" > "$P2S_WORK/stackx.list" || return 1
    # P2S-MUTATION: Publish the preference before enabling the source. Roll back this run's files before an install attempt.
    if ! (umask 022; mkdir -p /etc/apt/keyrings /etc/apt/preferences.d /etc/apt/sources.list.d) ||
        { [ "$P2S_STACKX_KEYRING" != "$keyring" ] &&
            ! p2s_backports_publish_file "$P2S_STACKX_KEYRING" "$keyring" "$record"; } ||
        ! p2s_backports_publish_file "$P2S_WORK/stackx.pref" "$pin_file" "$record" ||
        ! p2s_backports_publish_file "$P2S_WORK/stackx.list" "$source_file" "$record"; then
        p2s_fix_block source_authentication "Could not configure StackX without replacing an existing APT file."; return 1
    fi
    P2S_STACKX_KEYRING=$keyring
    P2S_STACKX_REPOSITORY_CREATED=true
    p2s_manifest_record repository_change "StackX|added=$suite|source_file=$source_file|preference_file=$pin_file"
}

p2s_stackx_preferences_verified() {
    local uri=$1 name
    local -a names=()
    while IFS= read -r name; do names[${#names[@]}]=$name; done < <(
        awk -F'|' '$1 ~ /^[a-z0-9][a-z0-9+.-]*$/ {print $1}' "$P2S_WORK/backports-binary-hashes" | sort -u
    )
    [ "${#names[@]}" -gt 0 ] || return 1
    p2s_command_run 60 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "${names[@]}" > "$P2S_WORK/stackx-policy" ||
        return 1
    awk -v uri="$uri" '
        FILENAME==ARGV[1] {
            split($0, selected, /[|]/)
            name=selected[1]; sub(/:[^:]+$/, "", name); allowed[name]=1; next
        }
        /^[a-z0-9][a-z0-9+.:-]*:$/ {
            name=$0; sub(/:$/, "", name); sub(/:[^:]+$/, "", name); priority=0; next
        }
        {
            position=($1=="***" ? 2 : 1)
            if (NF==position+1 && $(position+1) ~ /^-?[0-9]+$/) priority=$(position+1)+0
            if (($2==uri || $2==uri "/") && $3=="./" && $4=="Packages") {
                found=1
                if (!(name in allowed) && priority>=0) bad=1
            }
        }
        END {exit (!found || bad)}
    ' "$P2S_WORK/apt-selected" "$P2S_WORK/stackx-policy"
}

# Read-only apart from temporary APT and key inspection data.
p2s_backports_add_preflight() {
    local suite=$1 apt_version https_method preferences definitions state configured_key file component keyring=''
    local managed_key=/etc/apt/keyrings/dephp2shell-debian-php-backports.gpg
    local -a missing
    shift
    P2S_BACKPORTS_ADD_KEYRING=''
    P2S_BACKPORTS_ADD_MISSING=$(p2s_backports_missing_components "$suite" "$@") || return 1
    [ -n "$P2S_BACKPORTS_ADD_MISSING" ] || return 0
    p2s_package_deb_sury_trust_preflight || return 1
    preferences=$(p2s_command_run 30 apt-config shell main Dir::Etc::Preferences/f parts Dir::Etc::PreferencesParts/d 2>/dev/null) || return 1
    if [ "$preferences" != "main='/etc/apt/preferences'
parts='/etc/apt/preferences.d/'" ]; then
        p2s_fix_block source_authentication "APT is configured to use a custom preferences path. Review the source and package priorities before adding Backports."
        return 1
    fi
    read -r -a missing <<< "$P2S_BACKPORTS_ADD_MISSING"
    for component in "${missing[@]}"; do
        for file in "/etc/apt/preferences.d/dephp2shell-debian-php-backports-$component.pref" \
            "/etc/apt/sources.list.d/dephp2shell-debian-php-backports-$component.list"; do
            if [ -e "$file" ] || [ -L "$file" ]; then
                p2s_fix_block source_authentication "The managed Backports path $file already exists for a missing component. Review the existing file."
                return 1
            fi
        done
    done
    apt_version=$(p2s_command_run 30 dpkg-query -W -f='${Version}' apt 2>/dev/null) || return 1
    if ! dpkg --compare-versions "$apt_version" ge '1.1~'; then
        p2s_fix_block source_authentication "APT $apt_version cannot add a source with a repository-scoped signing key. This operation requires APT 1.1 or newer."
        return 1
    fi
    https_method=$(p2s_command_run 30 apt-config shell method Dir::Bin::Methods/d 2>/dev/null) || return 1
    if [ "$https_method" != "method='/usr/lib/apt/methods/'" ] || [ ! -x /usr/lib/apt/methods/https ]; then
        p2s_fix_block source_authentication "APT needs its configured HTTPS acquisition method to add Backports. Review the existing APT HTTPS transport."
        return 1
    fi
    if [ ! -x /usr/lib/apt/apt-helper ] || ! p2s_command_exists gpg; then
        p2s_fix_block source_authentication "Adding or expanding Backports requires the installed gpg and APT helper commands to verify the repository."
        return 1
    fi
    definitions=$(p2s_backports_configured_sources "$suite") || return 1
    while IFS='|' read -r state _ configured_key file; do
        case "$state" in active|source)
            if [ "$configured_key" = '-' ] || { [ -n "$keyring" ] && [ "$keyring" != "$configured_key" ]; }; then
                p2s_fix_block source_authentication "Existing Backports definitions for $suite need one matching dedicated .gpg Signed-By keyring before components can be added. Review $file."
                return 1
            fi
            keyring=$configured_key ;;
        esac
    done <<< "$definitions"
    if [ -n "$keyring" ]; then
        if ! p2s_backports_verify_key "$keyring"; then
            p2s_fix_block source_authentication "The existing Backports Signed-By keyring could not be verified against the published signing fingerprint."
            return 1
        fi
    else
        for file in "$managed_key" /etc/apt/keyrings/*debian-php-backports*.gpg /usr/share/keyrings/*debian-php-backports*.gpg; do
            [ -f "$file" ] || continue
            if p2s_backports_verify_key "$file"; then keyring=$file; break; fi
        done
    fi
    if [ -z "$keyring" ]; then
        if [ -e "$managed_key" ] || [ -L "$managed_key" ]; then
            p2s_fix_block source_authentication "The managed Backports keyring exists and could not be verified. Review $managed_key."
            return 1
        fi
        if ! p2s_command_exists curl && ! p2s_command_exists wget; then
            p2s_fix_block source_authentication "Adding Backports needs an installed curl or wget command to retrieve the signing key over HTTPS."
            return 1
        fi
    fi
    P2S_BACKPORTS_ADD_KEYRING=$keyring
}

# P2S-MUTATION: Add only expressly allowed Backports components for the reviewed suite.
p2s_disruptive_backports_add_repository() {
    local suite=$1 missing component keyring output_key=false
    local name installed arch vendor build pin_file index
    local uri=https://animaartificialis.github.io/debian-php-backports
    local managed_key=/etc/apt/keyrings/dephp2shell-debian-php-backports.gpg
    local -a components
    shift
    if [ "${P2S_MODE:-check}" != fix ] || ! ${P2S_ALLOW_BACKPORTS_REPOSITORY:-false}; then
        p2s_fix_block source_authentication "Adding or expanding Debian PHP Backports requires fix mode and explicit repository permission."
        return 1
    fi
    local P2S_BACKPORTS_ADD_MISSING P2S_BACKPORTS_ADD_KEYRING
    p2s_backports_add_preflight "$suite" "$@" || return 1
    missing=$P2S_BACKPORTS_ADD_MISSING
    [ -n "$missing" ] || return 0
    read -r -a components <<< "$missing"
    keyring=$P2S_BACKPORTS_ADD_KEYRING
    if [ -z "$keyring" ]; then
        keyring=$managed_key
        output_key=true
        if p2s_command_exists curl; then
            p2s_command_run 90 curl --fail --silent --show-error --proto '=https' --connect-timeout 20 --max-time 60 \
                --output "$P2S_WORK/backports.key" "$uri/debian-php-backports.asc" > "$P2S_WORK/backports-key-download.log" 2>&1 || output_key=failed
        elif p2s_command_exists wget; then
            p2s_command_run 90 wget --timeout=20 --tries=1 --max-redirect=0 -O "$P2S_WORK/backports.key" \
                "$uri/debian-php-backports.asc" > "$P2S_WORK/backports-key-download.log" 2>&1 || output_key=failed
        else
            output_key=failed
        fi
        if [ "$output_key" = failed ]; then
            p2s_fix_block source_authentication "The Backports key could not be downloaded over verified HTTPS. Check connectivity, CA certificates and the installed curl or wget command."
            return 1
        fi
        if ! p2s_backports_verify_key "$P2S_WORK/backports.key" ||
            ! p2s_command_run 30 gpg --no-options --batch --dearmor < "$P2S_WORK/backports.key" > "$P2S_WORK/backports.gpg" 2>/dev/null; then
            p2s_fix_block source_authentication "The downloaded Backports key could not be verified and prepared as a dedicated APT keyring."
            return 1
        fi
    fi
    # Use package-specific fallbacks because APT::Default-Release can override
    # a generic Package: * pin. Keep user preferences for existing components.
    for component in "${components[@]}"; do
        : > "$P2S_WORK/backports-$component.approved" || return 1
        while IFS='|' read -r name installed arch vendor; do
            build=$(p2s_backports_package_build "$suite" "$name" "$arch" "$installed") || continue
            [ "${build#*|}" = "$component" ] || continue
            name=${name%:*}
            case "$name" in ''|*[!a-z0-9+.-]*) return 1 ;; esac
            case "$arch" in amd64|arm64|all) ;; *) return 1 ;; esac
            printf '%s|%s|%s\n' "$name" "$arch" "${build%%|*}" >> "$P2S_WORK/backports-$component.approved" || return 1
        done < "$P2S_WORK/apt-selected"
        if [ ! -s "$P2S_WORK/backports-$component.approved" ]; then
            p2s_fix_block source_authentication "No reviewed installed PHP packages qualify for the $suite/$component Backports preference."
            return 1
        fi
        {
            awk -F'|' '{ arch=($2=="all" ? "any" : $2); print "Package: " $1 ":" arch "\nPin: version " $3 "\nPin-Priority: 500\n" }' \
                "$P2S_WORK/backports-$component.approved" &&
            printf 'Package: *:any\nPin: release o=debian-php-backports,a=%s,n=%s,l=debian-php-backports,c=%s\nPin-Priority: -1\n' \
                "$suite" "$suite" "$component"
        } > "$P2S_WORK/backports-$component.pref" || return 1
        printf 'deb [signed-by=%s] %s %s %s\n' "$keyring" "$uri" "$suite" "$component" > "$P2S_WORK/backports-$component.list" || return 1
    done
    if ! (umask 022; mkdir -p /etc/apt/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d); then
        p2s_fix_block source_authentication "The directories for dedicated Backports configuration could not be prepared."
        return 1
    fi
    if $output_key && ! p2s_backports_publish_file "$P2S_WORK/backports.gpg" "$keyring"; then
        p2s_fix_block source_authentication "The dedicated Backports keyring could not be created without overwriting an existing file."
        return 1
    fi
    for component in "${components[@]}"; do
        pin_file=/etc/apt/preferences.d/dephp2shell-debian-php-backports-$component.pref
        index=/etc/apt/sources.list.d/dephp2shell-debian-php-backports-$component.list
        if ! p2s_backports_publish_file "$P2S_WORK/backports-$component.pref" "$pin_file" ||
            ! p2s_backports_publish_file "$P2S_WORK/backports-$component.list" "$index"; then
            p2s_fix_block source_authentication "The dedicated Backports source or preference for $suite/$component could not be created without overwriting an existing file."
            return 1
        fi
        P2S_BACKPORTS_REPOSITORY_CREATED=true
        P2S_BACKPORTS_ADDED_COMPONENTS="${P2S_BACKPORTS_ADDED_COMPONENTS:+$P2S_BACKPORTS_ADDED_COMPONENTS }$component"
        p2s_manifest_record repository_change "Backports|added=$suite/$component|source_file=$index|preference_file=$pin_file"
    done
}

# Verify every advertised binary's effective version priority. APT's release row
# alone misses package-specific rules and overrides in the user's preferences.
p2s_backports_scope_preferences_verified() {
    ${P2S_BACKPORTS_REPOSITORY_CREATED:-false} || return 0
    local suite=$1 native_arch component index uri codename target_component index_arch
    local approved inventory expected policy target
    local -a backports_targets
    native_arch=$(p2s_command_run 30 dpkg --print-architecture) || return 1
    p2s_command_run 30 apt-get indextargets --format '$(FILENAME)|$(SITE)|$(CODENAME)|$(COMPONENT)|$(ARCHITECTURE)' \
        'Identifier: Packages' > "$P2S_WORK/backports-index-targets" 2>/dev/null || return 1
    for component in $P2S_BACKPORTS_ADDED_COMPONENTS; do
        approved="$P2S_WORK/backports-$component.approved"
        inventory="$P2S_WORK/backports-$component.inventory"
        expected="$P2S_WORK/backports-$component.expected"
        policy="$P2S_WORK/backports-$component.policy"
        : > "$inventory" || return 1
        while IFS='|' read -r index uri codename target_component index_arch; do
            if [ "$uri" != https://animaartificialis.github.io/debian-php-backports ] ||
                [ "$codename" != "$suite" ] || [ "$target_component" != "$component" ]; then
                continue
            fi
            if [ ! -f "$index" ] || ! p2s_command_run 30 /usr/lib/apt/apt-helper cat-file "$index" > "$P2S_WORK/backports-index-content" 2>/dev/null; then
                p2s_fix_block source_authentication "Could not read the refreshed $suite/$component binary index for $index_arch."
                return 1
            fi
            awk '
                /^Package: / {package=$2}
                /^Architecture: / {architecture=$2}
                /^Version: / {version=$2}
                function emit() {
                    if (package!="" && architecture!="" && version!="") print package "|" architecture "|" version
                    package=architecture=version=""
                }
                /^$/ {emit()}
                END {emit()}
            ' "$P2S_WORK/backports-index-content" >> "$inventory" || return 1
        done < "$P2S_WORK/backports-index-targets"
        if [ ! -s "$inventory" ]; then
            p2s_fix_block source_authentication "APT returned no binary index for the newly added $suite/$component component."
            return 1
        fi
        awk -F'|' -v native="$native_arch" '
            NR==FNR {approved[$0]=1; next}
            {
                key=$1
                if ($2!=native && $2!="all") key=key ":" $2
                print key "|" $3 "|" (($0 in approved) ? 500 : -1)
            }
        ' "$approved" "$inventory" > "$expected" || return 1
        if ! awk -F'|' '!seen[$1]++ {print $1}' "$expected" > "$P2S_WORK/backports-policy-targets"; then return 1; fi
        backports_targets=()
        while IFS= read -r target; do backports_targets[${#backports_targets[@]}]=$target; done < "$P2S_WORK/backports-policy-targets"
        if ! p2s_command_run 60 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "${backports_targets[@]}" > "$policy" 2>/dev/null; then
            p2s_fix_block source_authentication "Could not inspect APT priorities for the newly added $suite/$component binary packages."
            return 1
        fi
        if ! awk '
            NR==FNR {
                split($0, fields, "|")
                expected[fields[1] SUBSEP fields[2]]=fields[3]
                next
            }
            /^[^ \t].*:[ \t]*$/ {package=$0; sub(/:[ \t]*$/, "", package)}
            $NF ~ /^-?[0-9]+$/ && (NF==2 || (NF==3 && $1=="***")) {
                version=$(NF-1)
                key=package SUBSEP version
                if (key in expected && $NF==expected[key]) delete expected[key]
            }
            END {
                failed=0
                for (key in expected) {
                    split(key, fields, SUBSEP)
                    print fields[1] "|" fields[2] "|expected_priority=" expected[key]
                    failed=1
                }
                exit failed
            }
        ' "$expected" "$policy" > "$P2S_WORK/backports-pin-mismatches"; then
            p2s_manifest_record repository_scope "Backports|$suite/$component|preferences_mismatch
$(cat "$P2S_WORK/backports-pin-mismatches")"
            p2s_fix_block source_authentication "Effective APT package priorities for the newly added $suite/$component component differ from the scoped preference. Review APT preferences before installing packages."
            return 1
        fi
        p2s_manifest_record repository_scope "Backports|$suite/$component|approved_exact_versions_positive|other_indexed_versions_excluded"
    done
}

# P2S-MUTATION: Removes only this run's opted-in source/key before any PHP installation attempt.
p2s_disruptive_sury_cleanup_added_repository() {
    # Retain an opted-in source after an installation attempt, including a partial failure, for recovery.
    if ${P2S_SURY_TRANSACTION_ATTEMPTED:-false}; then return 0; fi
    if ${P2S_SURY_REPOSITORY_CREATED:-false}; then
        rm -f /etc/apt/sources.list.d/dephp2shell-sury-php.list
        p2s_manifest_record repository_change 'Sury|new_source_removed|no_Sury_installation_attempt'
    fi
    if ${P2S_SURY_KEY_CREATED:-false}; then rm -f /etc/apt/keyrings/dephp2shell-sury-php.gpg; fi
    if ${P2S_SURY_PREFERENCES_CREATED:-false}; then rm -f /etc/apt/preferences.d/dephp2shell-sury-php.pref; fi
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

# P2S-MUTATION: Only the separately enabled migration may add this scoped source and key.
p2s_disruptive_sury_add_repository() {
    local suite uri key_url fingerprint file observed origin branch keyring=/etc/apt/keyrings/dephp2shell-sury-php.gpg
    local source_file=/etc/apt/sources.list.d/dephp2shell-sury-php.list
    local preferences=/etc/apt/preferences.d/dephp2shell-sury-php.pref
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
        ubuntu:26.04) ${P2S_NOVEMBER:-false} || return 1; suite=resolute ;;
        *) p2s_fix_block provider_migration "No matching Sury repository is reviewed for this OS release."; return 1 ;;
    esac
    if [ "$P2S_DISTRO" = debian ] || [ "$suite" = resolute ]; then
        uri=https://packages.sury.org/php
        origin=deb.sury.org
        key_url=https://packages.sury.org/php/apt.gpg
        fingerprint=15058500A0235D97F5D10063B188E2B695BD4743
    else
        uri=https://ppa.launchpadcontent.net/ondrej/php/ubuntu
        origin=LP-PPA-ondrej-php
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
    for file in "$keyring" "$source_file" "$preferences"; do
        if [ -e "$file" ] || [ -L "$file" ]; then
            p2s_fix_block source_authentication "The dedicated DePHP2Shell source or key file already exists but its repository is unavailable. Review it before retrying; no file was overwritten."; return 1
        fi
    done
    if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ]; then
        # Leave all other branches and shared packages on their existing sources in future APT runs too.
        if ! {
            while IFS= read -r branch; do
                case "$branch" in php[0-9].[0-9]) ;; *) return 1 ;; esac
                printf 'Package: src:%s:any\nPin: release o=%s,n=%s\nPin-Priority: 500\n\n' "$branch" "$origin" "$suite" || return 1
            done < "$P2S_APT_PHASE_BRANCHES"
            # Bullseye PHP can require the reviewed PCRE2 shared-library update.
            if [ "$suite" = bullseye ]; then
                printf 'Package: libpcre2-8-0:amd64\nPin: release o=%s,n=%s\nPin-Priority: 500\n\n' "$origin" "$suite" || return 1
            fi
            printf 'Package: *\nPin: release o=%s,n=%s\nPin-Priority: -1\n' "$origin" "$suite"
        } > "$P2S_WORK/sury-preferences"; then return 1; fi
    fi
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
    if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ]; then
        if ! (umask 022; mkdir -p /etc/apt/preferences.d && set -C && : > "$preferences"); then
            p2s_fix_block source_authentication "The dedicated PHP repository preference could not be created without replacing another file."; return 1
        fi
        P2S_SURY_PREFERENCES_CREATED=true
        if ! cat "$P2S_WORK/sury-preferences" > "$preferences"; then
            p2s_fix_block source_authentication "The dedicated PHP repository preference could not be written; it will be removed."; return 1
        fi
        p2s_manifest_record repository_scope "Sury|approved_source_packages=$(paste -sd, "$P2S_APT_PHASE_BRANCHES")|preference_file=$preferences"
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
        ubuntu:14.04) suite=trusty ;; ubuntu:16.04) suite=xenial ;;
        ubuntu:18.04) suite=bionic ;; ubuntu:20.04) suite=focal ;;
        ubuntu:22.04) suite=jammy ;; ubuntu:24.04) suite=noble ;;
        ubuntu:26.04) suite=resolute ;;
    esac
    # deb [signed-by=/key] URI suite main; Deb822 fields can continue on indented lines.
    # extrepo_sury.sources + /var/lib/extrepo/keys/sury.asc identify the managed PHP source.
    LC_ALL=C awk -v file="$file" -v suite="$suite" -v distro="${P2S_DISTRO:-}" -v active_arch="${2:-}" \
        -v standard_key=/usr/share/keyrings/debsuryorg-archive-keyring.gpg \
        -v extrepo_key=/var/lib/extrepo/keys/sury.asc '
        function trim(value) {gsub(/^[ \t]+|[ \t]+$/,"",value); return value}
        function contains(value,item) {gsub(/[, \t]+/," ",value); return index(" " trim(value) " "," " item " ")>0}
        # APT: Suites: bookworm + Components: main; exact-path Suites: ./ omits Components.
        function components_valid(n,a,i) {
            n=split(trim(suites),a,/[ \t]+/); if(trim(suites)=="") return 0
            for(i=1;i<=n;i++) {
                if(a[i] ~ /\/$/) {if(trim(components)!="") return 0}
                else if(trim(components)=="") return 0
            }
            return 1
        }
        function emit(n,a,i,uri,host,path,layout,matching,provider,family,reported_suites,suite_count,suite_names,suite_index,configured_suite,matching_suite) {
            if(types !~ /(^|[ \t])(deb|deb-src|rpm)([ \t]|$)/) return
            suite_count=split(trim(suites),suite_names,/[ \t]+/); matching_suite=0
            for(suite_index=1;suite_index<=suite_count;suite_index++) if(suite_names[suite_index]==suite) matching_suite=1
            n=split(uris,a,/[ \t]+/)
            for(i=1;i<=n;i++) {
                uri=a[i]; if(uri !~ /^https?:\/\//) continue
                host=uri; sub(/^https?:\/\//,"",host); sub(/[\/?#].*$/,"",host); sub(/^.*@/,"",host)
                path=uri; sub(/^https?:\/\/[^\/]+/,"",path); sub(/[?#].*$/,"",path)
                if(active_arch!="") {
                    if(enabled=="yes" && contains(types,"deb") && components_valid() && suite!="" && matching_suite &&
                       (active_arch=="all" || ((architectures=="" || contains(architectures,active_arch) || contains(added_architectures,active_arch)) && !contains(excluded_architectures,active_arch))) &&
                       (((distro=="debian" || distro=="ubuntu") && host=="packages.sury.org" && path ~ /^\/php\/?$/) ||
                        (distro=="ubuntu" && host ~ /^ppa[.]launchpad(content)?[.]net$/ && path ~ /^\/ondrej\/php\/ubuntu\/?$/))) print "active"
                    continue
                }
                provider=""; family=""
                if(host=="packages.sury.org" && path ~ /^\/php\/?$/ && types!="rpm") {
                    provider="sury"
                    layout="standard"
                    if(file ~ /\/extrepo_sury[.]sources$/ || signing==extrepo_key) {
                        layout="extrepo"
                        if(signing!=extrepo_key || uri !~ /^https:\/\//) layout="extrepo_custom"
                    } else if(signing!=standard_key || uri !~ /^https:\/\//) layout="legacy_or_custom"
                } else if(host ~ /^ppa[.]launchpad(content)?[.]net$/ && path ~ /^\/ondrej\/php\/ubuntu\/?$/ && types!="rpm") {
                    provider="ondrej"; family="Ubuntu"; layout="ppa"
                }
                if(provider!="") {
                    # Suites: bookworm bookworm bullseye -> matching bookworm, different bullseye.
                    reported_suites=""
                    if(suite_count==0 || trim(suites)=="") {suite_count=1; suite_names[1]="unrecognised"}
                    for(suite_index=1;suite_index<=suite_count;suite_index++) {
                        configured_suite=suite_names[suite_index]
                        if(configured_suite !~ /^[a-zA-Z0-9_.+~\/-]+$/) configured_suite="unrecognised"
                        if(contains(reported_suites,configured_suite)) continue
                        reported_suites=reported_suites " " configured_suite
                        family="unverified"
                        # Hostnames do not establish the distribution of every suite in a mixed stanza.
                        if(provider=="ondrej" || contains("trusty xenial bionic focal jammy noble resolute",configured_suite)) family="Ubuntu"
                        else if(contains("stretch buster bullseye bookworm trixie",configured_suite)) family="Debian"
                        matching="unreviewed"
                        if(suite!="") {matching="different"; if(configured_suite==suite) matching="matching"}
                        if((distro=="debian" && family=="Ubuntu") || (distro=="ubuntu" && family=="Debian")) matching="different"
                        if(!components_valid()) {layout="invalid_components"; matching="unreviewed"}
                        print provider "|" layout "|" enabled "|" matching "|" family "|" configured_suite "|" suite
                    }
                } else if(host=="software.virtualmin.com") print "virtualmin|legacy|" enabled "|unreviewed"
                else if(host=="download.virtualmin.com") print "virtualmin|current|" enabled "|unreviewed"
            }
        }
        function reset() {types=""; uris=""; suites=""; components=""; signing=""; enabled="yes"; key=""; architectures=""; added_architectures=""; excluded_architectures=""}
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
                count=split(line,entry,/[ \t]+/); uris=entry[1]; suites=entry[2]
                for(j=3;j<=count;j++) components=components " " entry[j]
                emit(); reset(); next
            }
            if(file ~ /[.]sources$/) {
                if($0 !~ /^[ \t]/ && line ~ /^[A-Za-z-]+:/) {key=tolower(line); sub(/:.*/,"",key); sub(/^[^:]*:[ \t]*/,"",line)}
                else if($0 !~ /^[ \t]/) key=""
                if(key=="types") types=types " " line
                if(key=="uris") uris=uris " " line
                if(key=="suites") suites=suites " " line
                if(key=="components") components=components " " line
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
                    ''|none) advice='Automatic Sury/ondrej updates need an active matching source. Review missing, malformed, commented-out or disabled sources and their release and architecture settings.' ;;
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
        if [ "$layout" = invalid_components ]; then
            p2s_message_print warn "PHP source definition in $file has an invalid Components setting for suite '$suites'. Named suites require Components; exact-path suites ending '/' must omit them. This definition was not counted as an active matching source."
            p2s_manifest_record source_gap "$file|PHP_source_components_invalid|suite=$suites"
            continue
        fi
        case "$provider:$matching" in sury:different|ondrej:different)
            case "$P2S_DISTRO" in
                ubuntu) advice="Confirm current publisher support for ${expected:-the installed Ubuntu release} at https://launchpad.net/~ondrej/+archive/ubuntu/php or https://packages.sury.org/php/dists/, or plan a supported OS/application migration." ;;
                debian) advice="Confirm a maintained package source for ${expected:-the installed Debian release}; review current Sury suites at https://packages.sury.org/php/dists/ or plan a supported OS/application migration." ;;
                *) advice='Check the PHP publisher support for this distribution and release.' ;;
            esac
            p2s_message_print warn "PHP repository mismatch in $file: configured $family suite '$suites'; this server runs $P2S_DISTRO $P2S_RELEASE (expected suite '${expected:-unverified}'). $advice Do not substitute another release's repository. This source configuration does not establish the origin of installed packages. Changing or disabling the source does not replace packages or verify PHP fixes. Use apt-cache policy PACKAGE to inspect installed and candidate versions and their sources."
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

# Inspect only selected FPM packages after a failed repair; never start or change a service.
p2s_package_deb_repair_fpm_diagnostics() {
    local targets="$1" since="$2" name version arch branch unit probe status binary config
    while IFS='|' read -r name version arch; do
        name=${name%:*}
        case "$name" in php[0-9].[0-9]-fpm) ;; *) continue ;; esac
        branch=${name#php}; branch=${branch%-fpm}; unit="$name.service"
        p2s_message_print info "PHP-FPM repair diagnostics for $name: review the service state, recent journal and standard configuration test in the detailed log. Service overrides may select a different configuration."
        for probe in systemctl journalctl; do
            if ! p2s_command_exists "$probe"; then
                p2s_manifest_record package_repair_service_probe "$unit|$probe|unavailable"
                continue
            fi
            status=0
            case "$probe" in
                systemctl) p2s_command_run 10 systemctl show "$unit" -p LoadState -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus > "$P2S_WORK/repair-service.log" 2>&1 || status=$? ;;
                journalctl) p2s_command_run 10 journalctl --unit="$unit" --since="$since" --lines=30 --no-pager --output=cat > "$P2S_WORK/repair-service.log" 2>&1 || status=$? ;;
            esac
            p2s_manifest_record package_repair_service_probe "$unit|$probe|exit=$status"
            p2s_manifest_record package_repair_service_output "$unit|$probe
$(p2s_service_diagnostic_redact < "$P2S_WORK/repair-service.log")"
        done
        binary="/usr/sbin/php-fpm$branch"; config="/etc/php/$branch/fpm/php-fpm.conf"
        if [ -x "$binary" ] && [ -r "$config" ]; then
            p2s_service_check_config "PHP-FPM ($name standard configuration after failed repair)" "$binary" -y "$config" -t
        else
            p2s_manifest_record package_repair_service_probe "$unit|configtest|standard_executable_or_configuration_unavailable"
        fi
    done < "$targets"
    return 0
}

# P2S-MUTATION: Configure only verified unpacked/half-configured standard PHP packages.
p2s_disruptive_package_configure_pending_php() {
    local name version arch target configure_status=0 started
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
    started=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    (export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
        p2s_command_run 600 dpkg --force-confold --no-triggers --configure "${targets[@]}" > "$P2S_WORK/repair.log" 2>&1) || configure_status=$?
    p2s_manifest_record package_repair_exit "configure_pending_php|exit=$configure_status|targets=${targets[*]}"
    if [ "$configure_status" -ne 0 ]; then
        p2s_package_log_report "$P2S_WORK/repair.log"
        p2s_fix_block package_repair "Could not finish configuring ${targets[*]} (dpkg exit $configure_status; 124 means timeout). Review the dpkg output and PHP-FPM diagnostics before retrying; configuration scripts may have changed services."
        p2s_package_deb_repair_fpm_diagnostics "$P2S_WORK/repair-pending" "$started"
        return 1
    fi
    p2s_package_log_report "$P2S_WORK/repair.log"
    p2s_package_deb_repair_finish "$P2S_WORK/repair-pending"
}

# Verify the exact APT candidate for an already-installed package from reviewed sources.
p2s_package_deb_exact_candidate_validate() {
    local name="$1" version="$2" arch="$3" installed="${4:-$2}" target suite origin source provider
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
    if [ "$installed" = "$version" ]; then
        p2s_manifest_record package_reinstall_policy "$name|$version|$arch
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/repair-policy")"
    else
        p2s_manifest_record apt_candidate_policy "$name|installed=$installed|architecture=$arch
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/repair-policy")"
    fi
    # Bind each exact-version source row to authenticated release Origin and the measured OS suite.
    if ! awk -v v="$version" -v i="$installed" -v suite="$suite" -v origin="$origin" -v provider="$provider" -v arch="$arch" '
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
        END {exit installed!=i || candidate!=v || !matches || bad}' "$P2S_WORK/repair-origins" "$P2S_WORK/repair-policy"; then return 1; fi
    p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$version" > "$P2S_WORK/repair-metadata" 2> "$P2S_WORK/repair-query.err" || return 1
    awk -v n="${name%:*}" -v v="$version" -v a="$arch" -v s="$source" -v i="$installed" '
        function check() {
            if (!package) return
            if (source=="") source=package
            if (package!=n || version!=v || arch!=a || source!=s || !hash || !file ||
                (i!=v && source_version!="" && source_version!="(" v ")")) bad=1
            records++
        }
        /^Package:/ {check(); package=$2; version=""; arch=""; source=""; source_version=""; hash=""; file=""}
        /^Version:/ {version=$2} /^Architecture:/ {arch=$2} /^Source:/ {source=$2; source_version=$3}
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
        if ! p2s_package_deb_exact_candidate_validate "$name" "$version" "$arch"; then
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

# APT may include an installed branch metapackage, e.g. php8.2 [8.2.35-1~deb12u1]
# -> 8.2.36-1~deb12u1 [all] alongside the approved php8.2-common upgrade.
p2s_package_deb_approve_metapackage() {
    local name="$1" old="$2" candidate="$3" arch="$4" branch record origin
    [ "$arch" = all ] && ! ${P2S_SURY_MIGRATION_ACTIVE:-false} || return 1
    branch=${name#php}
    case "${old#*:}:${candidate#*:}" in "$branch".*:"$branch".*) ;; *) return 1 ;; esac
    dpkg --compare-versions "$candidate" gt "$old" || return 1
    awk -F'|' -v n="$name-common" -v v="$candidate" '$1==n && $2==v && $3!="all" {found=1} END {exit !found}' \
        "$P2S_WORK/apt-approved" || return 1
    case "$P2S_DISTRO" in debian) origin=Debian ;; ubuntu) origin=Ubuntu ;; *) return 1 ;; esac
    record=$(p2s_command_run 30 dpkg-query -W '-f=${Status}|${Package}|${Version}|${Architecture}|${source:Package}|${source:Version}|${Maintainer}\n' "$name") || return 1
    case "$record" in
        "install ok installed|$name|$old|all|$name|$old|"*) ;;
        *) return 1 ;;
    esac
    [ "$(p2s_package_provider "$name" "${record##*|}" "$old")" = "$origin" ] || return 1
    # Candidate and installed identity must remain native even if Sury is configured.
    [ "$(p2s_package_provider "$name" "$origin" "$candidate")" = "$origin" ] || return 1
    p2s_package_deb_exact_candidate_validate "$name" "$candidate" "$arch" "$old" || return 1
    printf '%s|%s|%s|%s\n' "$name" "$candidate" "$arch" "$name" >> "$P2S_WORK/dependency-approved" &&
        printf '%s=%s\n' "$name" "$candidate" >> "$P2S_WORK/dependency-arguments"
}

# Read-only proposal approval; caller must rerun the pinned simulation and guard installation.
p2s_package_deb_dependency_approve_plan() {
    local log="$1" name old candidate arch installed_source record target suite origin file parent dep op required installed_version candidate_version maintainer plan_arch sury_pcre policy_status metadata_version new_library
    local signed_elts=''
    if ${P2S_FREEXIAN_ACTIVE:-false} && [ "${P2S_REPOSITORY_REFRESH:-}" = refreshed ]; then
        signed_elts=${P2S_FREEXIAN_SIGNED_SUITES:-}
    fi
    case "$P2S_BACKEND:$P2S_DISTRO:$P2S_RELEASE" in
        deb:debian:9|deb:debian:9.*) suite=stretch; origin=Debian ;;
        deb:debian:10|deb:debian:10.*) suite=buster; origin=Debian ;;
        deb:debian:11|deb:debian:11.*) suite=bullseye; origin=Debian ;;
        deb:debian:12|deb:debian:12.*) suite=bookworm; origin=Debian ;;
        deb:debian:13|deb:debian:13.*) suite=trixie; origin=Debian ;;
        deb:ubuntu:22.04) suite=jammy; origin=Ubuntu ;;
        deb:ubuntu:24.04) suite=noble; origin=Ubuntu ;;
        deb:ubuntu:26.04) suite=resolute; origin=Ubuntu ;;
        *) p2s_fix_block dependency_platform "No reviewed native dependency upgrade method exists for this OS release."; return 1 ;;
    esac
    if { [ "$suite" = stretch ] || [ "$suite" = buster ]; } && [ -z "${signed_elts// /}" ]; then
        p2s_fix_block dependency_platform "This legacy Debian release requires a verified public Freexian Extended LTS update path for automatic PHP library upgrades."
        return 1
    fi
    : > "$P2S_WORK/dependency-approved"
    : > "$P2S_WORK/dependency-arguments"
    : > "$P2S_WORK/dependency-new"
    : > "$P2S_WORK/dependency-needed"
    : > "$P2S_WORK/dependency-edges"
    # apt-get -s: php is already the newest version (2:7.4+76).
    # Inst php7.4-cli [old] (new bullseye [amd64]) [php7.4-common:amd64 ]
    # Inst libicu72 (72.1-3 bookworm [amd64]) -> libicu72|(none)|72.1-3|amd64
    # The trailing list tracks temporary dependency breaks while APT orders the upgrade.
    # Use 'apt autoremove' to remove it. / Use 'apt autoremove' to remove them.
    # These are advice only; \047 quotes an apostrophe inside AWK.
    if ! awk -v rejected="$P2S_WORK/dependency-plan-rejected" '
        function reject() {print NR "|" $0 > rejected; exit 1}
        /^(Remv|Purg|E:|W:) / {reject()}
        /^Inst / {sub(/ \[[a-z0-9+.:_ -]*\]$/, "")}
        /^[a-z0-9][a-z0-9+.:_-]* is already the newest version \([^()]+\)[.]$/ {next}
        /^Use \047apt(-get)? autoremove\047 to remove (it|them)[.]$/ {next}
        /^Conf / {if ($0 !~ /^Conf [a-z0-9][a-z0-9+.:_-]* \([^()]+ \[[a-z0-9]+\]\)$/) reject(); next}
        /^Inst / {
            if ($0 !~ /^Inst [a-z0-9][a-z0-9+.:_-]*( \[[a-zA-Z0-9.+:~_-]+\])? \([^()]+ \[[a-z0-9]+\]\)$/) reject()
            name=$2; old=$3; if (old ~ /^\[/) gsub(/[\[\]]/,"",old); else old="(none)"
            line=$0; sub(/^[^(]*\(/,"",line); split(line,a," ")
            arch=$NF; gsub(/[\[\]()]/,"",arch); print name "|" old "|" a[1] "|" arch; next
        }
        /^[ \t]*$/ || /^[ \t]+/ || /^(Reading package lists|Building dependency tree|Reading state information|The following|Suggested packages:|Recommended packages:|[0-9]+ upgraded,|NOTE: This is only a simulation[.]|[ \t]*apt-get needs root privileges)/ {next}
        {reject()}' "$log" > "$P2S_WORK/dependency-plan"; then
        p2s_manifest_record apt_plan_rejection "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/dependency-plan-rejected")"
        p2s_fix_block dependency_plan "The APT simulation produced a line the updater could not approve. This APT transaction did not start. See apt_plan_rejection in the detailed log for the line."; return 1
    fi
    while IFS='|' read -r name old candidate plan_arch; do
        if awk -F'|' -v n="$name" '$1==n || $1 ":" $3==n {found=1} END {exit !found}' "$P2S_WORK/apt-approved"; then continue; fi
        new_library=false
        if [ "$old" = '(none)' ]; then new_library=true; fi
        case "$name" in
            php[0-9].[0-9])
                if p2s_package_deb_approve_metapackage "$name" "$old" "$candidate" "$plan_arch"; then continue; fi ;;
        esac
        case "$new_library:${name%:*}" in
            true:php[0-9].[0-9])
                p2s_fix_block dependency_plan "The APT simulation proposes installing an additional PHP metapackage ($name). Review the full package plan manually."; return 1 ;;
            true:*|false:libpcre2-8-0|false:libonig5|false:libargon2-1|false:libxml2|false:libzip4|false:libzip5|false:libsodium23) ;;
            *)
                p2s_fix_block dependency_scope "APT also proposed changing $name from $old to $candidate. This change is outside the approved PHP update plan, so this APT transaction did not start. Review the simulation in the detailed log and run apt-cache policy $name to check the proposed build and its source."
                return 1 ;;
        esac
        if [ -s "$P2S_WORK/holds" ] && awk -v n="${name%:*}" -v a="$plan_arch" '
            $1==n || $1==n ":" a {found=1} END {exit !found}' "$P2S_WORK/holds"; then
            p2s_fix_block held_package "APT holds the required PHP library $name at its installed version. Run apt-mark showhold and confirm why it is held before changing the hold."; return 1
        fi
        if $new_library; then
            arch=$(p2s_command_run 10 dpkg --print-architecture) || return 1
            [ "$plan_arch" = "$arch" ] || { p2s_fix_block dependency_state "The proposed library $name does not match the native Debian architecture."; return 1; }
            installed_source=''
        else
            record=$(p2s_command_run 30 dpkg-query -W '-f=${Status}|${binary:Package}|${Version}|${Architecture}|${source:Package}|${Maintainer}\n' "$name") || return 1
            case "$record" in 'install ok installed|'*) ;; *) p2s_fix_block dependency_state "The proposed dependency $name is not fully installed."; return 1 ;; esac
            record=${record#*|}; target=${record%%|*}; record=${record#*|}; installed_version=${record%%|*}; record=${record#*|}; arch=${record%%|*}; record=${record#*|}; installed_source=${record%%|*}; maintainer=${record#*|}
            [ "${target%:*}" = "${name%:*}" ] && [ "$installed_version" = "$old" ] && [ -n "$installed_source" ] && [ "$arch" = amd64 ] && [ "$plan_arch" = "$arch" ] || {
                p2s_fix_block dependency_state "Installed dependency identity or architecture could not be verified for $name."; return 1;
            }
            p2s_manifest_record dependency_installed "$name|$old|$arch|source=$installed_source|maintainer=$maintainer|historical_download_origin=unverified"
            # Native Debian libraries can name an individual, e.g. Matthew Vernon <matthew@debian.org>.
            # Maintainer text is not origin evidence; retain foreign revision guards and verify native indexes below.
            if [ "$(p2s_package_provider "$name" '' "$old")" != 'unverified source' ]; then
                p2s_fix_block dependency_provider "The installed dependency $name has a third-party package revision; automatic native-library migration requires review."; return 1
            fi
        fi
        case "$name" in *:*) [ "${name##*:}" = "$arch" ] || return 1 ;; esac
        target="${name%:*}:$arch"
        p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "$target" > "$P2S_WORK/dependency-policy" 2> "$P2S_WORK/dependency-query.err" || return 1
        # Sury PHP 7.4 on bullseye requires PCRE2 >=10.38; Debian provides 10.36.
        sury_pcre=false
        if ${P2S_SURY_MIGRATION_ACTIVE:-false} && [ "$suite" = bullseye ] &&
            [ "${name%:*}" = libpcre2-8-0 ] && [ "$installed_source" = pcre2 ] && p2s_package_deb_is_sury "$candidate"; then
            sury_pcre=true
        fi
        if awk -v suite="$suite" -v origin="$origin" -v wanted="$candidate" -v old="$old" -v arch="$arch" -v sury_pcre="$sury_pcre" -v signed_elts="$signed_elts" '
            function official(uri) {
                if (origin=="Debian") return uri ~ /^https?:\/\/((deb|archive)[.]debian[.]org\/debian(-security)?|security[.]debian[.]org(\/debian-security)?)\/?$/
                return uri ~ /^https?:\/\/(([a-z][a-z][.])?archive[.]ubuntu[.]com\/ubuntu|security[.]ubuntu[.]com\/ubuntu)\/?$/
            }
            NR==FNR {
                if ($1 ~ /^-?[0-9]+$/ && $2 ~ /:\/\// && $5=="Packages") {key=$2 "|" $3 "|" $4; native=official($2); uri=$2; component=$3; repo_arch=$4; next}
                if ($1=="release" && key!="") {
                    line="," $2 ","
                    if (native && repo_arch==arch && index(line,",b=" arch ",") && index(line,",o=" origin ",") &&
                        (index(line,",n=" suite ",") || index(line,",n=" suite "-updates,") || index(line,",n=" suite "-security,"))) {
                        native_sources[key]=1; approved[key]=1
                    }
                    if (signed_elts!="" && uri ~ /^https:\/\/deb[.]freexian[.]com\/extended-lts\/?$/ &&
                        repo_arch==arch && index(line,",o=Freexian,") && index(line,",l=Freexian-Extended-LTS,") &&
                        index(line,",c=main,") && index(line,",b=" arch ",")) {
                        for (i=1; i<=split(signed_elts,releases," "); i++) {
                            release=releases[i]
                            if ((release==suite || release==suite "-lts") && component==release "/main" &&
                                index(line,",a=" release ",") && index(line,",n=" release ",")) {
                                native_sources[key]=1; approved[key]=1; elts_sources[key]=1
                            }
                        }
                    }
                    if (sury_pcre=="true" && uri ~ /^https?:\/\/packages[.]sury[.]org\/php\/?$/ && component==suite "/main" && repo_arch=="amd64" &&
                        index(line,",o=deb.sury.org,") && index(line,",n=" suite ",") && index(line,",c=main,") && index(line,",b=amd64,")) approved[key]=1
                    key=""
                }
                next
            }
            $1=="Installed:" {installed=$2; next}
            $1=="Candidate:" {candidate=$2; next}
            $1=="***" {version=$2; next}
            NF==2 && $2 ~ /^-?[0-9]+$/ {version=$1; next}
            version==old && $1 ~ /^-?[0-9]+$/ && NF>=2 {
                if ($2=="/var/lib/dpkg/status") next
                if ($5=="Packages" && native_sources[$2 "|" $3 "|" $4]) native_installed++; else foreign_installed++
            }
            version==wanted && $1 ~ /^-?[0-9]+$/ && NF>=2 {
                if ($2=="/var/lib/dpkg/status") next
                if ($5=="Packages" && approved[$2 "|" $3 "|" $4]) {
                    matches++; if (elts_sources[$2 "|" $3 "|" $4]) elts++
                } else other++
            }
            END {
                if (installed!=old || (old!="(none)" && (native_installed<1 || foreign_installed))) exit 2
                if (!(candidate==wanted && matches>0 && other==0)) exit 1
                if (elts) print "Freexian-ELTS"
            }
        ' "$P2S_WORK/candidate-origins" "$P2S_WORK/dependency-policy" > "$P2S_WORK/dependency-provider"; then
            :
        else
            policy_status=$?
            p2s_manifest_record dependency_package_policy "$name|installed=$old|candidate=$candidate
$(p2s_manifest_redact_repository_urls < "$P2S_WORK/dependency-policy")"
            if [ "$policy_status" -eq 2 ]; then
                p2s_fix_block dependency_provider "The installed version of $name could not be matched exclusively to reviewed native sources for this OS suite. Maintainer names do not establish package origin."
            else
                p2s_fix_block dependency_provider "The normal candidate for $name is not exclusively from reviewed sources for this OS suite. Sury PCRE2 is eligible only during a reviewed Debian 11 Sury publisher switch."
            fi
            return 1
        fi
        if ! $new_library && ! dpkg --compare-versions "$candidate" gt "$old"; then
            p2s_fix_block dependency_downgrade "The proposed dependency $name is not an upgrade."; return 1
        fi
        file="$P2S_WORK/dependency-${name%:*}.metadata"
        for metadata_version in "$old" "$candidate"; do
            [ "$metadata_version" != '(none)' ] || continue
            p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$metadata_version" > "$file" 2> "$P2S_WORK/dependency-query.err" || return 1
            if ! awk -v n="${name%:*}" -v v="$metadata_version" -v a="$arch" -v s="$installed_source" '
                function check() {
                    if (package=="") return
                    if (package!=n || version!=v || arch!=a) bad=1
                    if (s!="" && (source!="" ? source : package)!=s) bad=1
                    if (s=="" && (section !~ /(^|\/)libs$/ || essential_or_protected)) bad=1
                }
                /^Package:/ {check(); package=$2; version=""; arch=""; source=""; section=""; essential_or_protected=0}
                /^Version:/ {version=$2} /^Architecture:/ {arch=$2} /^Source:/ {source=$2} /^Section:/ {section=$2}
                /^(Essential|Protected):/ && tolower($2)!="no" {essential_or_protected=1}
                END {check(); exit (bad || package=="")}' "$file"; then
                p2s_fix_block dependency_identity "Package metadata for $name=$metadata_version does not establish the expected library identity, architecture and source."; return 1
            fi
        done
        printf '%s|%s|%s|%s\n' "${name%:*}" "$candidate" "$arch" "$name" >> "$P2S_WORK/dependency-approved"
        printf '%s|%s|%s\n' "${name%:*}" "$old" "$candidate" >> "$P2S_WORK/dependency-needed"
        if $new_library; then
            printf '%s|%s\n' "${name%:*}" "$arch" >> "$P2S_WORK/dependency-new"
        else
            printf '%s=%s\n' "$target" "$candidate" >> "$P2S_WORK/dependency-arguments"
        fi
        if $sury_pcre; then
            p2s_message_print warn "The proposed Sury migration also upgrades the installed shared PCRE2 library ($name: $old to $candidate). Other applications can use this library; PHP still retains its current version branch."
            p2s_manifest_record dependency_provider "$name|$old|$candidate|Sury|bullseye_migration|source=pcre2|architecture=$arch|authorization=${P2S_PROVIDER_AUTHORIZATION:-explicit_option}"
        elif [ -s "$P2S_WORK/dependency-provider" ]; then
            p2s_manifest_record dependency_provider "$name|$old|$candidate|Freexian-ELTS|signed_suite|source=$installed_source|architecture=$arch"
        fi
    done < "$P2S_WORK/dependency-plan"
    [ -s "$P2S_WORK/dependency-approved" ] || return 0
    # A non-alternative hard dependency must require adding or upgrading the library.
    cat "$P2S_WORK/apt-approved" "$P2S_WORK/dependency-approved" > "$P2S_WORK/dependency-parents"
    while [ -s "$P2S_WORK/dependency-needed" ] && IFS='|' read -r parent candidate arch name; do
        target="$parent:$arch"; [ "$arch" != all ] || target=$parent
        file="$P2S_WORK/dependency-$parent.metadata"
        {
            p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= show "$target=$candidate" > "$file" 2> "$P2S_WORK/dependency-query.err" || return 1
        }
        awk '/^(Pre-Depends|Depends):/ {line=$0; sub(/^[^:]*:[ \t]*/,"",line); active=1; print "," line; next}
            /^[ \t]/ {if (active) print; next} {active=0}' "$file" | tr '\n' ' ' | tr ',' '\n' |
            awk '/^[ \t]*[a-z0-9+.-]+(:[a-z0-9]+)?[ \t]*$/ {print $1 "||"; next}
            index($0,"|")==0 && $0 ~ /^[ \t]*[a-z0-9+.-]+(:[a-z0-9]+)?[ \t]+\((>=|>>|=)[ \t]+[^() \t]+\)[ \t]*$/ {
                gsub(/[()]/,""); print $1 "|" $2 "|" $3}' > "$P2S_WORK/dependency-fields"
        while IFS='|' read -r dep op required; do
            dep=${dep%:any}; dep=${dep%:"$arch"}
            record=$(awk -F'|' -v n="$dep" '$1==n {print $2 "|" $3}' "$P2S_WORK/dependency-needed")
            [ -n "$record" ] || continue
            installed_version=${record%%|*}; candidate_version=${record#*|}
            case "$op" in '>=' ) op=ge ;; '>>') op=gt ;; '=') op=eq ;; '') [ "$installed_version" = '(none)' ] || continue ;; *) continue ;; esac
            if [ -z "$op" ] || { { [ "$installed_version" = '(none)' ] || ! dpkg --compare-versions "$installed_version" "$op" "$required"; } &&
                dpkg --compare-versions "$candidate_version" "$op" "$required"; }; then
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
        p2s_fix_block dependency_necessity "At least one proposed library change lacks a matching unsatisfied PHP dependency. Review the broader dependency changes manually."; return 1
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
            p2s_fix_block held_package "APT holds $name at its installed version. Run apt-mark showhold and confirm why it is held before changing the hold."
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
        p2s_fix_block package_state "dpkg reports package-state or metadata warnings. Run dpkg --audit to identify what needs repair before updating PHP."
        return 1
    fi
    p2s_package_deb_holds_preflight
}

p2s_package_deb_archive_suite() {
    case "$P2S_DISTRO:${P2S_RELEASE%%.*}:$P2S_RELEASE" in
        debian:6:*) printf 'squeeze\n' ;; debian:7:*) printf 'wheezy\n' ;; debian:8:*) printf 'jessie\n' ;;
        debian:9:*) printf 'stretch\n' ;; debian:10:*) printf 'buster\n' ;; debian:11:*) printf 'bullseye\n' ;;
        ubuntu:*:12.04) printf 'precise\n' ;; ubuntu:*:14.10) printf 'utopic\n' ;; ubuntu:*:15.04) printf 'vivid\n' ;;
        ubuntu:*:15.10) printf 'wily\n' ;; ubuntu:*:16.10) printf 'yakkety\n' ;; ubuntu:*:17.04) printf 'zesty\n' ;;
        ubuntu:*:17.10) printf 'artful\n' ;; ubuntu:*:18.10) printf 'cosmic\n' ;; ubuntu:*:19.04) printf 'disco\n' ;;
        ubuntu:*:19.10) printf 'eoan\n' ;; ubuntu:*:20.10) printf 'groovy\n' ;; ubuntu:*:21.04) printf 'hirsute\n' ;;
        ubuntu:*:21.10) printf 'impish\n' ;; ubuntu:*:22.10) printf 'kinetic\n' ;; ubuntu:*:23.04) printf 'lunar\n' ;;
        ubuntu:*:23.10) printf 'mantic\n' ;; ubuntu:*:24.10) printf 'oracular\n' ;;
        *) return 1 ;;
    esac
}

# Match repository-level metadata failures. InRelease alone can fall back to Release.
p2s_package_deb_archive_failures() {
    awk '
        BEGIN {quote=sprintf("%c",39)}
        function emit(uri, suite) {sub(/\/$/, "", uri); print uri "|" suite}
        /^(E|W): The repository / && /(does not have|no longer has) a Release file[.]?$/ &&
            substr($4,1,1)==quote && $6=="Release" quote {emit(substr($4,2),$5)}
        $1=="E:" && $2=="Failed" && $3=="to" && $4=="fetch" && $6=="404" && $7=="Not" && $8=="Found" {
            uri=$5
            if (uri !~ /\/dists\/[a-z0-9\/-]+\/Release$/) next
            sub(/\/dists\/.*/,"",uri)
            suite=substr($5,length(uri)+8); sub(/\/Release$/,"",suite)
            emit(uri,suite)
        }
        /^Err:[0-9]+ / && $4=="Release" {uri=$2; suite=$3; next}
        {if (uri!="" && $1=="404" && $2=="Not" && $3=="Found") emit(uri,suite); uri=""}
    ' "$1"
}

# Replace only the URI token. Even within a Deb822 stanza, keep comments, options,
# signing key configuration, architectures, types, suites and components intact.
p2s_package_deb_archive_render() {
    local file=$1 suite=$2 scheme=$3 failures=$4 changes=$5
    awk -v base="$suite" -v distro="$P2S_DISTRO" -v scheme="$scheme" -v changes="$changes" '
        FILENAME==ARGV[1] {failed[$0]=1; next}
        function replacement(uri, suite,    normalized, host, target, prefix) {
            normalized=uri; sub(/\/$/,"",normalized)
            if (!(normalized "|" suite in failed)) return ""
            host=normalized; sub(/^https?:\/\//,"",host)
            if (host==normalized) return ""
            if (distro=="debian") {
                if (host ~ /^(deb|ftp([.][a-z][a-z])?)[.]debian[.]org\/debian$/) {
                    if (suite==base || (base=="squeeze" && suite=="squeeze-lts") ||
                        (suite==base "-updates" && (base=="buster" || base=="bullseye")) ||
                        (suite==base "-proposed-updates" && base !~ /^(wheezy|jessie)$/) ||
                        ((suite==base "-backports" || suite==base "-backports-sloppy") && base!="squeeze"))
                        target="archive.debian.org/debian"
                    if (base=="squeeze" && suite=="squeeze-backports") target="archive.debian.org/debian-backports"
                } else if (host ~ /^(security|deb)[.]debian[.]org\/debian-security$/ ||
                    (host=="security.debian.org" && base!="bullseye")) {
                    if ((base=="bullseye" && suite=="bullseye-security") || (base!="bullseye" && suite==base "/updates"))
                        target="archive.debian.org/debian-security"
                } else if (host=="backports.debian.org/debian-backports" && base=="squeeze" && suite=="squeeze-backports")
                    target="archive.debian.org/debian-backports"
            } else if (distro=="ubuntu" && host ~ /^(([a-z][a-z][.])?archive|security)[.]ubuntu[.]com\/ubuntu$/ &&
                (suite==base || suite==base "-updates" || suite==base "-security" ||
                    suite==base "-backports" || suite==base "-proposed")) target="old-releases.ubuntu.com/ubuntu"
            if (target=="") return ""
            # Older APT may lack HTTPS transport. Never downgrade an existing HTTPS entry.
            prefix=(uri ~ /^https:/ ? "https" : scheme)
            return prefix "://" target (uri ~ /\/$/ ? "/" : "")
        }
        function log_change(uri, suite, target) {print uri "|" suite "|" target >> changes}
        function stanza(    i, count, ids, newuri, target, start) {
            if (!invalid && fields["types"] ~ /^(deb|deb-src)( (deb|deb-src))?$/ &&
                (fields["enabled"]=="" || tolower(fields["enabled"])=="yes") &&
                fields["uris"] ~ /^[^ \t]+$/ && !folded_uri && fields["components"]!="") {
                count=split(fields["suites"],ids," ")
                for (i=1; i<=count; i++) {
                    target=replacement(fields["uris"],ids[i])
                    if (target=="" || (i>1 && newuri!=target)) {newuri=""; break}
                    newuri=target
                }
                if (newuri!="") {
                    start=index(lines[uri_line],fields["uris"])
                    lines[uri_line]=substr(lines[uri_line],1,start-1) newuri substr(lines[uri_line],start+length(fields["uris"]))
                    for (i=1; i<=count; i++) log_change(fields["uris"],ids[i],newuri)
                }
            }
            for (i=1; i<=line_count; i++) {print lines[i]; delete lines[i]}
            for (key in fields) delete fields[key]
            line_count=uri_line=folded_uri=invalid=0
            key=""
        }
        FILENAME ~ /[.]sources$/ {
            if ($0 ~ /^[ \t\r]*$/) {stanza(); print; next}
            lines[++line_count]=$0
            if ($0 ~ /^[ \t]*#/) next
            value=$0
            if ($0 ~ /^[ \t]/) {
                if (key=="uris") folded_uri=1
            } else {
                if ($0 !~ /^[A-Za-z][A-Za-z0-9-]*:/) {invalid=1; next}
                key=tolower($0); sub(/:.*/,"", key); sub(/^[^:]*:/,"",value)
                if (key in fields) invalid=1
                if (key=="uris") uri_line=line_count
            }
            sub(/^[ \t]+/,"",value); sub(/[ \t\r]+$/,"",value); gsub(/[ \t]+/," ",value)
            fields[key]=(fields[key]=="" ? value : fields[key] " " value)
            next
        }
        {
            if (!match($0,/^[ \t]*(deb|deb-src)[ \t]+(\[[^]]*\][ \t]+)?/)) {print; next}
            first=RLENGTH
            rest=substr($0,first+1); sub(/#.*/,"",rest); sub(/\r$/,"",rest)
            count=split(rest,fields_list,/[ \t]+/)
            uri=fields_list[1]; pocket=fields_list[2]
            target=(count>=3 && fields_list[3]!="" ? replacement(uri,pocket) : "")
            if (target=="") print
            else {print substr($0,1,first) target substr($0,first+length(uri)+1); log_change(uri,pocket,target)}
        }
        END {if (FILENAME ~ /[.]sources$/) stanza()}
    ' "$failures" "$file"
}

# P2S-MUTATION: Replace enabled same-release stock URI tokens, then keep the
# rewrite only after a complete refresh with the existing authentication policy.
p2s_package_deb_repair_archived_sources() (
    local log=$1 suite scheme=http file staged backup pending='' committed=false seen=0
    local before after pocket old_uri new_uri i
    local -a sources replacements backups
    sources=(); replacements=(); backups=()
    ${P2S_NOVEMBER:-false} && [ "${P2S_MODE:-check}" = fix ] || return 1
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 1 ;; esac
    suite=$(p2s_package_deb_archive_suite) || return 1
    p2s_package_deb_archive_failures "$log" > "$P2S_WORK/archive-failures" || return 1
    [ -s "$P2S_WORK/archive-failures" ] || return 1
    if [ -x /usr/lib/apt/methods/https ]; then scheme=https; fi
    for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$file" ] || continue
        case "${file##*/}" in *[!a-zA-Z0-9_.-]*) continue ;; esac
        staged="$P2S_WORK/archive-source-$seen"
        before="$staged.before"
        after="$staged.after"
        cp -p -- "$file" "$before" || return 1
        : > "$staged.changes" || return 1
        p2s_package_deb_archive_render "$file" "$suite" "$scheme" "$P2S_WORK/archive-failures" "$staged.changes" > "$after" || return 1
        [ -s "$staged.changes" ] || continue
        if [ -L "$file" ] || [ "$(stat -c '%h' -- "$file")" != 1 ]; then
            p2s_manifest_record repository_archive_repair "skipped|file=$file|reason=source_is_linked"
            return 1
        fi
        if [ -n "$(tail -c 1 -- "$before")" ]; then truncate -s -1 -- "$after" || return 1; fi
        sources[$seen]=$file
        replacements[$seen]=$staged
        seen=$((seen+1))
    done
    [ "$seen" -gt 0 ] || return 1
    p2s_package_deb_sury_trust_preflight || return 1
    trap '
        [ -z "$pending" ] || rm -f -- "$pending"
        for ((i=${#backups[@]}-1; i>=0; i--)); do
            file=${sources[i]}; staged=${replacements[i]}; backup=${backups[i]}
            if $committed || { [ ! -L "$file" ] && cmp -s -- "$backup" "$file"; }; then
                rm -f -- "$backup"
            elif [ ! -L "$file" ] && cmp -s -- "$staged.after" "$file" && mv -fT -- "$backup" "$file"; then
                p2s_manifest_record repository_archive_repair "restored|file=$file"
            else
                p2s_message_print warn "Could not restore $file safely. Its original is saved at $backup."
                p2s_manifest_record repository_archive_repair "restore_required|file=$file|backup=$backup"
            fi
        done
    ' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    for ((i=0; i<seen; i++)); do
        file=${sources[i]}; staged=${replacements[i]}
        backup=$(mktemp "${file%/*}/.dephp2shell-archive-original.XXXXXX") || return 1
        if [ -L "$file" ] || ! cmp -s -- "$staged.before" "$file" || ! cp --preserve=all -- "$file" "$backup"; then
            rm -f -- "$backup"
            p2s_manifest_record repository_archive_repair "skipped|file=$file|reason=source_changed_or_backup_failed"
            return 1
        fi
        backups[$i]=$backup
        pending=$(mktemp "${file%/*}/.dephp2shell-archive-staged.XXXXXX") || return 1
        if ! cp --preserve=all -- "$backup" "$pending" || ! cat "$staged.after" > "$pending" ||
            [ -L "$file" ] || ! cmp -s -- "$backup" "$file" || ! mv -fT -- "$pending" "$file"; then
            p2s_manifest_record repository_archive_repair "skipped|file=$file|reason=source_changed_or_publish_failed"
            return 1
        fi
        pending=''
        while IFS='|' read -r old_uri pocket new_uri; do
            p2s_manifest_record repository_archive_repair "retrying|file=$file|suite=$pocket|from=$old_uri|to=$new_uri"
            p2s_message_print info "Moved $pocket from $old_uri to $new_uri in $file. Checking all APT sources."
        done < "$staged.changes"
    done
    if ! p2s_package_deb_refresh_indexes archive-retry; then
        p2s_message_print warn "APT archive repair did not yield a complete authenticated refresh. Restoring the original source files."
        return 1
    fi
    committed=true
    p2s_manifest_record repository_archive_repair "retained|files=$seen|authenticated_refresh=complete"
)

p2s_package_deb_refresh_indexes() {
    local log="$P2S_WORK/apt.log" status=0 hook scope
    local apt_update_options=()
    P2S_REPOSITORY_REFRESH=failed
    if [ "${P2S_MODE:-fix}" = check ]; then
        # APT can run locally configured commands on update, even without a package transaction.
        for scope in '' 'Binary::apt-get::'; do
            for hook in Pre-Invoke Post-Invoke Post-Invoke-Success; do
                printf '#clear %sAPT::Update::%s;\n' "$scope" "$hook"
            done
        done > "$P2S_WORK/apt-check.conf" || {
            p2s_fix_block repositories "Could not write the APT check configuration. Review free space and permissions in the temporary directory."; return 1;
        }
        apt_update_options=(-c "$P2S_WORK/apt-check.conf")
    fi
    p2s_message_print info "Running apt-get update to refresh package lists."
    # Contents maps filenames to packages for apt-file searches; PHP updates need package indexes, not those large maps.
    # These command-only defaults preserve source files and trust checks. Explicit per-source Targets can override them.
    p2s_manifest_record apt_refresh_scope 'optional_Contents_defaults=disabled|translations=disabled|required_package_indexes_and_signature_checks=retained|persistent_configuration=unchanged'
    # APT retries an acquisition once. The refresh deadline and signature checks still apply.
    # P2S-MUTATION: Refreshes on-disk APT metadata; this does not install packages.
    p2s_command_run 300 apt-get "${apt_update_options[@]}" -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowWeakRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
        -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::Languages=none \
        -o Acquire::IndexTargets::deb::Contents-deb::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb::Contents-deb-legacy::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb::Contents-udeb::DefaultEnabled=false \
        -o Acquire::IndexTargets::deb-src::Contents-dsc::DefaultEnabled=false update > "$log" 2>&1 || status=$?
    p2s_manifest_record repository_refresh "apt-get update|exit=$status"
    if [ "${1:-}" != archive-retry ] && ${P2S_NOVEMBER:-false} && [ "${P2S_MODE:-check}" = fix ] && [ "$status" -ne 124 ] &&
        { [ "$status" -ne 0 ] || grep -Ei '^(E:|W:.*(Failed to fetch|Some index files|GPG error|not signed))' "$log" >/dev/null; }; then
        # The retry reuses apt.log. Keep the first failure intact for diagnostics.
        if cp -- "$log" "$P2S_WORK/apt-original-refresh.log"; then
            if p2s_package_deb_repair_archived_sources "$P2S_WORK/apt-original-refresh.log"; then
                P2S_REPOSITORY_REFRESH=refreshed
                return 0
            fi
            log="$P2S_WORK/apt-original-refresh.log"
        fi
    fi
    case "$status" in
        0) ;;
        124) p2s_package_refresh_failure_report "$log" "apt-get update timed out after 300 seconds. Check repository connectivity and retry."; return 1 ;;
        *) p2s_package_refresh_failure_report "$log" "apt-get update failed (exit $status). Review the repository error in the package-manager log, then retry."; return 1 ;;
    esac
    if grep -Ei '^(E:|W:.*(Failed to fetch|Some index files|GPG error|not signed))' "$log" >/dev/null; then
        p2s_package_refresh_failure_report "$log" "apt-get update left some package lists incomplete. Fix the reported repository errors and rerun the check."; return 1
    fi
    p2s_package_log_report "$log"
    P2S_REPOSITORY_REFRESH=refreshed
}

p2s_package_deb_load_candidate_origins() {
    if ! p2s_command_exists apt-cache || ! p2s_command_exists dpkg ||
        ! p2s_command_run 30 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy > "$P2S_WORK/candidate-origins" 2> "$P2S_WORK/candidate-origins.err"; then
        if [ -s "$P2S_WORK/candidate-origins.err" ]; then p2s_manifest_record apt_policy_error "$(p2s_manifest_redact_repository_urls < "$P2S_WORK/candidate-origins.err")"; fi
        p2s_fix_block candidate_provider "APT candidate origins could not be inspected; refusing an unchecked PHP package source change."
        return 1
    fi
}

# P2S-MUTATION: APT update path; refreshes metadata and upgrades PHP and verified required native libraries.
p2s_package_deb_update() {
    local log="$P2S_WORK/apt.log" name version arch vendor changed sury=false has_sury=false target source branch
    local P2S_SURY_MIGRATION_ACTIVE=false P2S_DEB_NATIVE_PREFERENCE=false
    local P2S_FREEXIAN_ACTIVE=false P2S_FREEXIAN_SIGNED_SUITES=''
    local P2S_BACKPORTS_ACTIVE=false P2S_STACKX_ACTIVE=false
    local P2S_STACKX_KEYRING='' P2S_STACKX_PREVIEW_ONLY=false P2S_STACKX_REPOSITORY_CREATED=false
    local packages cache_options install_options dependency_options status freexian_branch='' backports_suite native_archive_lookup=false
    local stackx_suite stackx_uri stackx_branches requested
    local P2S_PROVIDER_AUTHORIZATION=explicit_option
    packages=(); cache_options=(); install_options=()
    dependency_options=(--no-install-recommends -o APT::Install-Suggests=false)
    : > "$P2S_WORK/backports-approved-sha256" || return 1
    : > "$P2S_WORK/dependency-new" || return 1
    if ${P2S_APT_NOVEMBER_POLICY:-false}; then
        P2S_PROVIDER_AUTHORIZATION=configured_source_policy
        if ${P2S_SURY_REPOSITORY_CREATED:-false} || ${P2S_BACKPORTS_REPOSITORY_CREATED:-false}; then
            P2S_PROVIDER_AUTHORIZATION=explicit_source_addition
        fi
    fi
    P2S_FREEXIAN_SELECTED=false
    if [ "${1:-}" = stackx ]; then
        ${P2S_ALLOW_STACKX:-false} && p2s_stackx_scope || return 1
        if [ "$(p2s_command_run 10 dpkg --print-architecture)" != amd64 ]; then
            p2s_fix_block candidate_provider "StackX requires amd64 as the host's native Debian package architecture."
            return 1
        fi
        P2S_STACKX_ACTIVE=true
        stackx_suite=$(p2s_stackx_suite) || return 1
        stackx_uri="https://mirrors.scalarx.net/stackx-php/$stackx_suite/repo"
        stackx_branches=" ${P2S_PHP_SOURCE_BRANCHES//,/ } "
        : > "$P2S_WORK/stackx-selected-branches" || return 1
    fi
    if [ "${1:-}" = backports ]; then
        P2S_BACKPORTS_ACTIVE=true
        local P2S_ALLOW_FREEXIAN=false P2S_ALLOW_SURY_MIGRATION=false
        backports_suite=$(p2s_backports_suite) && p2s_backports_select_branches "$backports_suite" || {
            p2s_fix_block candidate_fix "No vulnerable installed PHP branch matches the reviewed Debian PHP Backports packages for this OS and architecture."; return 1;
        }
    fi
    if ${P2S_ALLOW_FREEXIAN:-false} && p2s_freexian_native_scope; then
        freexian_branch=$(p2s_freexian_suite) || return 1
        freexian_branch=${freexian_branch#*|}
        P2S_FREEXIAN_ACTIVE=true
    fi
    : > "$P2S_WORK/dependency-approved"
    if [ "${P2S_MODE:-fix}" = check ]; then cache_options=(-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=); fi
    if ! $P2S_FREEXIAN_ACTIVE && ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        p2s_disruptive_sury_validate_equivalents || return 1
        P2S_SURY_MIGRATION_ACTIVE=true
        p2s_message_print warn "Checking the Sury/ondrej fallback for branches without a verified fix from their current publisher. Only equivalent packages with matching PHP branches, architecture and extension APIs are eligible."
        p2s_manifest_record provider_migration "Sury|authorization=$P2S_PROVIDER_AUTHORIZATION|same_names_branches_architectures_and_extension_API|required_fixed_candidates|selectors_frozen"
    fi
    while IFS='|' read -r name version arch vendor; do
        if p2s_package_deb_is_sury "$version"; then has_sury=true; fi
    done < "$P2S_WORK/packages"
    : > "$P2S_WORK/apt-selected"
    while IFS='|' read -r name version arch vendor; do
        case "${P2S_PANEL:-}:$name" in cpanel:cpanel-php*|cpanel:sw-engine*) continue ;; esac
        if $P2S_STACKX_ACTIVE; then
            branch=$(p2s_backports_source "$name") || continue
            case "$stackx_branches" in *" $branch "*) ;; *) continue ;; esac
            if ! awk -F'|' -v n="$name" -v v="$version" -v a="$arch" -v s="$branch" \
                '$1==n && $2==v && $3==a {if ($4==s && $5==v) match_source=1; else other=1} END {exit (!match_source || other)}' "$P2S_WORK/deb-source-records"; then
                if ! p2s_package_is_engine "$name"; then continue; fi
                p2s_fix_block candidate_provider "The installed source package of $name could not be matched to $branch for StackX."; return 1
            fi
            case "$arch:$(p2s_package_provider "$name" "$vendor" "$version")" in
                amd64:Debian|all:Debian|amd64:Sury/*|all:Sury/*|amd64:StackX*|all:StackX*) ;;
                *) p2s_fix_block candidate_provider "The installed publisher or architecture of $name is outside the StackX fallback scope."; return 1 ;;
            esac
            if p2s_package_is_engine "$name"; then
                if [ "$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$branch" "$version")" = N ]; then
                    p2s_fix_block candidate_fix "$name already has a verified fix. Keep the current publisher for $branch."; return 1
                fi
                if [ "$arch" = amd64 ]; then printf '%s\n' "$branch" >> "$P2S_WORK/stackx-selected-branches" || return 1; fi
            fi
            packages[${#packages[@]}]="$name"
            printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/apt-selected"
            continue
        fi
        if $P2S_BACKPORTS_ACTIVE && [ "$name" = php-common ]; then
            p2s_backports_package_build "$backports_suite" "$name" "$arch" "$version" >/dev/null || continue
            awk -F'|' -v v="$version" '$1=="php-common" && $2==v && $3=="all" && $4=="php-defaults" &&
                ($5==v || $5=="60ubuntu1") {yes=1} END {exit !yes}' "$P2S_WORK/deb-source-records" || return 1
        elif $P2S_BACKPORTS_ACTIVE; then
            source=$(p2s_backports_source "$name") && grep -Fxq -- "$source" "$P2S_WORK/backports-branches" || continue
            if ! awk -F'|' -v n="$name" -v v="$version" -v a="$arch" -v s="$source" \
                '$1==n && $2==v && $3==a {if ($4==s && $5==v) match_source=1; else other=1} END {exit (!match_source || other)}' "$P2S_WORK/deb-source-records"; then
                if ! p2s_package_is_engine "$name"; then continue; fi
                p2s_fix_block candidate_provider "The installed source package of $name could not be matched to $source."; return 1;
            fi
        fi
        if $P2S_FREEXIAN_ACTIVE; then
            case "${name%:*}" in "$freexian_branch"-*|libapache2-mod-"$freexian_branch") ;; *) continue ;; esac
            if ! awk -F'|' -v n="$name" -v v="$version" -v a="$arch" -v s="$freexian_branch" \
                '$1==n && $2==v && $3==a && $4==s && $5==v {found=1} END {exit !found}' "$P2S_WORK/deb-source-records" ||
                [ "$(p2s_package_provider "$name" "$vendor" "$version")" != Debian ]; then
                p2s_fix_block candidate_provider "The installed source package of $name does not match the native Debian $freexian_branch build."
                return 1
            fi
        fi
        if ! $P2S_BACKPORTS_ACTIVE && { $has_sury || $P2S_SURY_MIGRATION_ACTIVE || [ -n "${P2S_APT_PHASE_BRANCHES:-}" ]; }; then
            # Freeze selectors: updating php-cli/php-xml can select a different already-installed branch.
            case "${name%:*}" in php[0-9].[0-9]-*|libapache2-mod-php[0-9].[0-9]|php5-*|libapache2-mod-php5|libapache2-mod-php5filter|php-common|php-pear) ;;
                *) p2s_manifest_record source_preservation "$name|selector_or_unreviewed_package_not_selected"; continue ;;
            esac
            case "${name%:*}" in php-common|php-pear)
                # New php-common revisions can Break older extension selectors; do not request a helper upgrade.
                continue ;;
            esac
            if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ] || { $P2S_SURY_MIGRATION_ACTIVE && ! p2s_package_deb_is_sury "$version"; }; then
                source=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4]++ {print $4}' "$P2S_WORK/deb-source-records")
                branch=$(p2s_backports_source "$name") || continue
                [ "$source" = "$branch" ] || continue
                if [ -n "${P2S_APT_PHASE_BRANCHES:-}" ] && ! grep -Fxq -- "$branch" "$P2S_APT_PHASE_BRANCHES"; then continue; fi
            fi
        fi
        # Generic selectors do not contain a PHP engine and can have no candidate on otherwise patchable hosts.
        case "${name%:*}" in php|php[0-9]|php[0-9].[0-9]|php-cli|php-cgi|php-fpm|php-phpdbg|libapache2-mod-php) continue ;; esac
        packages[${#packages[@]}]="$name"
        printf '%s|%s|%s|%s\n' "$name" "$version" "$arch" "$vendor" >> "$P2S_WORK/apt-selected"
    done < "$P2S_WORK/packages"
    if $P2S_STACKX_ACTIVE; then
        while IFS= read -r requested; do
            if ! grep -Fxq -- "$requested" "$P2S_WORK/stackx-selected-branches" ||
                ! p2s_stackx_published_build "$stackx_suite" "$requested" >/dev/null; then
                p2s_fix_block candidate_fix "StackX cannot update $requested. Select an installed, unresolved amd64 PHP branch published for Debian $stackx_suite."; return 1
            fi
        done < <(printf '%s\n' "$P2S_PHP_SOURCE_BRANCHES" | tr ',' '\n')
    fi
    [ "${#packages[@]}" -gt 0 ] || return 0
    p2s_package_deb_preflight || return 1
    if $has_sury || $P2S_SURY_MIGRATION_ACTIVE || $P2S_FREEXIAN_ACTIVE || $P2S_BACKPORTS_ACTIVE || $P2S_STACKX_ACTIVE; then
        p2s_package_deb_sury_trust_preflight || return 1
        p2s_manifest_record source_preservation "APT|per_package_provider_checks|selectors_frozen|Sury_migration=$P2S_SURY_MIGRATION_ACTIVE"
    fi
    if [ "${P2S_MODE:-fix}" = fix ] && $P2S_SURY_MIGRATION_ACTIVE && ${P2S_ALLOW_SURY_REPOSITORY:-false}; then
        p2s_disruptive_sury_add_repository || return 1
    fi
    if $P2S_STACKX_ACTIVE; then
        p2s_stackx_prepare_source "$stackx_suite" "$stackx_uri" || return 1
        if $P2S_STACKX_PREVIEW_ONLY; then
            p2s_manifest_record stackx_preflight 'source_setup_required|signed_candidates_available|simulation_after_source_setup'
            return 0
        fi
    fi
    if [ "${P2S_MODE:-fix}" = fix ]; then
        if $P2S_STACKX_REPOSITORY_CREATED || ! ${P2S_APT_INDEXES_REFRESHED:-false} ||
            { ${P2S_ALLOW_SURY_REPOSITORY:-false} && ${P2S_SURY_REPOSITORY_CREATED:-false}; }; then
            p2s_package_deb_refresh_indexes || return 1
        fi
    elif [ "${P2S_REPOSITORY_REFRESH:-not_refreshed}" != refreshed ]; then
        p2s_manifest_record apt_refresh_scope 'cached_plan_only|repositories_not_refreshed|no_packages_or_services_changed'
    fi
    if $P2S_FREEXIAN_ACTIVE && { [ "$P2S_REPOSITORY_REFRESH" != refreshed ] || ! p2s_freexian_signed_indexes; }; then
        p2s_fix_block source_authentication "Could not verify a freshly refreshed Freexian Extended LTS index for this Debian release with the published signing key. Review the configured feed and installed Freexian keyring."
        return 1
    fi
    if $P2S_BACKPORTS_ACTIVE && { [ "$P2S_REPOSITORY_REFRESH" != refreshed ] || ! p2s_backports_signed_index "$backports_suite"; }; then
        p2s_fix_block source_authentication "Could not verify the refreshed Debian PHP Backports index and published signing key for $backports_suite. Configure the signed source manually and rerun the check."
        return 1
    fi
    if $P2S_BACKPORTS_ACTIVE; then p2s_backports_verify_indexes "$backports_suite" || return 1; fi
    if $P2S_STACKX_ACTIVE && { [ "$P2S_REPOSITORY_REFRESH" != refreshed ] || ! p2s_stackx_verify_index "$stackx_suite"; }; then
        p2s_fix_block source_authentication "Could not verify the refreshed StackX package index for Debian $stackx_suite. Check access to the signed source and its dedicated keyring."
        return 1
    fi
    p2s_package_deb_load_candidate_origins || return 1
    if $P2S_STACKX_REPOSITORY_CREATED && ! p2s_stackx_preferences_verified "$stackx_uri"; then
        p2s_fix_block candidate_provider "APT did not exclude StackX packages outside the selected PHP branches. Review APT preferences before retrying."
        return 1
    fi
    if $P2S_SURY_MIGRATION_ACTIVE && ${P2S_SURY_PREFERENCES_CREATED:-false} &&
        ! awk '
            $1 ~ /^-?[0-9]+$/ && $5=="Packages" {priority=$1; next}
            $1=="release" && ("," $2 ",") ~ /,o=(deb[.]sury[.]org|LP-PPA-ondrej-php),/ {
                scoped=1; if (priority>=0) unscoped=1
            }
            END {exit (!scoped || unscoped)}' "$P2S_WORK/candidate-origins"; then
        p2s_fix_block candidate_provider "APT did not apply the new PHP repository's default exclusion. Review APT preferences and the default release before adding this source."; return 1
    fi
    packages=()
    : > "$P2S_WORK/apt-approved"
    : > "$P2S_WORK/migration-api-branches"
    while IFS='|' read -r name version arch vendor; do
        sury=false
        if p2s_package_deb_is_sury "$version"; then sury=true; fi
        if ${P2S_APT_NATIVE_FALLBACK:-false}; then
            if ! $sury; then return 1; fi
            sury=false
            case "$P2S_DISTRO" in debian) vendor=Debian ;; ubuntu) vendor=Ubuntu ;; esac
        elif ${P2S_APT_NOVEMBER_POLICY:-false} && ${P2S_APT_CURRENT_PROVIDER_ONLY:-false} && ! $sury; then
            case "$(p2s_package_provider "$name" "$vendor" "$version")" in
                Debian|Ubuntu) ;;
                *) p2s_fix_block candidate_provider "The installed publisher of $name ($version) needs a reviewed package update route."; return 1 ;;
            esac
        fi
        status=0
        p2s_package_deb_candidate "$name" "$version" "$arch" "$sury" "$vendor" || status=$?
        if [ "$status" -ne 0 ]; then
            if [ "$status" -eq 2 ]; then
                p2s_fix_block candidate_fix "APT found no eligible fixed build of $name from its current publisher (installed build $version). Check the publisher’s security advisory and package sources for a fixed build on this release."
            fi
            return 1
        fi
        if [ "$P2S_DEB_CANDIDATE" = "$version" ]; then
            p2s_manifest_record candidate_unchanged "$name|$version|not_requested_for_upgrade"
            continue
        fi
        target=${name%:*}; [ "$arch" = all ] || target="$target:$arch"
        packages[${#packages[@]}]="$target=$P2S_DEB_CANDIDATE"
        printf '%s|%s|%s|%s\n' "${name%:*}" "$P2S_DEB_CANDIDATE" "$arch" "$name" >> "$P2S_WORK/apt-approved"
    done < "$P2S_WORK/apt-selected"
    if $P2S_SURY_MIGRATION_ACTIVE || $P2S_FREEXIAN_ACTIVE || $P2S_BACKPORTS_ACTIVE || $P2S_STACKX_ACTIVE || ${P2S_APT_NATIVE_FALLBACK:-false}; then
        while IFS='|' read -r name version arch vendor; do
            if ! p2s_package_is_engine "$name"; then continue; fi
            branch=${name#libapache2-mod-}; branch=${branch%%-*}
            if $P2S_BACKPORTS_ACTIVE || $P2S_STACKX_ACTIVE; then branch=$(p2s_backports_source "$name") || return 1; fi
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
    if $has_sury || $P2S_SURY_MIGRATION_ACTIVE || $P2S_FREEXIAN_ACTIVE || $P2S_BACKPORTS_ACTIVE || $P2S_STACKX_ACTIVE ||
        $P2S_DEB_NATIVE_PREFERENCE || [ -n "${P2S_APT_PHASE_BRANCHES:-}" ]; then
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
    if ! p2s_command_run 120 apt-get -s "${cache_options[@]}" "${dependency_options[@]}" --no-remove install --only-upgrade "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"
        p2s_package_deb_policy_collect "${packages[@]}"
        p2s_fix_block transaction_plan "The APT simulation failed, so this APT transaction did not start. Review the APT error in the detailed log for package conflicts, pins, holds or missing candidates."
        return 1
    fi
    p2s_package_log_report "$log"
    if awk -F'|' '
        FILENAME==ARGV[1] {approved[$1]=1; approved[$1 ":" $3]=1; next}
        /^Inst / {split($0,a," "); if (!(a[2] in approved)) extra=1}
        END {exit !extra}' "$P2S_WORK/apt-approved" "$log"; then
        p2s_package_deb_dependency_approve_plan "$log" || return 1
        if [ -s "$P2S_WORK/dependency-new" ]; then
            p2s_package_deb_sury_trust_preflight || return 1
        fi
        if [ -s "$P2S_WORK/dependency-arguments" ] || [ -s "$P2S_WORK/dependency-new" ]; then
            while IFS= read -r target; do packages[${#packages[@]}]="$target"; done < "$P2S_WORK/dependency-arguments"
            if ! p2s_command_run 120 apt-get -s "${cache_options[@]}" "${dependency_options[@]}" --no-remove install --only-upgrade "${packages[@]}" > "$log" 2>&1; then
                p2s_package_log_report "$log"; p2s_fix_block dependency_plan "The exact pinned PHP dependency simulation failed; no packages were installed."; return 1
            fi
            p2s_package_log_report "$log"
        fi
    fi
    if { [ -s "$P2S_WORK/dependency-approved" ] || $P2S_STACKX_ACTIVE; } && ! awk -F'|' '
        FILENAME==ARGV[1] {v[$1]=$2; v[$1 ":" $3]=$2; arch[$1]=$3; arch[$1 ":" $3]=$3; next}
        FILENAME==ARGV[2] {key=$1 ":" $2; additions[$1]=additions[key]=key; pending[key]=1; next}
        /^Inst / {sub(/ \[[a-z0-9+.:_ -]*\]$/, "")}
        /^(Inst|Conf) / {
            split($0,a," ")
            if (a[1]=="Inst") {
                if ($0 !~ /^Inst [a-z0-9][a-z0-9+.:_-]*( \[[a-zA-Z0-9.+:~_-]+\])? \([^()]+ \[[a-z0-9]+\]\)$/ ||
                    ((a[2] in additions) == (a[3] ~ /^\[/))) {bad=1; next}
                if (a[2] in additions) delete pending[additions[a[2]]]
            }
            if ($0 ~ /^Conf / && $0 !~ /^Conf [a-z0-9][a-z0-9+.:_-]* \([^()]+ \[[a-z0-9]+\]\)$/) {bad=1; next}
            line=$0; sub(/^[^(]*\(/,"",line); split(line,b," ")
            count=split($0,parts," "); observed=parts[count]; gsub(/[\[\]()]/,"",observed)
            if (!(a[2] in v) || b[1]!=v[a[2]] || observed!=arch[a[2]]) bad=1
            next
        }
        /^[a-z0-9][a-z0-9+.:_-]* is already the newest version \([^()]+\)[.]$/ {next}
        /^Use \047apt(-get)? autoremove\047 to remove (it|them)[.]$/ {next}
        /^[ \t]*$/ || /^[ \t]+/ || /^(Reading package lists|Building dependency tree|Reading state information|The following|Suggested packages:|Recommended packages:|[0-9]+ upgraded,|NOTE: This is only a simulation[.]|[ \t]*apt-get needs root privileges)/ {next}
        {bad=1}
        END {for (key in pending) bad=1; exit bad}' "$P2S_WORK/apt-approved" "$P2S_WORK/dependency-new" "$log"; then
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
        if [ "${P2S_REPOSITORY_REFRESH:-not_refreshed}" = refreshed ]; then
            p2s_manifest_record cached_update_plan 'approved_after_refresh|fresh_fix_preflight_and_refresh_required'
        else
            p2s_manifest_record cached_update_plan 'approved_with_cached_metadata_only|fresh_fix_preflight_and_refresh_required'
        fi
        return 0
    fi
    if [ "${P2S_MODE:-fix}" != fix ]; then
        p2s_fix_block privileges 'A package installation requires explicit fix mode.'; return 1
    fi
    if $P2S_BACKPORTS_ACTIVE || $P2S_STACKX_ACTIVE || [ -s "$P2S_WORK/dependency-new" ]; then
        if ! $P2S_BACKPORTS_ACTIVE && ! $P2S_STACKX_ACTIVE; then native_archive_lookup=true; fi
        if ! p2s_backports_prepare_archive_guard "$log" "$native_archive_lookup"; then
            p2s_fix_block candidate_checksum "Could not verify SHA256 values for every package in the approved APT transaction."
            return 1
        fi
        install_options=(-o 'DPkg::Pre-Install-Pkgs::=sh "$P2S_BACKPORTS_ARCHIVE_GUARD"')
    fi
    P2S_TRANSACTION_ATTEMPTED=true
    if $P2S_SURY_MIGRATION_ACTIVE; then P2S_SURY_TRANSACTION_ATTEMPTED=true; fi
    if $P2S_BACKPORTS_ACTIVE && ${P2S_BACKPORTS_REPOSITORY_CREATED:-false}; then P2S_BACKPORTS_TRANSACTION_ATTEMPTED=true; fi
    if $P2S_STACKX_ACTIVE; then P2S_STACKX_TRANSACTION_ATTEMPTED=true; fi
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }apt-get install --only-upgrade PHP packages"
    p2s_message_print info "Installing the approved PHP package updates with APT. This can take up to 30 minutes."
    status=0
    (export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
        if [ "${#install_options[@]}" -gt 0 ]; then export P2S_BACKPORTS_ARCHIVE_GUARD="$P2S_WORK/backports-archive-guard"; fi
        # P2S-MUTATION: Installs PHP and verified required library updates; package scripts can also change services.
        p2s_command_run 1800 apt-get -y --no-remove "${dependency_options[@]}" "${install_options[@]}" -o APT::Get::AllowUnauthenticated=false \
            -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowWeakRepositories=false \
            -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
            -o Dpkg::Options::=--force-confold install --only-upgrade "${packages[@]}" > "$log" 2>&1) || status=$?
    if [ "$status" -ne 0 ]; then
        p2s_package_log_report "$log"
        if [ "${#install_options[@]}" -gt 0 ] && [ -f "$P2S_WORK/backports-archive-guard-started" ] &&
            [ ! -f "$P2S_WORK/backports-archive-guard-passed" ]; then
            P2S_BACKPORTS_TRANSACTION_ATTEMPTED=false
            P2S_STACKX_TRANSACTION_ATTEMPTED=false
            p2s_fix_block candidate_checksum "APT stopped before passing packages to dpkg because the archive SHA256 check failed. Review the downloaded package and repository diagnostics."
        elif [ "$status" -eq 124 ]; then
            p2s_fix_block package_update "APT reached the 30-minute installation limit. Check dpkg --audit and your websites before retrying. The APT output is in the detailed log."
        else
            p2s_fix_block package_update "APT installation failed (exit $status). Check dpkg --audit and your websites before retrying. The APT output is in the detailed log."
        fi
        return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "APT completed the approved PHP package updates and any required library updates."
    if $P2S_STACKX_ACTIVE; then
        P2S_STACKX_INSTALLED=true
        p2s_message_print info "APT installed the selected StackX PHP builds. Test the affected websites and scheduled jobs after the update."
    fi
}

# The migration options authorize a fallback. Plan all installed branches before changing sources.
p2s_package_deb_update_current_sources_first() {
    local name version arch vendor branch source source_version sury status split_branch
    local P2S_APT_PHASE_BRANCHES='' P2S_APT_CURRENT_PROVIDER_ONLY=true P2S_APT_INDEXES_REFRESHED=true
    local P2S_SURY_MIGRATION_ACTIVE=false
    local decisions="$P2S_WORK/apt-branch-decisions" current="$P2S_WORK/apt-current-branches" fallback="$P2S_WORK/apt-migrate-branches"
    p2s_package_deb_preflight && p2s_disruptive_sury_platform_preflight &&
        p2s_package_deb_refresh_indexes && p2s_package_deb_load_candidate_origins || return 1
    : > "$decisions"
    while IFS='|' read -r name version arch vendor; do
        p2s_package_is_engine "$name" || continue
        branch=${name#libapache2-mod-}; branch=${branch%%-*}
        case "$branch" in php[0-9].[0-9]) ;; *)
            p2s_fix_block provider_migration "The PHP engine $name has no reviewed APT branch identity."; return 1 ;;
        esac
        source=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4,$5]++ {print $4 "|" $5}' "$P2S_WORK/deb-source-records")
        source_version=${source#*|}; source=${source%%|*}
        if [ "$source" != "$branch" ] || [ -z "$source_version" ] || [[ "$source_version" == *$'\n'* ]]; then
            p2s_fix_block candidate_provider "Could not verify the installed source-package identity for $name."; return 1
        fi
        sury=false
        if p2s_package_deb_is_sury "$version"; then sury=true
        else
            case "$(p2s_package_provider "$name" "$vendor" "$version")" in Debian|Ubuntu) ;; *)
                p2s_fix_block candidate_provider "The installed publisher of $name has no reviewed equivalent-package migration path."; return 1 ;;
            esac
        fi
        status=0
        if [ "$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$source" "$source_version")" = N ]; then
            status=fixed
        else
            p2s_package_deb_candidate "$name" "$version" "$arch" "$sury" "$vendor" || status=$?
            case "$status" in
                0) status=update ;;
                2) status=migrate ;;
                *) return 1 ;;
            esac
        fi
        printf '%s|%s\n' "$branch" "$status" >> "$decisions"
        p2s_manifest_record provider_choice "$name|$branch|current_publisher=$status"
    done < "$P2S_WORK/packages"
    [ -s "$decisions" ] || return 0
    # A branch is a single dependency cohort. Refuse ambiguous mixed plans within it.
    split_branch=$(awk -F'|' '$2=="migrate" {migrate[$1]=1; next} {keep[$1]=1}
        END {for (branch in migrate) if (keep[branch]) print branch}' "$decisions")
    if [ -n "$split_branch" ]; then
        p2s_fix_block provider_migration "Some packages in $(printf '%s' "$split_branch" | tr '\n' ' ') have verified fixes from the current publisher and others do not. Review the branch's package versions before switching publishers."; return 1
    fi
    awk -F'|' '$2=="update" && !seen[$1]++ {print $1}' "$decisions" > "$current"
    awk -F'|' '$2=="migrate" && !seen[$1]++ {print $1}' "$decisions" > "$fallback"
    if [ -s "$current" ]; then
        P2S_APT_PHASE_BRANCHES=$current
        local P2S_ALLOW_SURY_MIGRATION=false
        p2s_package_deb_update || return 1
        P2S_ALLOW_SURY_MIGRATION=true
        if [ -s "$fallback" ]; then
            p2s_package_inventory_collect
            if ${P2S_BLOCKED:-false} || [ ! -s "$P2S_WORK/packages" ]; then return 1; fi
            if ! awk -F'|' -v additions="$P2S_WORK/dependency-new" '
                BEGIN {while ((getline row < additions)>0) {split(row,a,"|"); library[a[1] "|" a[2]]=1}; close(additions)}
                FILENAME==ARGV[1] {if (!(($1 "|" $3) in library)) pending[$4 "|" $2 "|" $3]=1; next}
                {delete pending[$1 "|" $2 "|" $3]} END {for (package in pending) exit 1}' "$P2S_WORK/apt-approved" "$P2S_WORK/packages"; then
                p2s_fix_block package_update "The installed PHP versions do not match the approved current-source update. Verify the package state before changing sources."; return 1
            fi
            p2s_package_sources_collect
        fi
    fi
    if [ -s "$fallback" ]; then
        P2S_APT_PHASE_BRANCHES=$fallback
        p2s_package_deb_update
    elif [ ! -s "$current" ]; then
        p2s_message_print info "The installed PHP branches already have verified fixes. No repository or PHP publisher changes are needed."
    fi
}

p2s_package_rpm_validate_plan() {
    # LANG=C DNF4/YUM: Upgrading:/Updating:, package rows, Transaction Summary.
    # Other formats require a new reviewed recipe; unknown output is not an approved plan.
    # DNF "Installing dependencies:" then " libicu78 x86_64 78.3-2.el8.remi remi-safe 11 M"
    # reports libicu78|x86_64|78.3-2.el8.remi|remi-safe for verification.
    awk -F'|' -v panel="${P2S_PANEL:-}" -v candidates="${2:-}" -v upgrades="${3:-}" 'NR==FNR {
            if (panel!="cpanel" || $1 !~ /^(cpanel-php|sw-engine)/) selected[$1]=1
            next
        }
        /^[ \t\r]*$/ { next }
        /^[^ \t\r]/ { addition="" }
        /^Installing dependencies:$/ { rows=0; addition="required"; if (candidates=="") bad=1; next }
        /^Installing weak dependencies:$/ { rows=0; addition="weak"; bad=1; next }
        /^(Installing|Removing|Downgrading|Obsoleting|Reinstalling|Replacing|Upgrading dependencies|Updating for dependencies)/ { bad=1 }
        /^(Upgrading|Updating):/ { rows=1; seen=1; next }
        /^Transaction Summary/ { rows=0; summary=1; next }
        summary && /^Install[ \t]+[0-9]+[ \t]+Packages?$/ {
            split($0, totals, /[ \t]+/); install_count=totals[2]+0
        }
        (rows || addition) && NF {
            split($0, fields, /[ \t\r\n\014\013]+/)
            name=fields[1]; if (name=="") name=fields[2]
            if (name ~ /^=+$/) next
            if (addition && name ~ /^[a-zA-Z0-9][a-zA-Z0-9.+_-]*$/ &&
                fields[3] ~ /^(x86_64|aarch64|noarch|i[3-6]86|ppc64le|s390x|riscv64)$/) {
                printf "%s%s (%s)", separator, name, addition
                separator=", "
                if (addition=="required" && candidates!="" &&
                    fields[4] ~ /^[a-zA-Z0-9][a-zA-Z0-9.+:~_-]*$/ && fields[5] ~ /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/) {
                    print name "|" fields[3] "|" fields[4] "|" fields[5] >> candidates
                    additions_seen++
                } else bad=1
            } else if (addition) bad=1
            sub(/\.(x86_64|aarch64|noarch|i[3-6]86|ppc64le|s390x)$/, "", name)
            if (rows && !(name in selected)) bad=1
            if (rows && upgrades!="") {
                if (fields[3] !~ /^(x86_64|aarch64|noarch|i[3-6]86|ppc64le|s390x|riscv64)$/ ||
                    fields[4] !~ /^[a-zA-Z0-9][a-zA-Z0-9.+:~_-]*$/) unpinnable=1
                else print name "-" fields[4] "." fields[3] >> upgrades
            }
        }
        END { exit (bad || !seen || !summary || (additions_seen && (unpinnable || install_count!=additions_seen))) }
    ' "$P2S_WORK/packages" "$1"
}

p2s_package_rpm_approve_libraries() {
    local cache=$1 name arch version repository file repo_cache identity vendor
    while IFS='|' read -r name arch version repository; do
        # The DNF4 test transaction downloaded these exact RPMs in its private cache.
        set -- "$cache"/"$repository"-*/packages/"$name-${version#*:}.$arch.rpm"
        [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] || return 1
        file=$1
        repo_cache=${file%/packages/*}; repo_cache=${repo_cache##*/}; repo_cache=${repo_cache#"$repository"-}
        [ "${#repo_cache}" -eq 16 ] || return 1
        case "$repo_cache" in *[!a-fA-F0-9]*) return 1 ;; esac
        identity=$(p2s_command_run 20 rpm -qp --qf '%{NAME}|%{ARCH}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{VENDOR}\n' "$file") || return 1
        case "$version" in *:*) ;; *) version=0:$version ;; esac
        case "$identity" in "$name|$arch|$version|"*) vendor=${identity##*|} ;; *) return 1 ;; esac
        case "$repository" in
            baseos|BaseOS|appstream|AppStream|powertools|PowerTools|crb|CRB|rhel-*-baseos-rpms|rhel-*-appstream-rpms|ol*_baseos_latest|ol*_appstream)
                case "$P2S_DISTRO:$vendor" in
                    'rocky:Rocky Enterprise Software Foundation'|almalinux:AlmaLinux|centos:CentOS|rhel:Red\ Hat*|ol:Oracle\ America*) ;;
                    *) return 1 ;;
                esac ;;
            remi-safe)
                case "$vendor" in "Remi's RPM repository <https://rpms.remirepo.net/>"|"Remi's RPM repository <https://rpms.remirepo.net/> "*) ;; *) return 1 ;; esac
                awk -F'|' '$2 ~ /[.]remi$/ && $4 ~ /^Remi\047s RPM repository <https:\/\/rpms[.]remirepo[.]net\/>($| )/ {found=1} END {exit !found}' \
                    "$P2S_WORK/packages" || return 1 ;;
            *) return 1 ;;
        esac
        # RPM --provides: libicuuc.so.78()(64bit). A package name alone is not library evidence.
        p2s_command_run 20 rpm -qp --provides "$file" > "$P2S_WORK/rpm-library-provides" &&
            LC_ALL=C grep -Eq '^[a-zA-Z0-9_.+-]+[.]so[.][0-9][.0-9]*(\(\)(\(64bit\))?)?([[:space:]]|$)' "$P2S_WORK/rpm-library-provides" || return 1
        # rpm -qpl: /usr/lib64/libicuuc.so.78.3 is a runtime file; a service or command needs review.
        p2s_command_run 20 rpm -qpl "$file" > "$P2S_WORK/rpm-library-files" &&
            LC_ALL=C awk '
                /^\/(usr\/)?lib(64)?\/.*[.]so[.][0-9][.0-9]*$/ {library=1}
                /^\/(usr\/)?s?bin\/|\/systemd\/(system|user)\/|^\/etc\/(init[.]d|cron([.]|tab|\/))/ {mixed=1}
                END {exit (!library || mixed)}
            ' "$P2S_WORK/rpm-library-files" || return 1
    done < "$P2S_WORK/rpm-library-plan"
}

# P2S-MUTATION: Refreshes configured RPM repositories and writes their metadata cache.
p2s_package_rpm_refresh_indexes() {
    local manager="$1" log="$2" consent=-y status=0
    shift 2
    [ "${P2S_MODE:-fix}" != check ] || consent=--assumeno
    P2S_REPOSITORY_REFRESH=failed
    p2s_message_print info "Running $manager makecache to refresh package metadata."
    p2s_command_run 300 "$manager" "$consent" "$@" '--setopt=*.metadata_expire=0' --setopt=timeout=20 --setopt=retries=1 --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false' makecache < /dev/null > "$log" 2>&1 || status=$?
    p2s_manifest_record repository_refresh "$manager makecache|exit=$status"
    case "$status" in
        124) p2s_package_refresh_failure_report "$log" "$manager makecache timed out after 300 seconds. Check repository connectivity and retry."; return 1 ;;
        0) ;;
        *) p2s_package_refresh_failure_report "$log" "$manager makecache failed (exit $status). Review the repository error in the package-manager log, then retry."; return 1 ;;
    esac
    if grep -Ei 'No (enabled repos|repositories available)' "$log" >/dev/null; then
        p2s_package_refresh_failure_report "$log" "$manager makecache found no enabled repositories. Check the server's repository configuration."; return 1
    fi
    if grep -Ei 'Ignoring repositories:|Failed to download metadata|Cannot download repomd' "$log" >/dev/null; then
        p2s_package_refresh_failure_report "$log" "$manager makecache left repositories unrefreshed. Fix the reported repository errors and rerun the check."; return 1
    fi
    p2s_package_log_report "$log"
    P2S_REPOSITORY_REFRESH=refreshed
}

# P2S-MUTATION: DNF/YUM update path; refreshes caches and can install PHP packages.
p2s_package_rpm_update() {
    local manager manager_version log="$P2S_WORK/rpm-update.log" name version arch vendor additions
    local cache="$P2S_WORK/rpm-cache" library_plan='' upgrades='' packages transaction_options cache_options
    packages=()
    cache_options=()
    while IFS='|' read -r name version arch vendor; do
        case "${P2S_PANEL:-}:$name" in cpanel:cpanel-php*|cpanel:sw-engine*) continue ;; esac
        case "$vendor" in
            ''|'(none)'|unknown)
                p2s_fix_block rpm_vendor "The installed RPM does not identify a publisher for $name ($arch). Review the installed package and its intended source before updating PHP."
                return 1 ;;
        esac
        packages[${#packages[@]}]="$name"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    if p2s_command_exists dnf; then manager=dnf
    elif p2s_command_exists yum; then manager=yum
    else p2s_fix_block rpm_manager "Neither dnf nor yum is available; cannot update RPM PHP packages."; return 1
    fi
    if ! p2s_command_run 30 "$manager" --version > "$log" 2>&1; then
        p2s_package_log_report "$log"
        p2s_fix_block rpm_vendor "Could not verify that $manager can keep the installed PHP package publishers. Review the package manager before updating PHP."
        return 1
    fi
    IFS= read -r manager_version < "$log"
    transaction_options=(-y --setopt=gpgcheck=1 --setopt=sslverify=true '--setopt=*.skip_if_unavailable=false'
        --setopt=allow_vendor_change=false --setopt=install_weak_deps=False --setopt=obsoletes=False)
    # DNF 4.4.2 introduced this solver option. YUM 3 cannot enforce it, but a yum alias for DNF can.
    # DNF4 version output starts with "4.7.0". DNF5 starts with "dnf5 version 5.2.17.0".
    if [[ "$manager_version" =~ ^4\.([0-9]{1,3})\.([0-9]{1,3})([.-][[:alnum:].-]+)?$ ]] &&
        (( 10#${BASH_REMATCH[1]} > 4 || (10#${BASH_REMATCH[1]} == 4 && 10#${BASH_REMATCH[2]} >= 2) )); then
        p2s_manifest_record source_preservation "$manager|DNF4|vendor_change_disabled"
        cache_options=("--setopt=cachedir=$cache" --setopt=keepcache=True '--setopt=*.gpgcheck=1')
        library_plan="$P2S_WORK/rpm-library-plan"
        upgrades="$P2S_WORK/rpm-upgrade-plan"
        : > "$library_plan" && : > "$upgrades" || return 1
    elif [[ "$manager_version" =~ ^dnf5[[:blank:]]version[[:blank:]]5\.[0-9] ]]; then
        # DNF5 policies can otherwise allow vendor changes even with allow_vendor_change=false.
        transaction_options+=(--clear-vendor-policies)
        p2s_manifest_record source_preservation "$manager|DNF5|vendor_change_disabled|vendor_policy_exceptions_disabled_for_this_run"
    else
        p2s_package_log_report "$log"
        p2s_fix_block rpm_vendor "This version of $manager cannot be verified to keep the installed PHP package publishers. Use a supported DNF version or have an administrator review the candidate publishers before updating PHP."
        return 1
    fi
    p2s_package_rpm_refresh_indexes "$manager" "$log" "${cache_options[@]}" || return 1
    # P2S-MUTATION: Test transaction can download/cache packages; no real PHP installation is requested.
    if ! p2s_command_run 1800 "$manager" "${transaction_options[@]}" "${cache_options[@]}" --setopt=tsflags=test update "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block transaction_plan "The RPM test transaction failed with publisher protection enabled. Review the package manager output. No packages were installed."; return 1
    fi
    p2s_package_log_report "$log"
    # DNF can successfully report no work; that is not an unrecognised transaction.
    # Do not perform an install, or infer that the installed PHP has verified fixes.
    if grep -Fx 'Nothing to do.' "$log" >/dev/null; then
        p2s_manifest_record package_update_plan "$manager|no_updates"
        if $P2S_RESTART_PENDING || ${P2S_PANEL_UPDATE_COMPLETED:-false}; then return 0; fi
        p2s_fix_block no_candidate "The configured repositories offered no newer versions for the installed PHP packages from their current publishers. Check the vendor security advisory, enabled repositories, and any package holds or exclusions."
        return 1
    fi
    if ! additions=$(p2s_package_rpm_validate_plan "$log" "$library_plan" "$upgrades") ||
        { [ -n "$library_plan" ] && [ -s "$library_plan" ] && ! p2s_package_rpm_approve_libraries "$cache"; }; then
        if [ -n "$additions" ]; then
            p2s_fix_block transaction_scope "The RPM plan would also install $additions. Review the full transaction and verify the package sources before applying it manually."
        else
            p2s_fix_block transaction_scope "The RPM plan failed the PHP-only update checks. Review additional dependencies, removals and the plan format before proceeding."
        fi
        return 1
    fi
    if [ -n "$library_plan" ] && [ -s "$library_plan" ]; then
        # Pin the PHP upgrades and leave the verified hard dependencies to the cached solver.
        packages=()
        while IFS= read -r name; do packages[${#packages[@]}]="$name"; done < "$upgrades"
        [ "${#packages[@]}" -gt 0 ] || return 1
        cache_options+=(--cacheonly)
        p2s_manifest_record dependency_approval "$(cat "$library_plan")"
        p2s_message_print info "The PHP update requires $additions. The transaction uses the verified cached RPMs."
    fi
    P2S_TRANSACTION_ATTEMPTED=true
    P2S_UPDATE_METHOD="${P2S_UPDATE_METHOD:+$P2S_UPDATE_METHOD; }$manager update PHP packages"
    # P2S-MUTATION: Installs PHP RPM updates; package scriptlets can also change services.
    if ! p2s_command_run 1800 "$manager" "${transaction_options[@]}" "${cache_options[@]}" update "${packages[@]}" > "$log" 2>&1; then
        p2s_package_log_report "$log"; p2s_fix_block package_update "The RPM PHP update failed or timed out; check the package transaction before retrying."; return 1
    fi
    p2s_package_log_report "$log"
    p2s_message_print fixmethod "Updated installed PHP packages through $manager, keeping their publishers and enabled streams."
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
        if ${P2S_NOVEMBER:-false}; then
            p2s_message_print info "This installed PHP build already has verified November fixes. Review the stream migration advice for ongoing support."
        else
            p2s_message_print info "This installed PHP build already has verified PHP2Shell fixes. Review the stream migration advice for ongoing support."
        fi
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
    if ${P2S_NOVEMBER:-false}; then
        p2s_message_print info "Verify the full candidate package revision against the publisher's November PHP advisory before choosing a stream. After migration, check the installed build and rerun --check --november-2026."
    else
        p2s_message_print info "Published PHP2Shell fixes exist for these destination streams, but listing a stream does not verify its current package candidate. After applying one chosen migration, check the full installed build with 'rpm -q php-common' and rerun this script with --check. PHP 7.4 vendor backports can keep the 7.4.33 engine version."
    fi
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
            litespeed)
                # The directory can outlive the server. Engine and process inventory also checks LiteSpeed.
                if [ -x "$directory/bin/lshttpd" ] || [ -x "$directory/bin/openlitespeed" ]; then
                    p2s_fix_block detached_php "LiteSpeed is installed. Detached LSPHP workers can survive a web-server restart; a handler-specific update and restart review is required."
                fi ;;
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
    : > "$P2S_WORK/php-restart-details"
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
                case "$path" in *' (deleted)')
                    P2S_UNKNOWN=true; P2S_RESTART_PENDING=true
                    printf '%s|PHP module|%s\n' "$comm" "${path% (deleted)}" >> "$P2S_WORK/php-restart-details" ;;
                esac
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
                printf '%s|executable|%s\n' "$comm" "${executable% (deleted)}" >> "$P2S_WORK/php-restart-details"
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
    if [ -s "$P2S_WORK/php-restart-details" ]; then
        p2s_manifest_record php_restart_warning details_emitted
        sort -u "$P2S_WORK/php-restart-details" | while IFS='|' read -r comm label path; do
            p2s_message_print warn "$comm still uses the old $label at $path. Restart its service or wait for the process to exit. Run this check again."
        done
    fi
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

p2s_service_diagnostic_redact() {
    sed '
s@https\{0,1\}://[^[:space:]]*@[URL redacted]@g
s@ftp://[^[:space:]]*@[URL redacted]@g
/[Pp][Aa][Ss][Ss]/s/.*/[sensitive diagnostic redacted]/
/[Tt][Oo][Kk][Ee][Nn]/s/.*/[sensitive diagnostic redacted]/
/[Ss][Ee][Cc][Rr][Ee][Tt]/s/.*/[sensitive diagnostic redacted]/'
}

p2s_service_check_config() {
    local label="$1" status argument
    shift
    # Arguments and errors stay in the manifest, never masquerading as customer/protocol messages.
    for argument in "$@"; do
        p2s_manifest_record configtest_argument "$(printf '%s\n' "$argument" | p2s_service_diagnostic_redact)"
    done
    p2s_command_run 30 "$@" > "$P2S_WORK/configtest" 2>&1
    status=$?
    p2s_manifest_record configtest_exit "$label|$status"
    p2s_manifest_record configtest_output "$(p2s_service_diagnostic_redact < "$P2S_WORK/configtest")"
    case "$label" in PHP-FPM*) p2s_runtime_report_startup_warnings "$label" "$(cat "$P2S_WORK/configtest")" ;; esac
    if [ "$status" -ne 0 ]; then
        if [ "$status" -eq 124 ]; then
            p2s_fix_block configtest "$label configuration validation timed out after 30 seconds. Review configtest_output in the detailed log and check the service logs before trying the update."
        else
            p2s_fix_block configtest "$label configuration validation failed (exit $status). Review configtest_output in the detailed log and fix the reported configuration problem before trying the update."
        fi
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
            p2s_fix_block restart "Could not restart and verify $unit. Check its status and service logs to see whether it is running and why the restart failed."
            failed=true
        else
            p2s_message_print fixmethod "Restarted $unit and confirmed it is active."
        fi
    done < "$P2S_WORK/services.before"
    # Recheck original worker identities after the service command completes.
    while IFS='|' read -r pid executable; do
        case "$executable" in */nginx*) continue ;; esac
        if [ -e "/proc/$pid/exe" ]; then
            p2s_fix_block old_worker "A PHP or web worker present before the restart is still running (PID $pid). Run ps -p $pid -o pid,lstart,comm to inspect it and verify which service owns it before restarting anything again."
            failed=true
        fi
    done < "$P2S_WORK/processes.before"
    if $failed; then return 1; fi
}

# Customer summaries

p2s_stackx_report() {
    local suite name source revision index reported=' '
    [ "${P2S_MODE:-check}" = check ] && suite=$(p2s_stackx_suite) || return 0
    index="https://mirrors.scalarx.net/stackx-php/$suite/repo/Sources"
    # The summary also contains executable observations. Use installed engine packages with an unresolved assessment.
    awk -F'|' '$2 != "N" && $8 == "package" && $12 == "amd64" {print $10}' "$P2S_WORK/summary-versions" |
        while IFS= read -r name; do
            source=$(p2s_backports_source "$name") || continue
            case "$reported" in *" $source "*) continue ;; esac
            revision=$(p2s_stackx_published_build "$suite" "$source") || continue
            reported="$reported$source "
            p2s_message_print info "StackX publishes a security build of PHP ${source#php} for Debian $suite (amd64). Source revision in this check's snapshot: $revision."
            p2s_manifest_record stackx_published_build "$suite|$source|amd64|$revision|evidence=vendor_reported|source_index=$index"
        done
}

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
    sort -u "$P2S_WORK/summary-versions" | awk -F'|' -v prefix="$prefix" -v distro="${P2S_DISTRO:-unknown}" -v release="${P2S_RELEASE:-unknown}" -v november="${P2S_NOVEMBER:-false}" '
        {
            key=$1 SUBSEP $2 SUBSEP $5
            # A backport changes the package build while php -v can stay unchanged.
            if ($5 ~ /^Sury\/|^StackX /) key=key SUBSEP $6
            if (!(key in version)) { order[++count]=key; version[key]=$1; state[key]=$2; provider[key]=$5 }
            if (!seen_role[key SUBSEP $3]++) roles[key]=roles[key] (roles[key] ? ", " : "") $3
            if ($4 != "" && !seen_build[key SUBSEP $3 SUBSEP $4]++) builds[key]=builds[key] (builds[key] ? "; " : "") $3 ": " $4
            if ($7 == "Y") affected_upstream[key]=1
            if ($2 == "Y" && $7 == "?") presumed_affected[key]=1
            if ($8 != "") evidence[key SUBSEP $8]=1
            if ($6 != "" && !seen_revision[key SUBSEP $6]++) revisions[key]=revisions[key] (revisions[key] ? ", " : "") $6
            if ($9 != "") reasons[key SUBSEP $9]=1
            if ($10 != "" && !seen_package[key SUBSEP $10]++) packages[key]=packages[key] (packages[key] ? ", " : "") $10
            if ($11 != "" && !seen_fixed[key SUBSEP $11]++) fixed_builds[key]=fixed_builds[key] (fixed_builds[key] ? ", " : "") $11
            if ($12 != "" && !seen_arch[key SUBSEP $12]++) architectures[key]=architectures[key] (architectures[key] ? ", " : "") $12
        }
        END {
            for (i=1; i<=count; i++) {
                key=order[i]; level="info"; conclusion="fixes verified for both PHP2Shell vulnerabilities."
                if (november=="true") conclusion="November PHP fixes verified."
                if (state[key]=="Y") { level="warn"; conclusion="vulnerable; update these components and restart the services using them." }
                if (state[key]=="Y" && presumed_affected[key] && november!="true")
                    conclusion="presumed vulnerable because this stock CentOS 5 PHP package predates the PHP2Shell fixes and has no verified backport. Migrate applications to maintained, patched PHP. Exploitability has not been tested."
                if (state[key]=="?") { level="warn"; conclusion="patch status not verified." }
                split(version[key], parts, "[.]")
                if (state[key]=="?" && november!="true" && version[key] ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ &&
                    (parts[1]<5 || (parts[1]==5 && parts[2]<4)))
                    conclusion="outside this detector\047s verified PHP2Shell coverage; review its security support and migrate applications to maintained, patched PHP."
                text=prefix "PHP " version[key] " (" roles[key] "): " conclusion
                source=provider[key]; sub(/ [(](revision|namespace) hint[)]$/, "", source)
                if (source) text=text (provider[key] ~ /^StackX / ? " Package publisher hint: " : " Package publisher: ") source "."
                if (packages[key]) text=text " Installed packages: " packages[key] "."
                if (builds[key]) text=text " Reported build dates: " builds[key] "."
                if ((provider[key] ~ /^Sury\// || november=="true") && revisions[key]) text=text " Installed package build: " revisions[key] "."
                if (state[key]=="N" && affected_upstream[key]) text=text " The PHP package publisher added the security fixes without changing the PHP version."
                if (state[key]=="?") {
                    if (provider[key] !~ /^Sury\// && revisions[key] && november!="true") text=text " Installed package build: " revisions[key] "."
                    if (reasons[key SUBSEP "engine_package_version_mismatch"])
                        text=text " The executable reports a different PHP version from its owning package; check the runtime mismatch warning."
                    else if (reasons[key SUBSEP "package_inventory_unavailable"])
                        text=text " Package inventory is unavailable, so the installed build and any vendor security fixes could not be checked."
                    else if (reasons[key SUBSEP "owner_is_not_an_assessed_engine"] || reasons[key SUBSEP "owner_outside_PHP_inventory"])
                        text=text " No assessed PHP engine package owns this executable; confirm its installation source and security fixes."
                    else if (november=="true")
                        text=text " Check the full package revision against the publisher\047s November advisory."
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
                        text=text " This check compares installed Sury/ondrej package versions with a built-in list of package builds verified to include both PHP2Shell fixes. That list has no entry for " (packages[key] ? packages[key] : "these packages") " on " distro " " release " (package architecture: " (architectures[key] ? architectures[key] : "unknown") "). The list covers PHP 5.6-8.1 on amd64 for Debian 11-13 and Ubuntu 22.04/24.04. Without a matching list entry, this check cannot determine whether the installed build includes the fixes. The publisher may still offer a fixed package; check both CVEs with the package publisher."
                    else if (affected_upstream[key])
                        text=text " This PHP release needs security fixes from its package publisher. This script has no verified fix record for the installed build. Check both CVEs with the publisher or install a confirmed fixed build."
                    else text=text " No verified version or package fix rule matches this build; check both CVEs with its publisher."
                }
                if (state[key]=="Y" && provider[key]=="AlmaLinux" && november!="true") text=text " AlmaLinux has published security updates for this PHP stream; check your configured package sources for an available fix."
                if (evidence[key SUBSEP "running_path"]) text=text " Running processes use this installation."
                else if (evidence[key SUBSEP "executable"]) { text=text " Installed; no matching running process was found."; idle_observation=1 }
                else if (evidence[key SUBSEP "module"]) { text=text " Apache module installed; no matching running process was found."; idle_observation=1 }
                else if (evidence[key SUBSEP "package"]) text=text " Checked installed packages; no PHP executable or Apache module was matched."
                print level "|" text
            }
            if (idle_observation) print "info|Process observations cover this check only. PHP with no matching running process may still be required by websites, scheduled jobs or other packages. Review those requirements before considering removal."
        }' | while IFS='|' read -r level message; do p2s_message_print "$level" "$message"; done
    p2s_stackx_report
}

# Suggested commands only: an unresolved update must never take applications offline automatically.
p2s_fix_print_exposure_advice() {
    local unit name path command properties trigger triggers_verified found=false
    [ "${P2S_MODE:-check}" = fix ] && [ "$P2S_STATE" != N ] || return 0
    # pgb:php-exposure: Use observed PHP service mappings, never all web servers or a guessed FPM unit.
    p2s_message_print warn "Temporary exposure reduction: PHP may still be vulnerable. You can stop the affected PHP services until a patched build is verified. Review the PHP version warnings when choosing which services to stop. This will interrupt websites, jobs and any control-panel functions using those services. These commands are suggestions; this script does not run them."
    : > "$P2S_WORK/exposure-services.raw"
    if [ -r "$P2S_WORK/services" ]; then cat "$P2S_WORK/services" >> "$P2S_WORK/exposure-services.raw"; fi
    if [ -r "$P2S_WORK/unmapped-services" ]; then
        # An observed FPM template instance can be stopped manually even without an automatic restart recipe.
        while IFS='|' read -r name path unit; do
            case "$name:$unit" in php*fpm*:php*.service) printf '%s\n' "$unit" >> "$P2S_WORK/exposure-services.raw" ;; esac
        done < "$P2S_WORK/unmapped-services"
    fi
    if [ -s "$P2S_WORK/exposure-services.raw" ]; then
        sort -u "$P2S_WORK/exposure-services.raw" > "$P2S_WORK/exposure-services"
        while IFS= read -r unit; do
            case "$unit" in ''|*[!a-zA-Z0-9_.@:-]*|[!a-zA-Z0-9]*) continue ;; esac
            case "$unit" in
                apache2.service|httpd.service|init:apache2|init:httpd)
                    p2s_message_print warn "Apache was observed hosting PHP (an embedded module or PHP workers). Stopping $unit stops every website in that Apache instance, including non-PHP sites. Removing its PHP handler can break configuration or expose PHP source; do not disable the module as a generic workaround." ;;
            esac
            case "$unit" in
                *.service)
                    command='sudo systemctl stop'
                    triggers_verified=false
                    # systemctl show: TriggeredBy=php-fpm.socket php-refresh.timer -> stop these together with the service.
                    if properties=$(p2s_command_run 10 systemctl show "$unit" -p TriggeredBy 2>/dev/null); then
                        case "$properties" in TriggeredBy=*)
                            triggers_verified=true
                            printf '%s\n' "${properties#TriggeredBy=}" | tr ' ' '\n' > "$P2S_WORK/exposure-triggers"
                            while IFS= read -r trigger; do
                                [ -n "$trigger" ] || continue
                                case "$trigger" in *[!a-zA-Z0-9_.@:-]*|[!a-zA-Z0-9]*) triggers_verified=false; continue ;; esac
                                case "$trigger" in
                                    *.socket|*.timer|*.path) command="$command '$trigger'" ;;
                                    *) triggers_verified=false ;;
                                esac
                            done < "$P2S_WORK/exposure-triggers" ;;
                        esac
                    fi
                    if ! $triggers_verified; then
                        p2s_message_print warn "Activation triggers for $unit could not be fully checked. Review sudo systemctl show '$unit' -p TriggeredBy and stop any associated socket, timer or path activation before relying on the service stop."
                    fi
                    command="$command '$unit'" ;;
                init:*)
                    name=${unit#init:}
                    case "$name" in ''|[!a-zA-Z0-9]*) continue ;; esac
                    if p2s_command_exists service; then command="sudo service '$name' stop"
                    else command="sudo '/etc/init.d/$name' stop"
                    fi ;;
                *) continue ;;
            esac
            found=true
            p2s_message_print warn "To stop PHP served by $unit, run: $command"
            p2s_manifest_record exposure_stop_command "$unit|$command|suggestion_only"
        done < "$P2S_WORK/exposure-services"
    fi
    if ! $found; then
        p2s_message_print warn "No verified PHP service stop command could be identified. An administrator must identify and stop the affected PHP applications or their launchers using the process details in the diagnostic report."
    fi
    if [ -s "$P2S_WORK/unmapped-services" ]; then
        p2s_message_print warn "Some PHP workers have no automatic restart recipe; any unlisted launchers still need a shutdown review using the process and parent details in the diagnostic report. For Supervisor, run sudo supervisorctl status, then sudo supervisorctl stop PROGRAM (replace PROGRAM with the affected PHP program's exact name); do not stop Supervisor or unrelated programs."
    fi
    if [ -s "$P2S_WORK/scheduled-php" ]; then
        p2s_message_print warn "PHP scheduled tasks are also running. Stopping PHP-FPM or Apache will not stop these tasks. Pause only their PHP schedules and stop the affected jobs through their application's procedure; do not stop cron for the whole server. Their PIDs and executable paths are in the diagnostic report."
    fi
    if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}; then
        p2s_message_print warn "Stop any affected PHP workloads in containers or separate application environments from within those environments."
    fi
    p2s_message_print warn "Verify that the affected PHP workers have stopped and cannot be relaunched by requests, schedules, supervisors or panel monitoring. These commands cover the identified services only. Keep affected applications offline until their PHP fixes are verified; stopping services does not patch PHP."
}

p2s_summary_print_result() {
    local unresolved_versions='' update_blockers='' issue_name=PHP2Shell fixes='both PHP2Shell fixes' check_options=--check
    local migration_target target_branch target_state target_web target_cli target_preparation target_workloads
    if ${P2S_NOVEMBER:-false}; then
        issue_name='the November PHP vulnerabilities'
        fixes='the November PHP fixes'
        check_options='--check --november-2026'
    fi
    # This describes the final phase only; before/after protocol markers remain unchanged.
    case "$P2S_STATE" in
        Y) p2s_message_print warn "Result: The check found PHP affected by $issue_name. If patching has to wait, take affected PHP applications offline." ;;
        '?')
            # Package and executable checks can disagree within one installation; describe component evidence.
            if p2s_state_has_only_fixed_versions; then
                if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}; then
                    p2s_message_print warn "Result: Verified host PHP builds include $fixes. PHP in a separate application environment still needs checking."
                else
                    p2s_message_print warn "Result: Verified PHP builds include $fixes. Some checks are still unresolved."
                fi
                p2s_manifest_record verification_scope "assessed_host_versions=fixed|separate_environment_review=${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}|overall=unknown"
            elif [ -s "$P2S_WORK/summary-versions" ] && awk -F'|' '
                $2 == "N" { fixed=1 } $2 == "?" { unverified=1 }
                END { exit !(fixed && unverified) }' "$P2S_WORK/summary-versions"; then
                p2s_message_print warn "Result: The check verified $fixes for some PHP installations. Review the PHP versions that still need a fix or verification."
            else
                p2s_message_print warn "Result: We could not verify whether all PHP installations include $fixes. Review the checks that still need attention."
            fi ;;
        N)
            if [ "$P2S_COUNT" -eq 0 ]; then
                p2s_message_print info "Result: The check found no PHP in the packages, runtime locations, or running processes it inspected. No PHP update is needed for this issue."
            else
                p2s_message_print info "Result: All detected PHP installations include $fixes. No PHP restart is pending."
            fi ;;
    esac
    if [ "$P2S_STATE" != N ] && [ -s "$P2S_WORK/summary-versions" ]; then
        # Check package publisher support for unverified backports; migrate sites/jobs explicitly when a branch lacks a supported fix.
        unresolved_versions=$(sort -u "$P2S_WORK/summary-versions" | awk -F'|' '
            $1 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ {
                if ($2 != "N" && !seen_version[$1]++) versions=versions (versions ? ", " : "") "PHP " $1
            }
            END { if (versions != "") print versions }')
        if [ -n "$unresolved_versions" ]; then
            if ${P2S_NOVEMBER:-false}; then
                p2s_message_print warn "PHP versions needing attention: $unresolved_versions. Check the full package builds with their publishers for verified November fixes."
            else
                p2s_message_print warn "PHP versions needing attention: $unresolved_versions. Check the full package builds with their publishers for verified fixes. End-of-life status and PHP2Shell fix status are separate. Test migrated workloads and review package dependencies and proposed removals. Changing the default PHP version alone does not move individual websites."
            fi
        fi
    fi
    if [ "$P2S_STATE" = Y ] && [ "${P2S_APT_PLAN:-}" = ready ]; then
        p2s_message_print warn "Next action: Run the PHP update. It rechecks the APT plan before installing the approved fixes and restarts affected services as needed."
    elif [ "${P2S_APT_PLAN:-}" = blocked ]; then
        p2s_message_print warn "Next action: Resolve the reported APT plan problem, then run $check_options to check which PHP updates are available."
    elif [ "$P2S_STATE" != N ]; then
        if ${P2S_BLOCKED:-false}; then update_blockers='Resolve the problems in the warnings before running the update. '; fi
        if [ "$P2S_STATE" = '?' ] && p2s_state_has_only_fixed_versions; then
            if ! ${P2S_BLOCKED:-false} && ${P2S_RESTART_PENDING:-false}; then
                p2s_message_print warn "Next action: Review and restart the services reported as still running replaced PHP code. Then run $check_options to verify the running PHP and any remaining inventory."
            elif ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false}; then
                p2s_message_print warn "Next action: ${update_blockers}Verify the remaining inventory in containers or separate application environments, then run $check_options. The assessed PHP builds already have verified fixes."
            else
                p2s_message_print warn "Next action: ${update_blockers}Verify the remaining inventory identified in this report, then run $check_options. The assessed PHP builds already have verified fixes."
            fi
        else
            migration_target=''
            if [ -s "$P2S_WORK/summary-versions" ]; then
                # Sample: 8.4.28|N|PHP-FPM||Debian|8.4.28-1~deb13u1|N|executable|engine_package_assessment
                # With unresolved PHP 7.4 this can suggest 8.4|fixed|1|0. A library or panel-only runtime is not a target.
                migration_target=$(awk -F'|' '
                    function older(left, right, a, b) {
                        split(left, a, "."); split(right, b, ".")
                        return (a[1]+0 < b[1]+0) || (a[1]+0 == b[1]+0 && a[2]+0 < b[2]+0)
                    }
                    $1 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ {
                        branch=$1; sub(/[.][0-9]+$/, "", branch)
                        if ($2 != "N") {
                            unresolved[branch]=1
                            if (!oldest || older(branch, oldest)) oldest=branch
                        }
                        if ($6 == "" || $9 != "engine_package_assessment" || $5 ~ /^(cPanel internal|WebPros sw-engine)/) next
                        if ($5 == "" || $5 == "unverified source" || $5 == "unknown") next
                        if ($3 ~ /^(PHP-FPM|Apache module|CGI)$/) web[branch]=1
                        if ($3 == "command line") cli[branch]=1
                        if (web[branch] || cli[branch]) installed[branch]=1
                    }
                    END {
                        for (branch in installed) {
                            if (!oldest || !older(oldest, branch)) continue
                            # Prefer a verified target, then one with a web runtime, then the smallest applicable branch change.
                            rank=(unresolved[branch] ? 0 : 2) + web[branch]
                            if (!target || rank > best || (rank == best && older(branch, target))) {
                                target=branch; best=rank
                            }
                        }
                        if (target) print target "|" (unresolved[target] ? "unverified" : "fixed") "|" (web[target]+0) "|" (cli[target]+0)
                    }' "$P2S_WORK/summary-versions")
            fi
            if [ -n "$migration_target" ]; then
                IFS='|' read -r target_branch target_state target_web target_cli <<< "$migration_target"
                if [ "$target_state" = fixed ]; then
                    target_preparation="The check verified $fixes for the installed PHP $target_branch components it inspected. Confirm ongoing publisher support and verify the running PHP build, including any required service restart, before moving workloads."
                else
                    target_preparation="PHP $target_branch is also installed. Confirm with its publisher that a maintained package build includes $fixes, apply it, and rerun the check before moving any workloads."
                fi
                if [ "$target_web" = 1 ]; then
                    target_workloads="Test website and extension compatibility, then move compatible sites by changing each site’s PHP handler."
                    if [ "$target_cli" = 1 ]; then
                        target_workloads="$target_workloads Update any compatible scheduled jobs to use the newer command-line PHP."
                    else
                        target_workloads="$target_workloads Verify a compatible command-line runtime separately before changing scheduled jobs."
                    fi
                else
                    target_workloads="Test compatible scheduled jobs and command-line applications before changing the PHP executable they use. Verify a suitable web handler separately before moving any sites."
                fi
                p2s_message_print warn "Next action: ${update_blockers}Review moving workloads off the older PHP branches that still need attention. $target_preparation $target_workloads Test the migrated workloads. Review dependencies and the package manager’s proposed removals before manually uninstalling old PHP packages that nothing still uses."
            else
                p2s_message_print warn "Next action: ${update_blockers}Confirm which websites, applications, scheduled jobs and dependencies require ${unresolved_versions:-PHP}. Obtain verified fixed packages or migrate required workloads to supported, patched PHP. Remove unneeded PHP packages only after reviewing dependencies and the proposed removals."
            fi
        fi
    fi
    case "$P2S_STATE" in
        Y|'?') p2s_message_print info "RimuHosting offers a free, no-obligation assessment for servers hosted here or elsewhere. We'll report options to reduce exposure or move to supported OS and PHP versions. You can keep your current hosting provider. We'll agree any further work with you first. Start at https://distrorejuve.com/" ;;
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
    if ${P2S_ALLOW_BACKPORTS:-false} && p2s_backports_scope; then
        p2s_manifest_record update_recipe 'apt|explicit_debian_php_backports|existing_signed_source_and_candidate_required'
        return 0
    fi
    if ${P2S_ALLOW_STACKX:-false}; then
        if ! p2s_stackx_scope; then
            p2s_fix_block provider_migration "The StackX fallback requires Debian 9, 10 or 11 without a detected hosting panel. Select an eligible amd64 PHP branch."
            return 1
        fi
        p2s_manifest_record update_recipe 'apt|explicit_stackx|signed_source_setup_if_needed'
        return 0
    fi
    if p2s_november_apt_scope; then
        p2s_manifest_record update_recipe 'apt|configured_sources_first|verified_same_branch_packages_required'
        return 0
    fi
    # Snapshot 2026-10-22. Entitled Ubuntu ESM may still supply packages on old LTSs.
    case "$P2S_DISTRO:$P2S_MAJOR" in
        arch:*)
            p2s_fix_block update_recipe "Automatic updates are not implemented for Arch Linux. Arrange a reviewed system upgrade using pacman; Arch does not support partial package upgrades."
            return 1 ;;
        debian:*)
            [ "$P2S_MAJOR" -ge 12 ] && return 0
            if ${P2S_ALLOW_FREEXIAN:-false} && p2s_freexian_native_scope; then
                p2s_manifest_record update_recipe 'debian|explicit_Freexian_ELTS|existing_signed_source_and_candidate_required'
                return 0
            fi
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
                    p2s_message_print warn "Ubuntu $P2S_RELEASE is outside Canonical's standard security-support window. Continued Canonical PHP security updates require suitable Ubuntu Pro/ESM coverage (older releases may need the Legacy add-on). Check coverage at https://ubuntu.com/security/esm and setup at https://ubuntu.com/pro/docs/attach-tutorial/; use pro status to check enabled services. This check has not verified an entitlement. Ubuntu Pro does not patch third-party Sury/ondrej packages. Alternatively, plan a supported Ubuntu release upgrade or migrate applications to a supported Debian/Ubuntu server."
                    return 0 ;;
            esac ;;
        almalinux:*|rocky:*|rhel:*|ol:*) [ "$P2S_MAJOR" -ge 8 ] && return 0 ;;
        centos:7)
            p2s_fix_block unsupported_os "No automatic update recipe for $P2S_DISTRO $P2S_RELEASE is implemented in this script. CentOS Linux 7 reached end of life on 30 June 2024. Standard CentOS 7 archives contain historical PHP packages, including PHP 5.4.16-48.el7 from April 2020, without the PHP2Shell fixes. Updating those packages with yum upgrade or repairing archive mirror access will not resolve PHP2Shell. Use a maintained PHP publisher with a verified fix, or migrate applications to a supported OS and patched PHP."
            return 1 ;;
        centos:*) [ "$P2S_MAJOR" -ge 9 ] && return 0 ;;
    esac
    p2s_fix_block unsupported_os "No automatic update recipe for $P2S_DISTRO $P2S_RELEASE is implemented in this script. Ask the PHP package publisher whether it supplies a verified fix for this OS release. If no maintained build is available, plan an OS upgrade or move the affected workloads to a supported server."
    return 1
}

p2s_fix_disk_preflight() {
    local low_space system_space="$P2S_WORK/fix-disk" work_space="$P2S_WORK/fix-work-disk"
    # Keep diagnostics even when an earlier prerequisite already blocked the update.
    if p2s_command_exists df; then
        if ! p2s_command_run 10 df -Pk / /var /usr > "$system_space" 2>/dev/null ||
            ! p2s_command_run 10 df -Pk "$P2S_WORK" > "$work_space" 2>/dev/null; then
            p2s_fix_block disk_check "The free-space check failed. Run df -Pk / /var /usr and check the filesystem holding the updater’s temporary files before updating PHP."
            return 1
        fi
        p2s_manifest_record disk_preflight "$(cat "$system_space"; sed '1d' "$work_space")"
        # df -Pk: /dev/root 12582912 12582912 0 100% /
        # Keep 128 MiB for packages and 32 MiB for work files, including package-manager logs.
        low_space=$(awk '
            FNR==1 {minimum=(FILENAME==ARGV[1] ? 131072 : 32768); next}
            $4 ~ /^[0-9]+$/ && $4<minimum && !seen[$1 SUBSEP $6]++ {
                printf "%s%s (%s): %s KiB available, %s MiB required", separator, $6, $1, $4, minimum/1024
                separator="; "
            }' "$system_space" "$work_space") || {
            p2s_fix_block disk_check "The updater could not interpret the free-space report. Review disk_preflight in the detailed log before updating PHP."
            return 1
        }
        if [ -n "$low_space" ]; then
            p2s_fix_block disk_space "Insufficient free space for a PHP update: $low_space. Free space or check whether an enlarged VM disk still needs its partition/filesystem grown, then retry. Larger updates may need more space."
            return 1
        fi
    fi
}

# Fix mode repeats these local probes because prerequisites can change after a check.
p2s_fix_preflight() {
    local name version arch vendor
    p2s_fix_disk_preflight || return 1
    if $P2S_BLOCKED; then return 1; fi
    if { ${P2S_ALLOW_BACKPORTS:-false} || ${P2S_ALLOW_BACKPORTS_REPOSITORY:-false}; } && ! p2s_backports_scope; then
        p2s_fix_block provider_migration "Debian PHP Backports requires an eligible Debian or Ubuntu host without a detected hosting panel."
        return 1
    fi
    if ${P2S_ALLOW_FREEXIAN:-false} && p2s_freexian_native_scope; then
        : # The package preflight checks the configured ELTS source before any transaction.
    elif ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        if [ "$P2S_BACKEND" != deb ]; then
            p2s_fix_block provider_migration "The Sury migration method requires native Debian/Ubuntu packages; no change between package formats or RPM package publishers is implemented."
            return 1
        fi
        p2s_disruptive_sury_platform_preflight || return 1
    elif ${P2S_ALLOW_FREEXIAN:-false}; then
        p2s_fix_block provider_migration "The Freexian Extended LTS option covers reviewed native PHP packages on Debian 9, 10 or 11. This server's installed PHP or OS is outside that scope."
        return 1
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
            p2s_message_print warn "Package lock $file is held by PID $pid ($name, parent $parent), running for $elapsed (warning threshold: 1 hour). Lock acquisition time is unavailable. Ask an administrator to investigate its progress and logs before retrying."
            p2s_message_print warn "Recheck the owner: ps -p $pid -o pid,ppid,etime,stat,comm; lslocks. Stopping a package manager or removing its lock is not an automatic repair. Interrupting package installation/configuration can leave packages unfinished. No process was stopped and no lock file was removed."
        done
    done
    return 0
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
    local method=$1 options=$2 evidence=$3 scope=
    # An unresolved fix already tried the ordinary update path; retain only specific repair options.
    if [ "$P2S_PHASE" = afterfix ] && [ "$options" = --fix ]; then return 0; fi
    P2S_FIX_RECOMMENDATION_EMITTED=true
    if ${P2S_NOVEMBER:-false}; then scope=' --november-2026'; fi
    p2s_message_print info "Suggested options: $options$scope. $evidence Fix mode rechecks prerequisites and PHP afterwards; updates can interrupt applications."
    p2s_manifest_record fix_recommendation "$method|options=$options|$evidence|check_only_no_changes|fresh_fix_preflight_required"
}

p2s_freexian_setup_guidance() {
    local scope native version provider branch native_needed=false private='' action
    ${P2S_NOVEMBER:-false} && [ "${P2S_STATE:-N}" != N ] && [ "${P2S_BACKEND:-}" = deb ] || return 0
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 0 ;; esac
    case "$P2S_DISTRO:$P2S_RELEASE" in
        debian:9|debian:9.*|debian:10|debian:10.*|debian:11|debian:11.*|debian:12|debian:12.*|debian:13|debian:13.*|\
        ubuntu:18.04|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
        *) return 0 ;;
    esac
    [ -s "$P2S_WORK/summary-versions" ] || return 0
    p2s_fix_blockers_match '|unsupported_os|candidate_provider|candidate_fix|no_candidate|repositories|source_authentication|' || return 0
    scope=$(p2s_freexian_suite) || scope=''
    native=${scope#*|}; native=${native#php}
    while IFS='|' read -r version provider; do
        branch=${version%.*}
        if [ "$branch:$provider" = "$native:Debian" ]; then
            native_needed=true
            continue
        fi
        # The provider's public availability matrix shows branches, without a verified private build.
        case "$branch" in
            5.6|7.[0-4]|8.[0-3]) ;;
            8.[45])
                case "$P2S_DISTRO:$P2S_RELEASE" in debian:9|debian:9.*|ubuntu:18.04) continue ;; esac ;;
            *) continue ;;
        esac
        case ", $private," in *", PHP $branch,"*) continue ;; esac
        private="${private:+$private, }PHP $branch"
    done < <(awk -F'|' '$1 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ && $2 != "N" && $6 != "" &&
        ($8 == "package" || $9 == "engine_package_assessment") {print $1 "|" $5}' "$P2S_WORK/summary-versions" | sort -u)
    if $native_needed; then
        if p2s_freexian_native_scope; then
            action='Have your administrator configure the signed feed or check the existing setup, repair any failing APT sources, and rerun the PHP check. The update option appears after the package plan is verified.'
        else
            action='Ask your administrator to repair any failing APT sources, verify package availability and review the impact on shared services. Check each installed PHP branch separately for a fix.'
        fi
        p2s_message_print warn "Freexian Extended LTS publishes a November fix for native PHP $native on Debian ${P2S_RELEASE%%.*}. $action https://www.freexian.com/lts/extended/docs/how-to-use-extended-lts/"
        p2s_manifest_record freexian_guidance "extended_lts|${scope%%|*}|php$native|administrator_review"
    fi
    if [ -n "$private" ]; then
        p2s_message_print warn "The separate Freexian PHP LTS subscription lists $private for this OS. Subscribers can configure their Freexian-issued APT source using the setup guide. Ask Freexian to confirm the exact November fix and package access for this architecture. https://www.freexian.com/lts/php/docs/access-apt-repositories/"
        p2s_manifest_record freexian_guidance "php_lts|$P2S_DISTRO|$P2S_RELEASE|$private|exact_build_and_access_unverified"
    fi
}

p2s_stackx_recommendation() {
    local suite name branch branches='' log="$P2S_WORK/stackx-plan.log"
    local evidence='The configured StackX feed supplies signed packages that passed APT simulation.'
    p2s_stackx_scope && suite=$(p2s_stackx_suite) || return 0
    if ${P2S_ALLOW_STACKX:-false}; then
        if [ "${P2S_REPOSITORY_REFRESH:-}" != refreshed ]; then p2s_check_refresh_packages || return 0; fi
        branches=$P2S_PHP_SOURCE_BRANCHES
    else
        [ "${P2S_REPOSITORY_REFRESH:-}" = refreshed ] || return 0
        while IFS= read -r name; do
            branch=$(p2s_backports_source "$name") && p2s_stackx_published_build "$suite" "$branch" >/dev/null || continue
            case ",$branches," in *",$branch,"*) continue ;; esac
            branches="${branches:+$branches,}$branch"
        done < <(awk -F'|' '$2!="N" && $8=="package" && $12=="amd64" {print $10}' "$P2S_WORK/summary-versions")
    fi
    [ -n "$branches" ] || return 0
    branches=$(printf '%s\n' "$branches" | tr ',' '\n' | sort -u | paste -sd, -)
    if (
        P2S_MODE=check; P2S_ALLOW_STACKX=true; P2S_ASSESSMENT_ONLY=true; P2S_PHP_SOURCE_BRANCHES=$branches
        p2s_fix_preflight && p2s_package_deb_update stackx
    ) > "$log" 2>&1; then
        if grep -Fq '|source_setup_required|signed_candidates_available|' "$log"; then
            evidence='The signed StackX feed supplies matching packages. Fix mode configures the repository and simulates the selected update before installing.'
        fi
        p2s_manifest_record source_add_scope "stackx|$branches"
        p2s_fix_recommendation_print stackx "--fix --enable-extra-fixes --use-stackx --php-source-branches=$branches" "$evidence"
    elif ${P2S_ALLOW_STACKX:-false}; then
        sed -n '/^dss:warn: /p' "$log"
    fi
    p2s_manifest_record option_assessment "stackx|refreshed
$(cat "$log")"
}

p2s_fix_recommend_options() {
    local P2S_VERIFIED_PROVIDER_PLAN=false
    P2S_FIX_RECOMMENDATION_EMITTED=false
    if ${P2S_STACKX_INSTALLED:-false}; then
        P2S_FIX_RECOMMENDATION_EMITTED=true
        return 0
    fi
    if ${P2S_ALLOW_STACKX:-false}; then
        p2s_stackx_recommendation
        return 0
    fi
    if p2s_november_apt_scope && [ "${P2S_REPOSITORY_REFRESH:-}" = refreshed ] &&
        p2s_fix_blockers_match '|unsupported_os|candidate_fix|no_candidate|'; then
        p2s_november_apt_update
        if [ "${P2S_APT_PLAN:-}" != ready ]; then p2s_stackx_recommendation; fi
        return 0
    fi
    p2s_fix_plan_options
    if ! $P2S_VERIFIED_PROVIDER_PLAN; then p2s_freexian_setup_guidance; fi
    if ! $P2S_FIX_RECOMMENDATION_EMITTED; then p2s_stackx_recommendation; fi
}

p2s_november_apt_scope() {
    ${P2S_NOVEMBER:-false} && [ "${P2S_BACKEND:-}" = deb ] || return 1
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 1 ;; esac
    case "$P2S_DISTRO:${P2S_RELEASE%%.*}:$P2S_RELEASE" in
        debian:1[123]:*|ubuntu:*:22.04|ubuntu:*:24.04|ubuntu:*:26.04|ubuntu:*:26.10) return 0 ;;
        *) p2s_backports_suite >/dev/null ;;
    esac
}

p2s_november_apt_route() {
    local P2S_APT_PHASE_BRANCHES=$2 P2S_APT_INDEXES_REFRESHED=true
    local P2S_APT_CURRENT_PROVIDER_ONLY=false P2S_APT_NATIVE_FALLBACK=false P2S_ALLOW_FREEXIAN=false
    local P2S_DISRUPTIVE=false P2S_ALLOW_SURY_MIGRATION=false P2S_ALLOW_SURY_REPOSITORY=false
    case "$1" in
        current) P2S_APT_CURRENT_PROVIDER_ONLY=true ;;
        distro) P2S_APT_CURRENT_PROVIDER_ONLY=true; P2S_APT_NATIVE_FALLBACK=true ;;
        freexian)
            p2s_freexian_native_scope || return 1
            P2S_ALLOW_FREEXIAN=true ;;
        sury)
            P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true ;;
        backports) p2s_package_deb_update backports; return $? ;;
    esac
    p2s_package_deb_update
}

p2s_november_sury_add_covered() {
    case "$P2S_DISTRO:${P2S_RELEASE%%.*}:$P2S_RELEASE" in
        debian:1[23]:*|ubuntu:*:22.04|ubuntu:*:24.04|ubuntu:*:26.04) ;;
        *) return 1 ;;
    esac
    case "$1" in php5.6|php7.[0-4]|php8.[0-6]) return 0 ;; *) return 1 ;; esac
}

# A source approval covers the named source packages, regardless of the number of APT components.
p2s_november_apt_update() {
    local branch name version arch vendor source source_version route scope components suite build method approved missing reason
    local plan="$P2S_WORK/apt-branch-plan" pending="$P2S_WORK/apt-branch-pending"
    local scope_file="$P2S_WORK/apt-branch-scope" sury_add="$P2S_WORK/apt-sury-add" backports_add="$P2S_WORK/apt-backports-add"
    local log="$P2S_WORK/apt-branch-assessment" P2S_APT_NOVEMBER_POLICY=true P2S_APT_PHASE_BRANCHES=''
    local adding='' available=false unresolved=false source_add_possible negative_pins=false
    local -a component_list
    [ "${P2S_STATE:-N}" != N ] || return 0
    if [ ! -s "$P2S_WORK/deb-source-records" ]; then
        P2S_APT_PLAN=blocked
        p2s_fix_block candidate_provider "No installed PHP source-package records were available. Review the dpkg package inventory and the PHP package publisher before updating."
        return 1
    fi
    p2s_package_deb_preflight && p2s_package_deb_sury_trust_preflight || return 1
    if [ "$P2S_MODE" = fix ]; then p2s_package_deb_refresh_indexes || return 1; fi
    [ "$P2S_REPOSITORY_REFRESH" = refreshed ] || return 1
    if [ -r "$P2S_WORK/apt-policy-records" ] && grep -q '^missing|.*|1$' "$P2S_WORK/apt-policy-records"; then
        negative_pins=true
        p2s_message_print warn "An installed PHP package has no APT candidate and a negative priority. Review the reported APT preferences before adding a PHP repository."
    fi
    if ${P2S_ALLOW_SURY_REPOSITORY:-false}; then adding=sury; fi
    if ${P2S_ALLOW_BACKPORTS_REPOSITORY:-false}; then adding=backports; fi
    suite=$(p2s_backports_suite) || suite=''
    : > "$plan"; : > "$sury_add"; : > "$backports_add"
    while IFS='|' read -r name version arch vendor; do
        p2s_package_is_engine "$name" || continue
        branch=$(p2s_backports_source "$name") || continue
        source=$(awk -F'|' -v n="$name" -v v="$version" -v a="$arch" '$1==n && $2==v && $3==a && !seen[$4,$5]++ {print $4 "|" $5}' "$P2S_WORK/deb-source-records")
        source_version=${source#*|}
        [ "${source%%|*}" = "$branch" ] && [[ "$source_version" != *$'\n'* ]] || continue
        [ "$(p2s_version_package_state "$name" "$version" "$vendor" "$arch" "$branch" "$source_version")" != N ] || continue
        printf '%s\n' "$branch"
    done < "$P2S_WORK/packages" | sort -u > "$pending"
    while IFS= read -r branch; do
        printf '%s\n' "$branch" > "$scope_file"
        available=false; source_add_possible=true
        if $negative_pins; then source_add_possible=false; fi
        for route in current distro freexian sury backports; do
            if (
                P2S_MODE=check; P2S_ASSESSMENT_ONLY=true
                p2s_november_apt_route "$route" "$scope_file"
            ) > "$log" 2>&1 && grep -q '^dss:manifest:cached_update_plan:[^|]*|approved_after_refresh|' "$log"; then
                printf '%s|%s\n' "$branch" "$route" >> "$plan"
                p2s_manifest_record option_assessment "$branch|$route|approved
$(cat "$log")"
                available=true
                break
            fi
            if [ -s "$log" ]; then
                p2s_manifest_record option_assessment "$branch|$route|unavailable
$(cat "$log")"
                if [ "$route" = current ]; then
                    reason=$(sed -n 's/^dss:manifest:blocker:[^|]*|//p' "$log" | head -n 1)
                    case "${reason%%|*}" in
                        transaction_*|dependency_*|removals|package_downgrade|source_authentication)
                            source_add_possible=false
                            p2s_message_print warn "$branch: ${reason#*|}" ;;
                    esac
                fi
            fi
        done
        if $available; then
            if [ "$P2S_MODE" = check ]; then p2s_manifest_record php_branch_update "$branch|$route|configured_source"; fi
            continue
        fi
        unresolved=true
        p2s_manifest_record php_branch_update "$branch|no_verified_configured_source"
        $source_add_possible || continue
        P2S_APT_PHASE_BRANCHES=$scope_file
        if p2s_november_sury_add_covered "$branch" && p2s_command_exists gpg &&
            { p2s_command_exists curl || p2s_command_exists wget; } &&
            (p2s_repository_sury_source_present; [ "$?" -eq 1 ]) &&
            (P2S_ASSESSMENT_ONLY=true; p2s_disruptive_sury_validate_equivalents) > "$log" 2>&1; then
            printf '%s\n' "$branch" >> "$sury_add"
        elif [ -n "$suite" ] && p2s_backports_select_branches "$suite"; then
            while IFS='|' read -r name version arch vendor; do
                p2s_package_is_engine "$name" && [ "$(p2s_backports_source "$name")" = "$branch" ] || continue
                build=$(p2s_backports_build "$suite" "$branch" "$arch") || continue
                components=${build#*|}
                if (
                    P2S_ASSESSMENT_ONLY=true
                    local P2S_BACKPORTS_ADD_KEYRING
                    missing=$(p2s_backports_missing_components "$suite" "$components") && [ -n "$missing" ] &&
                        p2s_backports_add_preflight "$suite" "$components" &&
                        p2s_backports_preview_source "$suite" "$components" "$scope_file"
                ) > "$log" 2>&1; then
                    printf '%s|%s\n' "$branch" "$components" >> "$backports_add"
                    break
                elif [ -s "$log" ]; then
                    p2s_manifest_record option_assessment "$branch|backports_source|unavailable
$(cat "$log")"
                fi
            done < "$P2S_WORK/packages"
        fi
        P2S_APT_PHASE_BRANCHES=''
    done < "$pending"

    if [ "$P2S_MODE" = check ]; then
        if [ -s "$plan" ]; then
            P2S_APT_PLAN=ready
            p2s_fix_recommendation_print existing_provider '--fix' 'APT refreshed the package lists and found an update plan using configured sources. Running the update rechecks each branch before installing.'
        elif [ -s "$pending" ]; then
            P2S_APT_PLAN=blocked
            p2s_message_print warn "No configured APT source passed the PHP package checks for $(paste -sd, "$pending"). See the per-source results in the detailed log."
        fi
        if $unresolved && p2s_repository_repair_assess native-security-source &&
            [ "${P2S_REPOSITORY_REPAIR_STATE:-needed}" = needed ]; then
            p2s_fix_recommendation_print repository_repair '--fix --enable-extra-fixes --add-os-security-repository' 'A matching native security source is missing; fresh repository access and fixed candidates still need verification.'
        fi
        for route in sury backports; do
            case "$route" in
                sury) method=sury_source; scope=$(paste -sd, "$sury_add")
                    approved='--migrate-php-to-sury --add-sury-repository' ;;
                backports) method=debian_php_backports; scope=$(cut -d'|' -f1 "$backports_add" | sort -u | paste -sd, -)
                    approved=--add-debian-php-backports ;;
            esac
            [ -n "$scope" ] || continue
            p2s_manifest_record source_add_scope "$method|$scope"
            reason="Allow adding this signed APT source for $scope if the configured sources still provide no verified update. The new packages must pass verification and APT simulation before installing."
            if [ "$route" = backports ]; then
                reason="The signed Backports index matches the review and contains the equivalent packages for $scope. Fix mode rechecks the source and simulates the host's APT transaction before installing."
            fi
            p2s_fix_recommendation_print "$method" "--fix --enable-extra-fixes $approved --php-source-branches=$scope" "$reason"
        done
        if $unresolved; then p2s_freexian_setup_guidance; fi
        return 0
    fi

    # Reject newly required branches before changing any packages or sources.
    case "$adding" in
        sury) cp "$sury_add" "$P2S_WORK/source-add-branches" || return 1 ;;
        backports) cut -d'|' -f1 "$backports_add" | sort -u > "$P2S_WORK/source-add-branches" || return 1 ;;
    esac
    if [ -n "$adding" ]; then
        printf '%s\n' "$P2S_PHP_SOURCE_BRANCHES" | tr ',' '\n' > "$P2S_WORK/source-add-approved"
        approved=$(grep -Fvx -f "$P2S_WORK/source-add-approved" "$P2S_WORK/source-add-branches")
        if [ -n "$approved" ]; then
            p2s_fix_block provider_migration "The missing $adding source now needs approval for $(printf '%s' "$approved" | tr '\n' ' '). Run a fresh check and select the updated source option."
            return 1
        fi
    fi
    while IFS='|' read -r branch route; do
        printf '%s\n' "$branch" > "$scope_file"
        p2s_manifest_record php_branch_update "$branch|$route|configured_source"
        p2s_november_apt_route "$route" "$scope_file" || return 1
        p2s_package_inventory_collect
        if ${P2S_BLOCKED:-false} || ! awk -F'|' '
            FILENAME==ARGV[1] {selected[$1 "|" $3]=1; next}
            FILENAME==ARGV[2] {if (selected[$4 "|" $3]) pending[$4 "|" $2 "|" $3]=1; next}
            {delete pending[$1 "|" $2 "|" $3]} END {for (package in pending) exit 1}
        ' "$P2S_WORK/apt-selected" "$P2S_WORK/apt-approved" "$P2S_WORK/packages"; then
            p2s_fix_block package_update "Installed package versions differ from the approved $branch plan. Check package state before continuing."
            return 1
        fi
        p2s_package_sources_collect
    done < "$plan"
    if [ -n "$adding" ] && [ -s "$P2S_WORK/source-add-branches" ]; then
        P2S_APT_PHASE_BRANCHES="$P2S_WORK/source-add-branches"
        if [ "$adding" = sury ]; then
            p2s_disruptive_sury_add_repository || return 1
        else
            components=$(cut -d'|' -f2 "$backports_add" | sort -u | paste -sd' ' -)
            read -r -a component_list <<< "$components"
            p2s_backports_source_selection "$suite" "$P2S_APT_PHASE_BRANCHES" || return 1
            p2s_disruptive_backports_add_repository "$suite" "${component_list[@]}" || return 1
        fi
        p2s_package_deb_refresh_indexes || return 1
        if [ "$adding" = backports ]; then p2s_backports_scope_preferences_verified "$suite" || return 1; fi
        p2s_november_apt_route "$adding" "$P2S_APT_PHASE_BRANCHES"
    elif [ -s "$plan" ] || [ ! -s "$pending" ] || ${P2S_RESTART_PENDING:-false}; then
        return 0
    else
        p2s_fix_block candidate_fix "None of the configured APT sources supplied a verified update for $(paste -sd, "$pending"). Run a fresh check for available source options and diagnostics."
        return 1
    fi
}

p2s_backports_scope() {
    ${P2S_NOVEMBER:-false} && [ "${P2S_STATE:-N}" != N ] || return 1
    case "${P2S_PANEL:-}" in ''|none) ;; *) return 1 ;; esac
    p2s_backports_suite >/dev/null
}

# Check preferred methods again after the fix's own refresh. Their assessment never installs anything.
p2s_backports_update_last() {
    local log="$P2S_WORK/backports-preferred.log"
    local P2S_APT_INDEXES_REFRESHED=true
    p2s_package_deb_preflight && p2s_package_deb_sury_trust_preflight && p2s_package_deb_refresh_indexes || return 1
    if (
        P2S_ALLOW_BACKPORTS=false; P2S_MODE=check; P2S_VERIFIED_PROVIDER_PLAN=false; P2S_FIX_RECOMMENDATION_EMITTED=false
        P2S_CHECK_LEGACY_BACKPORTS=true
        p2s_fix_plan_options
        $P2S_VERIFIED_PROVIDER_PLAN || $P2S_FIX_RECOMMENDATION_EMITTED
    ) > "$log" 2>&1; then
        p2s_manifest_record option_assessment "preferred_before_debian_php_backports|$(cat "$log")"
        p2s_fix_block candidate_provider "A preferred PHP update or repository repair is available. Run the check again and use that option first."
        return 1
    fi
    p2s_manifest_record option_assessment "preferred_before_debian_php_backports|$(cat "$log")"
    p2s_package_deb_update backports
}

# Plan using the metadata already on disk. A separate refresh records its outcome.
p2s_fix_plan_options() {
    local name version arch vendor exact=true native_php=false migration_repair='' source_evidence=cached_only plan_blocker
    [ "${P2S_STATE:-N}" != N ] || return 0
    if [ "${P2S_REPOSITORY_REFRESH:-not_refreshed}" = refreshed ]; then source_evidence=refreshed; fi
    case "${P2S_PANEL:-}" in
        cpanel|plesk)
            if ! ${P2S_BLOCKED:-false}; then p2s_fix_recommendation_print existing_provider '--fix' 'Use the detected panel updater for its PHP packages.'; fi
            return 0 ;;
    esac
    if [ "${P2S_BACKEND:-}" != deb ]; then
        if ! ${P2S_BLOCKED:-false}; then p2s_fix_recommendation_print existing_provider '--fix' 'Use the current supported package or panel procedure.'; fi
        return 0
    fi
    if p2s_fix_blockers_match '|package_state|'; then
        p2s_package_deb_repair_audit_collect
        if ${P2S_REPAIR_AUDIT_NEEDED:-false}; then
            if ${P2S_PENDING_PHP_REPAIR_ELIGIBLE:-false}; then
                if [ "$P2S_PHASE" = afterfix ] && ${P2S_PACKAGE_CONFIGURATION_ATTEMPTED:-false}; then
                    p2s_message_print warn "The attempted PHP package configuration is still incomplete. Review the dpkg and service diagnostics, resolve the reported problem, then run --check before trying the repair again."
                    return 0
                fi
                p2s_fix_recommendation_print pending_php '--fix --enable-extra-fixes --configure-pending-php-packages' 'Only recognized pending PHP package configuration was identified; unrelated package repair remains excluded.'
            elif ${P2S_EXACT_PHP_REPAIR_ELIGIBLE:-false}; then
                while IFS='|' read -r name version arch; do
                    if ! p2s_package_deb_exact_candidate_validate "$name" "$version" "$arch"; then exact=false; break; fi
                done < "$P2S_WORK/repair-reinstall"
                if $exact; then p2s_fix_recommendation_print exact_php '--fix --enable-extra-fixes --reinstall-php-same-version' 'Cached metadata has an equivalent exact installed-version PHP candidate; reinstallation retains that version, which needs a separate CVE assessment.'; fi
            fi
            return 0
        fi
    fi
    # Adding a source cannot repair an effective negative pin on an installed PHP package.
    if [ -r "$P2S_WORK/apt-policy-records" ] && grep '^missing|.*|1$' "$P2S_WORK/apt-policy-records" >/dev/null; then
        p2s_message_print warn "Resolve the reported negative APT priorities and recheck package candidates before choosing extra fixes. Repository additions and PHP provider migrations do not remove package pins."
        return 0
    fi
    if [ -s "$P2S_WORK/summary-versions" ] && ! ${P2S_RESTART_PENDING:-false} && p2s_state_has_only_fixed_versions; then return 0; fi
    if ! p2s_fix_blockers_match '|unsupported_os|candidate_provider|no_candidate|repositories|source_authentication|'; then return 0; fi
    if ${P2S_CHECK_LEGACY_BACKPORTS:-false} && [ "$source_evidence" = refreshed ] &&
        p2s_freexian_native_scope && p2s_fix_blockers_match '|unsupported_os|' &&
        (
            P2S_ASSESSMENT_ONLY=true; P2S_MODE=check; P2S_ALLOW_FREEXIAN=true
            P2S_ALLOW_SURY_MIGRATION=false; P2S_ALLOW_SURY_REPOSITORY=false
            p2s_package_deb_update && ${P2S_FREEXIAN_SELECTED:-false}
        ) > "$P2S_WORK/recommend-freexian.log" 2>&1; then
        p2s_manifest_record option_assessment "freexian_elts|$source_evidence
$(cat "$P2S_WORK/recommend-freexian.log")"
        P2S_VERIFIED_PROVIDER_PLAN=true
        return 0
    fi
    if [ -f "$P2S_WORK/recommend-freexian.log" ]; then
        p2s_manifest_record option_assessment "freexian_elts|$source_evidence
$(cat "$P2S_WORK/recommend-freexian.log")"
    fi
    if p2s_repository_repair_assess sury-key && p2s_command_exists gpg &&
        { p2s_command_exists curl || p2s_command_exists wget; } && p2s_repository_sury_key_needs_refresh; then
        if p2s_fix_blockers_match '|repositories|source_authentication|'; then
        p2s_fix_recommendation_print repository_repair '--fix --enable-extra-fixes --refresh-sury-signing-key' 'The standard Sury source uses an expired or mismatched installed key; this recipe replaces only its verified package keyring.'
        return 0
        fi
        migration_repair=' --refresh-sury-signing-key'
    fi
    # Prefer a normal update, including verified necessary native-library upgrades.
    if { ! ${P2S_BLOCKED:-false} || { [ "$source_evidence" = refreshed ] && p2s_fix_blockers_match '|unsupported_os|'; }; } && (
        P2S_ASSESSMENT_ONLY=true; P2S_MODE=check; P2S_ALLOW_SURY_MIGRATION=false
        P2S_ALLOW_SURY_REPOSITORY=false; P2S_ALLOW_FREEXIAN=false; P2S_DISRUPTIVE=false
        P2S_APT_CURRENT_PROVIDER_ONLY=false
        if [ "$source_evidence" = refreshed ]; then P2S_APT_CURRENT_PROVIDER_ONLY=true; fi
        p2s_package_deb_update
    ) > "$P2S_WORK/recommend-plan.log" 2>&1; then
        p2s_manifest_record option_assessment "existing_provider_and_dependencies|$source_evidence
$(cat "$P2S_WORK/recommend-plan.log")"
        if [ "$source_evidence" = refreshed ] && grep -q '^dss:manifest:cached_update_plan:[^|]*|approved_after_refresh|' "$P2S_WORK/recommend-plan.log"; then
            P2S_VERIFIED_PROVIDER_PLAN=true
        fi
        if ${P2S_BLOCKED:-false}; then
            p2s_message_print info "APT found a PHP update plan using the current sources. This operating system requires a manual update."
        elif [ "$source_evidence" = refreshed ]; then
            if $P2S_VERIFIED_PROVIDER_PLAN; then P2S_APT_PLAN=ready; fi
            p2s_fix_recommendation_print existing_provider '--fix' 'APT refreshed the package lists and found an update plan using the existing PHP sources. Running the update rechecks that plan before installing packages.'
        else
            p2s_fix_recommendation_print existing_provider '--fix' 'The cached PHP plan uses existing package sources, including verified necessary native-library upgrades; fix mode will refresh and revalidate candidates.'
        fi
        return 0
    fi
    if [ -f "$P2S_WORK/recommend-plan.log" ]; then
        p2s_manifest_record option_assessment "existing_provider_and_dependencies|$source_evidence
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
    if [ "$source_evidence" = cached_only ] && ! ${P2S_BLOCKED:-false}; then
        p2s_fix_recommendation_print existing_provider '--fix' 'The cached plan is incomplete; refresh and try the configured PHP package repositories before considering third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages.'
    fi
    [ "$source_evidence" = refreshed ] && [ -f "$P2S_WORK/recommend-plan.log" ] || return 0
    # Query, policy and simulation errors need their own repair before considering another publisher.
    plan_blocker=$(sed -n 's/^dss:manifest:blocker:[^|]*|//p' "$P2S_WORK/recommend-plan.log" | head -n 1)
    p2s_message_print info "apt-get update refreshed the package lists."
    if [ -n "$plan_blocker" ]; then
        p2s_message_print warn "${plan_blocker#*|}"
    else
        p2s_message_print warn "The APT plan check ended before reporting a package result. Review the APT diagnostics in the detailed log."
    fi
    case "$plan_blocker" in
        no_candidate\|*|candidate_fix\|*) ;;
        *) P2S_APT_PLAN=blocked; return 0 ;;
    esac
    if ! p2s_november_apt_scope && (
        P2S_ASSESSMENT_ONLY=true; P2S_DISRUPTIVE=true; P2S_ALLOW_SURY_MIGRATION=true
        p2s_disruptive_sury_validate_equivalents
    ) > "$P2S_WORK/recommend-migration.log" 2>&1; then
        if (
            P2S_ASSESSMENT_ONLY=true; P2S_MODE=check; P2S_DISRUPTIVE=true
            P2S_ALLOW_SURY_MIGRATION=true; P2S_ALLOW_SURY_REPOSITORY=false
            p2s_package_deb_update
        ) > "$P2S_WORK/recommend-migration-plan.log" 2>&1; then
            P2S_VERIFIED_PROVIDER_PLAN=true
            p2s_fix_recommendation_print sury_migration "--fix --enable-extra-fixes --migrate-php-to-sury$migration_repair" 'Candidates from the configured Sury source pass the package and dependency checks.'
        elif (p2s_repository_sury_source_present; [ "$?" -eq 1 ]); then
            p2s_fix_recommendation_print sury_source '--fix --enable-extra-fixes --migrate-php-to-sury --add-sury-repository' 'Optional switch from distribution PHP packages to third-party Sury (Debian) or ondrej PHP PPA (Ubuntu) packages: local package identities fit the reviewed scope, but candidates from the missing repository have not been checked.'
        fi
    fi
    if [ -f "$P2S_WORK/recommend-migration.log" ]; then
        p2s_manifest_record option_assessment "sury_migration_identity|$source_evidence
$(cat "$P2S_WORK/recommend-migration.log")"
    fi
    if [ -f "$P2S_WORK/recommend-migration-plan.log" ]; then
        p2s_manifest_record option_assessment "sury_migration_candidate_plan|$source_evidence
$(cat "$P2S_WORK/recommend-migration-plan.log")"
    fi
    return 0
}


p2s_check_refresh_packages() {
    local manager query=check-update manager_version status=0 name version arch vendor log="$P2S_WORK/rpm-availability.log"
    local P2S_MODE=check
    local packages=()
    case "${P2S_PANEL:-}:$P2S_BACKEND" in
        cpanel:*|plesk:*) return 0 ;;
        *:deb|*:rpm) ;;
        *) return 0 ;;
    esac
    [ -s "$P2S_WORK/packages" ] && [ "$(id -u)" = 0 ] || return 0
    while IFS='|' read -r name version arch vendor; do
        p2s_package_is_engine "$name" || continue
        packages[${#packages[@]}]="$name.$arch"
    done < "$P2S_WORK/packages"
    [ "${#packages[@]}" -gt 0 ] || return 0
    if [ "$P2S_STATE" = N ]; then p2s_fix_disk_preflight || return 1; fi
    if [ "$P2S_BACKEND" = deb ]; then
        if ! p2s_command_exists apt-get; then
            p2s_fix_block apt_missing "apt-get is missing. Install or restore APT before checking its repositories."
            return 1
        fi
        p2s_package_deb_sury_trust_preflight && p2s_package_deb_refresh_indexes
        return
    fi
    if p2s_command_exists dnf; then manager=dnf
    elif p2s_command_exists yum; then manager=yum
    else p2s_fix_block rpm_manager "Neither dnf nor yum is installed. Check which package manager this server uses."; return 1
    fi
    if ! p2s_command_run 30 "$manager" --version > "$log" 2>&1; then
        p2s_package_log_report "$log"
        p2s_fix_block rpm_manager "$manager --version failed. Check the installed package manager and rerun the check."
        return 1
    fi
    IFS= read -r manager_version < "$log"
    case "$manager_version" in 'dnf5 version '*) query=check-upgrade ;; esac
    p2s_package_rpm_refresh_indexes "$manager" "$log" || return 1
    [ "$P2S_STATE" != N ] || return 0
    p2s_command_run 90 "$manager" --cacheonly --assumeno "$query" "${packages[@]}" < /dev/null > "$log" 2>&1 || status=$?
    p2s_package_log_report "$log"
    # DNF and YUM return 100 when an update exists, even when no transaction was requested.
    p2s_manifest_record rpm_candidate_query "$manager $query|exit=$status"
    case "$status" in
        0) p2s_message_print warn "$manager $query found no update for the installed PHP packages after refreshing repositories." ;;
        100) p2s_message_print info "$manager $query found newer PHP package builds. See the run log for versions and repositories. A fix attempt checks the publishers and dependency plan before installing." ;;
        124) p2s_fix_block candidate_query "$manager $query timed out after 90 seconds. Review the package-manager log and rerun the check."; return 1 ;;
        *) p2s_fix_block candidate_query "$manager $query failed (exit $status). Review the package-manager log and rerun the check."; return 1 ;;
    esac
}

p2s_fix_report_patchability() {
    local assessment source_scope='from the existing PHP package sources'
    if ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
        source_scope='from the current sources first, with Sury allowed as a fallback'
    fi
    if [ "$P2S_STATE" = N ]; then
        assessment=not_needed
        p2s_message_print info "Automatic update: The PHP check found no update needed for this issue."
    else
        if p2s_fix_preflight; then
            if [ "$P2S_BACKEND" = deb ] && ! p2s_package_deb_preflight; then P2S_BLOCKED=true; fi
        else
            # A failed probe must not become an optimistic prediction even if it had no specific diagnostic.
            P2S_BLOCKED=true
        fi
        if [ "${P2S_MODE:-}" = check ] && p2s_fix_blockers_match '|unsupported_os|'; then
            p2s_check_refresh_packages || P2S_BLOCKED=true
        fi
        if $P2S_BLOCKED; then
            assessment=blocked
            p2s_message_print warn "Automatic update: A local check blocked the PHP update. Resolve the reported problems before running the update."
        elif [ "$P2S_STATE" = Y ] && ! $P2S_UNKNOWN && ! ${P2S_PACKAGE_POLICY_REVIEW:-false} && p2s_command_exists df; then
            assessment=eligible_to_attempt
            p2s_message_print info "Automatic update: The local checks passed. Running the PHP update attempts to install eligible fixes $source_scope. Afterward, review any PHP versions or restarts that still need attention."
        else
            assessment=unknown
            p2s_message_print info "Automatic update: The local checks found no blocker. Running the PHP update refreshes package lists and attempts to install any fixes that pass the package checks. Afterward, review any PHP installations whose patch status is still unverified."
        fi
    fi
    # Fix eligibility does not establish the installed PHP state.
    p2s_manifest_record patchability "$assessment|scope=host_php|repositories=${P2S_REPOSITORY_REFRESH:-not_refreshed}|candidate_fixes=not_verified|vulnerability=$P2S_STATE|inventory_unknown=$P2S_UNKNOWN|package_policy_review=${P2S_PACKAGE_POLICY_REVIEW:-false}"
}

# P2S-MUTATION: Orchestrates package updates and service restarts after preflight checks.
p2s_fix_run() {
    if [ "${P2S_MODE:-fix}" != fix ]; then
        p2s_fix_block mode 'Package updates, repairs and restarts require fix mode.'; return 1
    fi
    P2S_TRANSACTION_ATTEMPTED=false; P2S_SURY_TRANSACTION_ATTEMPTED=false; P2S_BACKPORTS_TRANSACTION_ATTEMPTED=false
    P2S_STACKX_TRANSACTION_ATTEMPTED=false
    P2S_RESTART_ATTEMPTED=false; P2S_PANEL_UPDATE_COMPLETED=false
    P2S_PACKAGE_CONFIGURATION_ATTEMPTED=false; P2S_PACKAGE_REINSTALL_ATTEMPTED=false
    local selected_repairs=false
    if [ "${P2S_REPOSITORY_REPAIR:-none}" != none ] || ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false} || ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}; then selected_repairs=true; fi
    if [ "${P2S_BACKEND:-}" = deb ]; then p2s_package_lock_warn; fi
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
        case "$P2S_BACKEND" in
            deb)
                if ${P2S_ALLOW_STACKX:-false}; then
                    p2s_package_deb_update stackx
                elif p2s_november_apt_scope &&
                    { ${P2S_ALLOW_SURY_REPOSITORY:-false} || ${P2S_ALLOW_BACKPORTS_REPOSITORY:-false} ||
                        { ! ${P2S_ALLOW_BACKPORTS:-false} && ! ${P2S_ALLOW_FREEXIAN:-false} && ! ${P2S_ALLOW_SURY_MIGRATION:-false}; }; }; then
                    p2s_november_apt_update
                elif ${P2S_ALLOW_BACKPORTS:-false}; then
                    p2s_backports_update_last
                elif ${P2S_ALLOW_FREEXIAN:-false} && p2s_freexian_native_scope; then
                    p2s_package_deb_update
                elif ${P2S_DISRUPTIVE:-false} && ${P2S_ALLOW_SURY_MIGRATION:-false}; then
                    p2s_package_deb_update_current_sources_first
                else
                    p2s_package_deb_update
                fi ;;
            rpm) p2s_package_rpm_update ;;
            *) return 1 ;;
        esac
        update_status=$?
    fi
    # Maintainer scripts may already have replaced workers; still verify the saved services.
    local restart_status=0
    # P2S-MUTATION: Replaces workers after an installation attempt or a pending restart.
    if $P2S_TRANSACTION_ATTEMPTED ||
        { $P2S_RESTART_PENDING && ! ${P2S_ALLOW_BACKPORTS:-false} && ! ${P2S_ALLOW_STACKX:-false}; }; then
        p2s_service_restart_and_verify; restart_status=$?
    fi
    p2s_manifest_record fix_commands "update_exit=$update_status|restart_exit=$restart_status|restart_attempted=$P2S_RESTART_ATTEMPTED|pending_php_configuration_attempted=$P2S_PACKAGE_CONFIGURATION_ATTEMPTED|exact_php_reinstall_attempted=$P2S_PACKAGE_REINSTALL_ATTEMPTED"
    [ "$update_status" -eq 0 ] && [ "$restart_status" -eq 0 ]
}

# Command-line entry point

p2s_main() {
    # Update the revision when script behaviour changes; the checksum separately identifies the loaded functions.
    local mode=check result=0 command fix_options=--fix script_revision=2026-11-26.6 check_options=--check
    local P2S_APT_PLAN=
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
    if ${P2S_NOVEMBER:-false}; then
        fix_options="$fix_options --november-2026"
        check_options="$check_options --november-2026"
        p2s_message_print info "Assessing the November 2026 PHP security release."
    fi
    case "$mode" in
        check) p2s_message_print info "Check only: no packages or services will be changed." ;;
        fix)
            # pgb:php-fix-method: Record effective permissions even if preflight blocks the attempt.
            if ${P2S_DISRUPTIVE:-false}; then fix_options="$fix_options --enable-extra-fixes"; fi
            if ${P2S_ALLOW_SURY_MIGRATION:-false}; then fix_options="$fix_options --migrate-php-to-sury"; fi
            if ${P2S_ALLOW_FREEXIAN:-false}; then fix_options="$fix_options --allow-freexian"; fi
            if ${P2S_ALLOW_BACKPORTS:-false}; then fix_options="$fix_options --use-debian-php-backports"; fi
            if ${P2S_ALLOW_SURY_REPOSITORY:-false}; then fix_options="$fix_options --add-sury-repository"; fi
            if ${P2S_ALLOW_BACKPORTS_REPOSITORY:-false}; then fix_options="$fix_options --add-debian-php-backports"; fi
            if ${P2S_ALLOW_STACKX:-false}; then fix_options="$fix_options --use-stackx"; fi
            if [ -n "${P2S_PHP_SOURCE_BRANCHES:-}" ]; then fix_options="$fix_options --php-source-branches=$P2S_PHP_SOURCE_BRANCHES"; fi
            case "${P2S_REPOSITORY_REPAIR:-none}" in
                sury-key) fix_options="$fix_options --refresh-sury-signing-key" ;;
                native-security-source) fix_options="$fix_options --add-os-security-repository" ;;
            esac
            if ${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false}; then fix_options="$fix_options --configure-pending-php-packages"; fi
            if ${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}; then fix_options="$fix_options --reinstall-php-same-version"; fi
            p2s_message_print fixmethod "Attempted $fix_options"
            p2s_message_print info "Update requested. We will check PHP first and only attempt an update if a fix or further verification is needed. Updates and service restarts can interrupt websites." ;;
    esac
    P2S_PHASE=beforefix; P2S_BLOCKED=false; P2S_FIX_FAILED=false
    P2S_REPOSITORY_REFRESH=not_refreshed
    P2S_TRANSACTION_ATTEMPTED=false; P2S_RESTART_ATTEMPTED=false
    P2S_UPDATE_METHOD=; P2S_RETRY_ASSESSMENT=false
    P2S_CPANEL_LAST_LOG_REPORTED=false
    P2S_SURY_REPOSITORY_CREATED=false; P2S_SURY_KEY_CREATED=false
    for command in awk sed grep sort tr head cat date uname id mkdir rm; do
        if ! p2s_command_exists "$command"; then
            p2s_message_print error "Required basic tool $command is unavailable; cannot perform a reliable check."
            p2s_vulnerability_result beforefix '?'
            p2s_vulnerability_result afterfix '?'
            return 1
        fi
    done
    if ! p2s_command_has_timeout && ! p2s_command_has_shell_watchdog && ! p2s_command_exists perl; then
        p2s_message_print error "No supported timeout, sleep or Perl is available to bound commands; a manual check is required."
        p2s_vulnerability_result beforefix '?'
        p2s_vulnerability_result afterfix '?'
        return 1
    fi
    umask 077
    p2s_work_directory_init || return 1
    : > "$P2S_WORK/blocker-keys"
    : > "$P2S_WORK/messages.inventory"
    # Main runs in a subshell so traps/options never leak into a caller that sources this script.
    trap 'p2s_disruptive_backports_cleanup_added_repository; p2s_stackx_cleanup_added_repository; p2s_disruptive_sury_cleanup_added_repository; rm -rf "$P2S_WORK"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export LC_ALL=C
    if ${P2S_NOVEMBER:-false}; then
        p2s_manifest_record schema 'php2shell-v1|CVE_2026_126714|covers=CVE-2026-115560,CVE-2026-126714,CVE-2026-129182,CVE-2026-129289,CVE-2026-129291,CVE-2026-129474,CVE-2026-129481,CVE-2026-129496|rules=2026-11-26'
    else
        p2s_manifest_record schema 'php2shell-v1|CVE_2026_109618|covers=CVE-2026-109618,CVE-2026-109619|rules=2026-10-29'
    fi
    p2s_manifest_record script_revision "$script_revision"
    p2s_manifest_record source_preservation 'policy=current_publisher_fixes_first|script_repository_changes=explicit_opt_in_only|APT_Sury_candidates=provider_branch_architecture_and_exact_version_guarded|RPM_vendor_changes=disabled|panel_transactions_require_separate_review'
    p2s_manifest_record dependency_policy 'required_runtime_libraries|verified_APT_and_DNF4_additions|reviewed_APT_upgrades|hard_dependencies_only|no_removals_or_downgrades'
    p2s_manifest_record disruptive_options "enabled=${P2S_DISRUPTIVE:-false}|allow_sury_migration=${P2S_ALLOW_SURY_MIGRATION:-false}|allow_sury_repository=${P2S_ALLOW_SURY_REPOSITORY:-false}|repository_repair=${P2S_REPOSITORY_REPAIR:-none}|pending_php_configuration=${P2S_ALLOW_PENDING_PHP_CONFIGURATION:-false}|exact_php_reinstall=${P2S_ALLOW_EXACT_PHP_REINSTALL:-false}"
    if ${P2S_NOVEMBER:-false}; then
        p2s_manifest_record configured_provider_policy 'eligible_APT_branches|configured_publisher_fallback_enabled|source_additions_require_approval'
    fi
    if ${P2S_ALLOW_FREEXIAN:-false}; then p2s_manifest_record freexian_opt_in 'enabled|existing_signed_ELTS_only'; fi
    p2s_manifest_record bash "$BASH_VERSION"
    # SSH can deliver source on stdin; $0 would identify Bash, not the delivered script.
    # Record optional cksum output for comparing the loaded functions between runs.
    if p2s_command_exists cksum; then
        p2s_manifest_record function_checksum "$(declare -f | cksum)"
    else
        p2s_manifest_record function_checksum unavailable
    fi
    for command in timeout sleep perl mktemp dpkg-query dpkg apt-get apt-cache rpm dnf yum pacman vercmp wget curl gpg sha256sum systemctl service; do
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
    if [ "$P2S_STATE" = N ] && p2s_fix_blockers_match '|unsupported_os|'; then
        p2s_check_refresh_packages
    fi
    if [ "$mode" = check ]; then p2s_fix_report_patchability; p2s_fix_recommend_options; fi
    p2s_vulnerability_result beforefix "$P2S_STATE"
    if [ "$mode" = fix ] && [ "$P2S_STATE" != N ]; then
        # Share the legacy lock so scripts deployed under either name cannot patch concurrently.
        if ! mkdir /var/run/rh-php2shell.lock 2>/dev/null; then
            p2s_fix_block lock "Could not acquire /var/run/rh-php2shell.lock. Check for a running DePHP2Shell update and inspect the lock directory before retrying."
            result=1
        else
            trap 'p2s_disruptive_backports_cleanup_added_repository; p2s_stackx_cleanup_added_repository; p2s_disruptive_sury_cleanup_added_repository; rmdir /var/run/rh-php2shell.lock; rm -rf "$P2S_WORK"' EXIT
            if ${P2S_NOVEMBER:-false} && [ -r "$P2S_WORK/packages" ]; then
                cp "$P2S_WORK/packages" "$P2S_WORK/packages.before"
            fi
            # P2S-MUTATION: Fix-only entry into package updates and service restarts.
            if ! p2s_fix_run; then result=1; fi
            p2s_disruptive_backports_cleanup_added_repository
            p2s_stackx_cleanup_added_repository
            P2S_PHASE=afterfix
            if [ "$result" -ne 0 ]; then P2S_FIX_FAILED=true; fi
            p2s_inventory_collect_and_assess
            # Fresh masters may differ after package scripts/restarts. Check their actual configurations
            # for extension-loader warnings too; -n version probes intentionally skip php.ini extensions.
            if $P2S_TRANSACTION_ATTEMPTED && ! p2s_service_preflight; then result=1; P2S_FIX_FAILED=true; fi
            if [ "$result" -ne 0 ] && [ "$P2S_STATE" = N ]; then P2S_STATE='?'; fi
        fi
    fi
    p2s_vulnerability_result afterfix "$P2S_STATE"
    if [ "$mode" = fix ] && [ "$P2S_STATE" != N ]; then
        # Reassess current blockers without carrying consent or stale failures into retry advice.
        (
            P2S_MODE=check; P2S_BLOCKED=false; : > "$P2S_WORK/blocker-keys"
            P2S_DISRUPTIVE=false; P2S_ALLOW_SURY_MIGRATION=false; P2S_ALLOW_SURY_REPOSITORY=false
            P2S_ALLOW_FREEXIAN=false
            P2S_ALLOW_BACKPORTS=false; P2S_ALLOW_BACKPORTS_REPOSITORY=false; P2S_PHP_SOURCE_BRANCHES=''
            P2S_ALLOW_STACKX=false
            P2S_ALLOW_PENDING_PHP_CONFIGURATION=false; P2S_ALLOW_EXACT_PHP_REINSTALL=false
            P2S_REPOSITORY_REPAIR=none
            P2S_PHASE=afterfix
            P2S_RETRY_ASSESSMENT=true
            p2s_inventory_collect_and_assess
            p2s_fix_check_distro_recipe
            if p2s_fix_preflight; then
                if [ "$P2S_BACKEND" = deb ]; then p2s_package_deb_preflight; fi
            fi
            if [ "$P2S_REPOSITORY_REFRESH" = not_refreshed ] && p2s_fix_blockers_match '|unsupported_os|'; then
                p2s_check_refresh_packages
            fi
            P2S_FIX_RECOMMENDATION_EMITTED=false
            p2s_fix_recommend_options
            if ! $P2S_FIX_RECOMMENDATION_EMITTED; then
                p2s_message_print warn "This script could not finish the PHP fix. Resolve the reported problems, then run $check_options again to reassess the server."
            fi
        )
        if ! $P2S_TRANSACTION_ATTEMPTED && ! $P2S_RESTART_ATTEMPTED; then
            if ${P2S_SEPARATE_ENVIRONMENT_REVIEW:-false} && p2s_state_has_only_fixed_versions; then
                p2s_message_print warn "Automatic changes were skipped. The assessed host PHP versions have verified fixes, but containers or separate application environments still require review. No PHP package installation or service restart was attempted. Review those environments and any other reported blockers; rerunning a host package update alone will not resolve the separate-environment check."
            else
                p2s_message_print error "The reported blockers stopped the PHP update. No PHP package installation or service restart was attempted."
            fi
            p2s_manifest_record fix_outcome 'blocked|package_install_attempted=false|service_restart_attempted=false'
        else
            if [ "$result" -eq 0 ] && [ "$P2S_STATE" = '?' ]; then
                p2s_message_print error "The update attempt finished. Review the remaining verification warnings to identify which PHP installations still need checking."
            elif [ "$result" -eq 0 ] && [ "$P2S_STATE" = Y ]; then
                p2s_message_print error "At least one PHP installation is still vulnerable after the update attempt. Review the PHP versions needing attention."
            else
                p2s_message_print error "The update could not be completed or verified. Packages or services may have changed. Review the messages and check your websites before retrying."
            fi
            p2s_manifest_record fix_outcome "incomplete|package_install_attempted=$P2S_TRANSACTION_ATTEMPTED|service_restart_attempted=$P2S_RESTART_ATTEMPTED"
        fi
        result=1
    fi
    p2s_summary_print_result
    p2s_fix_print_exposure_advice
    return "$result"
}

# Public command line; the inspection/update engine retains its structured output.

p2s_usage_print() {
    cat <<'EOF'
Usage: dephp2shell.sh [--check|--fix] [--enable-extra-fixes] [options]

  --check           Check PHP and refresh enabled APT, DNF or YUM repositories for
                    managed PHP. Skips package installation and service restarts (default).
  --fix             Refresh package lists, attempt allowed PHP updates and restart supported services.
                    Include verified required runtime libraries from reviewed sources.
                    Other applications may share these libraries. A broad OS upgrade requires separate maintenance.
                    November: keep the current publisher where possible, then try eligible configured sources.
                    Community Debian PHP Backports is the last resort for verified vulnerable branches.
  --november-2026   Assess the November security release. The default assesses October PHP2Shell.
  --enable-extra-fixes
                    Permit only the extra methods selected below; it does not bypass safety checks.
                    Implies --fix unless --check is explicit. Extra methods are disabled by default.
  --migrate-php-to-sury
                    Apply verified fixes from the current PHP publishers first. Allow eligible branches
                    without a verified current-source fix to switch to Sury (Debian) or the ondrej PHP PPA (Ubuntu).
                    Keep the PHP branch; download through an existing authenticated APT source.
                    This flag adds no repository. Switching PHP package publishers still needs application testing.
  --add-sury-repository
                    Also allow a matching source, dedicated verified signing key and scoped APT preference if needed.
                    Sources: packages.sury.org/php or ppa.launchpadcontent.net/ondrej/php/ubuntu.
                    Requires --migrate-php-to-sury and, for November, --php-source-branches.
                    New files remain after a migration install attempt
                    for recovery and future updates. An earlier current-source update does not retain them.
  --allow-freexian
                    Allow a signed Freexian Extended LTS feed already configured on Debian 9, 10 or 11.
                    Keep the reviewed native PHP branch. Prefer an eligible Debian build at the same
                    APT priority. Requires --november-2026 and --enable-extra-fixes.
  --use-debian-php-backports
                    Legacy explicit option for the existing signed community feed.
  --add-debian-php-backports
                    Add the reviewed signed community repository or missing components for PHP branches
                    without an eligible configured update. Requires --november-2026 and --enable-extra-fixes.
  --use-stackx      Configure the signed StackX feed if needed, then update the selected PHP
                    branches on Debian 9–11 amd64. Requires --november-2026 and --enable-extra-fixes.
  --php-source-branches=php5.6,php7.4
                    Branch scope reported by the latest November check for StackX or a third-party source addition.
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
  --output FORMAT   human (default) or machine (structured records for integrations).
  --log-dir DIR     Save full diagnostics in a private timestamped subdirectory of DIR.
  --color WHEN      auto (default), always or never; only human console accents.
  --no-color        Disable colour; bold is controlled separately.
  --bold WHEN       auto (default), always or never; emphasise labels and results.
  --no-bold         Disable bold emphasis.
  --help, -h        Show this help without inspecting or changing the server.

Linux only. Other operating systems exit before inventory or log creation.
DP2S_OUTPUT, DP2S_LOG_DIR, DP2S_COLOR and DP2S_BOLD set defaults.
DP2S_MIGRATE_PHP_TO_SURY, DP2S_ADD_SURY_REPOSITORY, DP2S_ALLOW_FREEXIAN, DP2S_USE_DEBIAN_PHP_BACKPORTS,
DP2S_CONFIGURE_PENDING_PHP_PACKAGES, DP2S_REINSTALL_PHP_SAME_VERSION and
DP2S_UPGRADE_REQUIRED_PHP_LIBRARIES accept true/false, yes/no or 1/0 (default false).
DP2S_REFRESH_SURY_SIGNING_KEY and DP2S_ADD_OS_SECURITY_REPOSITORY are also Boolean defaults (false).
--enable-extra-fixes is command-line consent only.
Method settings require --enable-extra-fixes. Checks refresh package metadata
without installing packages, adding repositories or restarting services.
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
    # Stream progress and keep the closing summary together.
    local label marker result='' next_action=''
    while IFS= read -r line || [ -n "$line" ]; do
        label=''; marker=''
        case "$line" in
            'dss:fixmethod: Attempted '*) continue ;;
            dss:info:*|dss:attemptingfix:*|dss:fixmethod:*) ;;
            dss:warn:*) label='Warning:'; marker=$marker_warning ;;
            dss:error:*) label='Error:'; marker=$marker_error ;;
            *) continue ;;
        esac
        message=${line#dss:}; message=${message#*:}; message=${message# }
        case "$message" in
            Result:*) result="$marker${emphasis}Result:$emphasis_reset${message#Result:}" ;;
            'Next action:'*) next_action="${emphasis}Next action:$emphasis_reset${message#Next action:}" ;;
            *)
                if [ -n "$label" ]; then
                    printf '%s%s%s%s %s\n' "$marker" "$emphasis" "$label" "$emphasis_reset" "$message" || return 1
                else
                    printf '%s\n' "$message" || return 1
                fi ;;
        esac
    done
    if [ -n "$result" ]; then printf '%s\n' "$result" || return 1; fi
    if [ -n "$next_action" ]; then printf '%s\n' "$next_action" || return 1; fi
}

p2s_cli() {
    local mode=check action='' output="${DP2S_OUTPUT:-human}" log_root="${DP2S_LOG_DIR:-}"
    local option value run_directory log_file stamp status permissions log_requested=false disruptive=false
    local color="${DP2S_COLOR:-auto}" bold="${DP2S_BOLD:-auto}"
    local P2S_DISRUPTIVE=false P2S_ALLOW_SURY_MIGRATION="${DP2S_MIGRATE_PHP_TO_SURY:-false}" P2S_ALLOW_SURY_REPOSITORY="${DP2S_ADD_SURY_REPOSITORY:-false}"
    local P2S_ALLOW_PENDING_PHP_CONFIGURATION="${DP2S_CONFIGURE_PENDING_PHP_PACKAGES:-false}"
    local P2S_ALLOW_FREEXIAN="${DP2S_ALLOW_FREEXIAN:-false}"
    local P2S_ALLOW_BACKPORTS="${DP2S_USE_DEBIAN_PHP_BACKPORTS:-false}"
    local P2S_ALLOW_STACKX="${DP2S_USE_STACKX:-false}" P2S_STACKX_INSTALLED=false
    local P2S_ALLOW_BACKPORTS_REPOSITORY="${DP2S_ADD_DEBIAN_PHP_BACKPORTS:-false}" P2S_PHP_SOURCE_BRANCHES=''
    local P2S_ALLOW_EXACT_PHP_REINSTALL="${DP2S_REINSTALL_PHP_SAME_VERSION:-false}"
    local refresh_sury_signing_key="${DP2S_REFRESH_SURY_SIGNING_KEY:-false}"
    local add_os_security_repository="${DP2S_ADD_OS_SECURITY_REPOSITORY:-false}"
    local P2S_REPOSITORY_REPAIR=none
    local P2S_NOVEMBER=false
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
            --november-2026) P2S_NOVEMBER=true ;;
            --enable-extra-fixes) disruptive=true ;;
            --migrate-php-to-sury) P2S_ALLOW_SURY_MIGRATION=true ;;
            --add-sury-repository) P2S_ALLOW_SURY_REPOSITORY=true ;;
            --migrate-php-to-sury=*) P2S_ALLOW_SURY_MIGRATION=${1#--migrate-php-to-sury=} ;;
            --add-sury-repository=*) P2S_ALLOW_SURY_REPOSITORY=${1#--add-sury-repository=} ;;
            --allow-freexian) P2S_ALLOW_FREEXIAN=true ;;
            --allow-freexian=*) P2S_ALLOW_FREEXIAN=${1#--allow-freexian=} ;;
            --use-debian-php-backports) P2S_ALLOW_BACKPORTS=true ;;
            --use-debian-php-backports=*) P2S_ALLOW_BACKPORTS=${1#--use-debian-php-backports=} ;;
            --use-stackx) P2S_ALLOW_STACKX=true ;;
            --use-stackx=*) P2S_ALLOW_STACKX=${1#--use-stackx=} ;;
            --add-debian-php-backports) P2S_ALLOW_BACKPORTS_REPOSITORY=true ;;
            --add-debian-php-backports=*) P2S_ALLOW_BACKPORTS_REPOSITORY=${1#--add-debian-php-backports=} ;;
            --php-source-branches=*) P2S_PHP_SOURCE_BRANCHES=${1#--php-source-branches=} ;;
            --configure-pending-php-packages) P2S_ALLOW_PENDING_PHP_CONFIGURATION=true ;;
            --reinstall-php-same-version) P2S_ALLOW_EXACT_PHP_REINSTALL=true ;;
            --configure-pending-php-packages=*) P2S_ALLOW_PENDING_PHP_CONFIGURATION=${1#--configure-pending-php-packages=} ;;
            --reinstall-php-same-version=*) P2S_ALLOW_EXACT_PHP_REINSTALL=${1#--reinstall-php-same-version=} ;;
            --refresh-sury-signing-key) refresh_sury_signing_key=true ;;
            --refresh-sury-signing-key=*) refresh_sury_signing_key=${1#--refresh-sury-signing-key=} ;;
            --add-os-security-repository) add_os_security_repository=true ;;
            --add-os-security-repository=*) add_os_security_repository=${1#--add-os-security-repository=} ;;
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
    if ! P2S_ALLOW_SURY_MIGRATION=$(p2s_option_boolean "$P2S_ALLOW_SURY_MIGRATION") ||
        ! P2S_ALLOW_SURY_REPOSITORY=$(p2s_option_boolean "$P2S_ALLOW_SURY_REPOSITORY") ||
        ! P2S_ALLOW_FREEXIAN=$(p2s_option_boolean "$P2S_ALLOW_FREEXIAN") ||
        ! P2S_ALLOW_BACKPORTS=$(p2s_option_boolean "$P2S_ALLOW_BACKPORTS") ||
        ! P2S_ALLOW_STACKX=$(p2s_option_boolean "$P2S_ALLOW_STACKX") ||
        ! P2S_ALLOW_BACKPORTS_REPOSITORY=$(p2s_option_boolean "$P2S_ALLOW_BACKPORTS_REPOSITORY") ||
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
    if $add_os_security_repository; then P2S_REPOSITORY_REPAIR='native-security-source'; fi
    if $P2S_ALLOW_SURY_REPOSITORY && ! $P2S_ALLOW_SURY_MIGRATION; then
        printf '%s\n' '--add-sury-repository also requires --migrate-php-to-sury.' >&2; return 64
    fi
    if $P2S_ALLOW_BACKPORTS_REPOSITORY; then
        if ! $P2S_NOVEMBER; then printf '%s\n' '--add-debian-php-backports requires --november-2026.' >&2; return 64; fi
        if $P2S_ALLOW_SURY_MIGRATION || $P2S_ALLOW_BACKPORTS || $P2S_ALLOW_FREEXIAN || [ "$P2S_REPOSITORY_REPAIR" != none ]; then
            printf '%s\n' 'Choose the Debian PHP Backports repository addition on its own.' >&2; return 64
        fi
    fi
    if $P2S_ALLOW_STACKX; then
        if ! $P2S_NOVEMBER; then printf '%s\n' '--use-stackx requires --november-2026.' >&2; return 64; fi
        if $P2S_ALLOW_SURY_MIGRATION || $P2S_ALLOW_BACKPORTS || $P2S_ALLOW_BACKPORTS_REPOSITORY ||
            $P2S_ALLOW_FREEXIAN || $P2S_ALLOW_PENDING_PHP_CONFIGURATION || $P2S_ALLOW_EXACT_PHP_REINSTALL ||
            [ "$P2S_REPOSITORY_REPAIR" != none ]; then
            printf '%s\n' 'Choose StackX on its own.' >&2; return 64
        fi
    fi
    if $P2S_NOVEMBER && { $P2S_ALLOW_SURY_REPOSITORY || $P2S_ALLOW_BACKPORTS_REPOSITORY || $P2S_ALLOW_STACKX; }; then
        if $P2S_ALLOW_FREEXIAN || [ "$P2S_REPOSITORY_REPAIR" != none ]; then
            printf '%s\n' 'Choose a single source addition per attempt.' >&2; return 64
        fi
        if ! printf '%s\n' "$P2S_PHP_SOURCE_BRANCHES" | grep -Exq 'php(5|[0-9][.][0-9])(,php(5|[0-9][.][0-9]))*' ||
            [[ "$P2S_PHP_SOURCE_BRANCHES" == *$'\n'* ]] ||
            [ -n "$(printf '%s\n' "$P2S_PHP_SOURCE_BRANCHES" | tr ',' '\n' | sort | uniq -d)" ]; then
            printf '%s\n' 'Use --php-source-branches with the branch list from a fresh check.' >&2; return 64
        fi
    elif [ -n "$P2S_PHP_SOURCE_BRANCHES" ]; then
        printf '%s\n' '--php-source-branches is for November third-party repository additions or StackX.' >&2; return 64
    fi
    if $P2S_ALLOW_FREEXIAN && ! $P2S_NOVEMBER; then
        printf '%s\n' '--allow-freexian requires --november-2026.' >&2; return 64
    fi
    if $P2S_ALLOW_BACKPORTS; then
        if ! $P2S_NOVEMBER; then printf '%s\n' '--use-debian-php-backports requires --november-2026.' >&2; return 64; fi
        if $P2S_ALLOW_SURY_MIGRATION || $P2S_ALLOW_FREEXIAN || $P2S_ALLOW_PENDING_PHP_CONFIGURATION ||
            $P2S_ALLOW_EXACT_PHP_REINSTALL || [ "$P2S_REPOSITORY_REPAIR" != none ]; then
            printf '%s\n' 'Choose the Debian PHP Backports fallback on its own.' >&2; return 64
        fi
    fi
    if $P2S_ALLOW_SURY_MIGRATION || $P2S_ALLOW_FREEXIAN || $P2S_ALLOW_BACKPORTS || $P2S_ALLOW_BACKPORTS_REPOSITORY || $P2S_ALLOW_STACKX || $P2S_ALLOW_PENDING_PHP_CONFIGURATION ||
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
                printf '%s\n' 'dss:error: DePHP2Shell requires Linux. No check or update was started.'
                p2s_vulnerability_result beforefix '?'
                p2s_vulnerability_result afterfix '?'
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
    if [ "$output" = human ]; then printf 'Detailed log: %s\n' "$log_file" >&2; fi
    return "$status"
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ] && ! (return 0 2>/dev/null); then
    (p2s_cli "$@")
    exit $?
fi
