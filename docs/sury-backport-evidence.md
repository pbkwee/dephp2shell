# Sury backport evidence for the original PHP2Shell CVEs

Reviewed 25 October 2026, with Debian 11 added 27 October 2026, New Zealand time. This review covers
CVE-2026-109618 and CVE-2026-109619. Other PHP vulnerabilities, including
CVE-2026-115560, require separate assessment.

## Bounded recognition rules

Use exact versions, source identity and package architecture together.
Do not turn these observations into an unrestricted minimum-version rule.
Only `amd64` binary indexes were verified in this review.
The checked suites are Debian 11/12/13 and Ubuntu 22.04/24.04.

For Debian, substitute `N=11`, `N=12` or `N=13` in the complete version below.
The corresponding source package is `php` followed by the branch.
The epoch is significant for PHP 7.4 and PHP 8.0.

| Branch | Exact Debian source/binary version |
| --- | --- |
| 5.6 | `5.6.40-105+0~20261022.135+debianN~1.gbp37a17e` |
| 7.0 | `7.0.33-93+0~20261022.119+debianN~1.gbp952195` |
| 7.1 | `7.1.33-81+0~20261022.128+debianN~1.gbpa88ccf` |
| 7.2 | `7.2.34-66+0~20261021.122+debianN~1.gbpe0bcd4` |
| 7.3 | `7.3.33-35+0~20261021.144+debianN~1.gbpecf76f` |
| 7.4 | `1:7.4.33-31+0~20261021.121+debianN~1.gbpe9c428` |
| 8.0 | `1:8.0.30-25+0~20261021.88+debianN~1.gbpabebea` |
| 8.1 | `8.1.34-9+0~20261021.82+debianN~1.gbp4e430a` |

For the Ubuntu PPA, substitute `U=22.04` or `U=24.04`.
These are Launchpad PPA versions, not packages.sury.org Ubuntu mirror versions.
Do not substitute one repository's version pattern for the other.

| Branch | Exact Ubuntu PPA source/binary version |
| --- | --- |
| 5.6 | `5.6.40-105+ubuntuU.1+deb.sury.org+1` |
| 7.0 | `7.0.33-92+ubuntuU.1+deb.sury.org+1` |
| 7.1 | `7.1.33-80+ubuntuU.1+deb.sury.org+1` |
| 7.2 | `7.2.34-66+ubuntuU.1+deb.sury.org+1` |
| 7.3 | `7.3.33-35+ubuntuU.1+deb.sury.org+1` |
| 7.4 | `1:7.4.33-31+ubuntuU.1+deb.sury.org+1` |
| 8.0 | `1:8.0.30-25+ubuntuU.1+deb.sury.org+1` |
| 8.1 | `8.1.34-9+ubuntuU.1+deb.sury.org+1` |

Authenticate the installed binary through its package provenance and reviewed
source/version tuple. Record package names, maintainer identities, version
suffixes and configured repositories as supporting observations.
A new installation must use authenticated APT metadata and the exact reviewed
source/version tuple. Ordinary updates keep the existing package publisher and branch;
switching PHP package publishers requires its separate explicit opt-ins and keeps the branch.
Keep ordinary runtime ownership, transaction-scope and service-restart checks.
An already-installed package with unresolved provenance needs a separate
provenance check, including when its version string matches a reviewed build.

## Authentication and source-to-binary chain

The review used downloaded metadata without installing keys or packages or changing repositories.

Debian metadata used the keyring extracted from the
[official archive keyring package](https://packages.sury.org/debsuryorg-archive-keyring.deb),
as linked by the [Sury's setup instructions](https://packages.sury.org/php/README.txt).
`gpgv` returned `VALIDSIG` for fingerprint
`15058500A0235D97F5D10063B188E2B695BD4743` on both Debian `InRelease` files.
Trust was bootstrapped through the official HTTPS endpoint, not an independent
out-of-band key exchange.

Ubuntu metadata used the fingerprint published on the
[official PPA page](https://launchpad.net/~ondrej/+archive/ubuntu/php):
`B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6`.
The corresponding public key was fetched from Ubuntu's HTTPS keyserver.
Both PPA `InRelease` files returned `VALIDSIG` for that exact fingerprint.
They also carried an additional signature whose key was unavailable locally.
That second signature was not used as evidence; the known-key signature validated.
Do not ignore a failed or absent known-key signature on a future review.

For every suite and branch listed above, the review checked this chain:

1. Validate the repository's `InRelease` signature with the expected key.
2. Match compressed `main/source/Sources.gz` and `main/binary-amd64/Packages.gz`
   sizes and SHA256 digests to that signed release.
3. Match the Debian packaging archive's size and SHA256 to the source index.
4. Confirm the fix patch is enabled in `debian/patches/series`.
5. Match binary package `Source` and `Version` fields to that reviewed source.
6. Download each of the 32 `phpX.Y-common` binaries, match its SHA256 to the
   signed binary index, and verify its actual control source/version/architecture.

The signed indexes declare matching engine/SAPI packages, including the common,
CLI, FPM and Apache-module packages. Recognition must still check each installed
engine/SAPI; one fixed branch does not cover other branches on the same server.

Repository metadata URLs:

| Suite | Signed release |
| --- | --- |
| Debian 11 | [bullseye InRelease](https://packages.sury.org/php/dists/bullseye/InRelease) |
| Debian 12 | [bookworm InRelease](https://packages.sury.org/php/dists/bookworm/InRelease) |
| Debian 13 | [trixie InRelease](https://packages.sury.org/php/dists/trixie/InRelease) |
| Ubuntu 22.04 | [jammy InRelease](https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/jammy/InRelease) |
| Ubuntu 24.04 | [noble InRelease](https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/noble/InRelease) |

These URLs change as packages are published. The captured release SHA256 values
below identify the exact metadata reviewed. Source and binary index digests are
inside those signed releases.

| Suite | Release date UTC | Captured InRelease SHA256 |
| --- | --- | --- |
| bullseye | 2026-10-26 03:01:30 | `c917dacbe0326b1cf3b722db9a376d3dbeb0a41f632ef3cca6e48b67e4ed0024` |
| bookworm | 2026-10-24 18:01:25 | `b6b61677fdba1bb7815c6182bbcdbb326c91fb162cbfba47aa559ab75b7d96d1` |
| trixie | 2026-10-24 17:01:28 | `ef50e143a914304505a7a779c5577935ea4e30368235b9f94c4584c88e7bb7cc` |
| jammy | 2026-10-22 14:42:33 | `5178c2db6914b9ea1fb0af7c06e7afdf7d4fe1bf354cfdb96dda05ba0978a4b7` |
| noble | 2026-10-22 14:42:20 | `64dddef922a5c9c459bdea480a92ebdcd8d44b2faf38518b3a3c535793b40051` |

## Debian 11 extension

The bullseye review repeated the signed release, source-index and amd64 binary-index
checks using the same expected signing key. All eight enabled PHP2Shell fix patches
are byte-identical to the corresponding bookworm patches. The downloaded eight
`phpX.Y-common` binaries matched their signed-index SHA256 and size, and their actual
package control fields matched the expected source, version and architecture.
The signed index also declares matching CLI, FPM, CGI and Apache-module packages
for each reviewed branch.

The bullseye compressed index SHA256 values were:

- `main/source/Sources.gz`: `0b660d7c5e0dcb3a57fab9630e2a737b3efdceaec155a44d1ffb3c4e439d185c`.
- `main/binary-amd64/Packages.gz`: `aab6e38bee9f5a95adadc960fea309264636e4761d81c2fb5d7c9c77a3832f50`.

This verifies the listed PHP fixes. Check ongoing support for the rest of the
Debian 11 system separately. Ordinary updates remain limited to existing Sury engines with candidate,
package-source and restart checks. Native Debian PHP requires the separate explicit
opt-ins for switching PHP package publishers; another OS suite must never be substituted for bullseye.

## Comparison with PHP's own fixes

The [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-5)
links exceptional minimal source backports for EOL PHP 7.4, 8.0 and 8.1.
These are distinct from supported upstream releases.
The [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
explain the two failure mechanisms.

The reviewed upstream backport commits are:

- [PHP 7.4: 712e60f9](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2).
- [PHP 8.0: 82f8f31b](https://github.com/php/php-src/commit/82f8f31b16a035c1b67cc253e79f7cc288f4cc20).
- [PHP 8.1: 1d7dec17](https://github.com/php/php-src/commit/1d7dec178a094e6e75b229ce22754045f8c6070a).

The Sury 8.0 and 8.1 patches preserve those upstream code changes.
Differences are existing unsigned-character `ctype` context, patch offsets and
whitespace. PHP 8.1 also removes trailing whitespace in an unrelated comment.
The Sury 7.4 patch omits the new multipart-limit hunks because an earlier enabled
patch, `0062-Introduce-max_multipart_body_parts-INI.patch`, supplies that limit.
It otherwise preserves the upstream fix, with equivalent context adjustments.

The older Sury patches explicitly port the PHP 7.4 backport.
Their reviewed mechanisms include immediate worker termination on allocation
failure/overflow, stale handler and request-state resets, disabling early session
upload-progress handling, and safer multipart/GPC allocation.
PHP 5.6 uses its older hash-table and TSRM APIs.
PHP 7.0-7.2 use `zend_API.c` for singleton array creation.
PHP 7.0/7.1 place handler resets after their older shutdown cleanup blocks.
PHP 7.2/7.3 account for their different object-store shutdown order.
The review authenticated and inspected these vendor adaptations. Their
correctness across all old-branch execution paths relies on vendor assurance.

The fix patches for 5.6, 7.2, 7.3, 7.4, 8.0 and 8.1 are byte-identical across
the original four reviewed suites. PHP 7.0/7.1 PPA patch headers differ from Debian only
in prose explaining the pre-existing multipart limit; their code hunks agree.
An exact recognition rule therefore records an authenticated vendor backport.
The older branches remain EOL upstream, and independent exploit validation
remains outside this review.

The minimal backport has observable behavior changes: allocation failure can
terminate a worker immediately, and session upload-progress handling is disabled.
Those differences are part of the upstream EOL strategy. Do not promise normal
OOM request cleanup or preservation of session upload-progress functionality.

## Review limits

The review authenticated Sury's declared source-to-binary relationship
through signed indexes and package identity. Exploit testing, package builds,
reproducible-build verification, application compatibility testing and service
restarts remain outside its scope.
Other architectures, suites, version revisions and repository mirrors remain
outside this bounded review. New revisions need renewed evidence.
