# StackX package evidence

The November check recognises all 30 exact amd64 source revisions in the
25 November 2026 main release for Debian 9 Stretch, 10 Buster and 11 Bullseye.
The binary version and its recorded source package and version must match.
Experimental repositories use separate builds.

Verified all three release signatures against fingerprint
`AF97 ED98 AACE 4CE1 29A0 3B6E 2C97 36B5 93BA BF7F` and matched the source
descriptors, original tarballs and packaging archives to the signed source
indexes. Applied each distribution's full Debian patch series and checked
the November fixes in the resulting trees. The SOAP fix overlapped later
cleanup changes in some trees. The effective code retains the DTD until
document cleanup.

- PHP 5.6 through 8.1 disable session upload progress in code for CVE-2026-115560.
  PHP 8.2 through 8.5 carry the upstream session fix.
- Stretch and Buster use HTTP parsers that predate the folded-header backport
  affected by CVE-2026-127960. Bullseye PHP 7.4 and newer carry its fix.
- The older FPM trees predate the delayed cleanup affected by CVE-2026-129291.
  The affected branches remove worker events before closing and clearing their
  descriptors.
- The signed binary index identifies the archives allowed in an APT transaction.
  Installed assessment uses the exact build identity and checks the running PHP
  processes separately.

[PHP November release changelog](https://www.php.net/ChangeLog-8.php) ·
[HTTP advisory](https://github.com/php/php-src/security/advisories/GHSA-mmf9-xm3v-hg2x) ·
[FPM advisory](https://github.com/php/php-src/security/advisories/GHSA-jm4m-qfqx-967m)

For Bullseye PHP 8.3 through 8.5 the runtime patches were also compared with
the corresponding upstream release. In the PHP
8.4 and 8.5 HTTP-wrapper backport for CVE-2026-127960, the differing line is
unchanged context and the added and removed code matches the upstream fix.
The bundled uriparser backport for CVE-2026-48841 matches its upstream fix.
[PHP release changelog](https://www.php.net/ChangeLog-8.php) · [uriparser fix](https://github.com/uriparser/uriparser/commit/4bf74cf04db45dd0c67c4b1e45843ebe06691065)


## Debian 9 Stretch

[StackX source index](https://mirrors.scalarx.net/stackx-php/stretch/repo/Sources)

| PHP branch | StackX source revision | Debian packaging archive SHA256 |
| --- | --- | --- |
| 5.6 | `5.6.40-60+0~20220627.67+debian9~1.gbp1f7ffd+sxphp.20261124.1` | `f0503d9c99801f5095927c1216528a7e3c534547f232058741fa3638f31e8e5f` |
| 7.0 | `7.0.33-60+0~20220627.68+debian9~1.gbp3d361a+sxphp.20261124.1` | `a457b20f3ec2af05f00b18fd5d58682042125ea910c07deae9a9cbb6097794ff` |
| 7.1 | `7.1.33-47+0~20220627.68+debian9~1.gbp1fc917+sxphp.20261124.1` | `f5220decbce12d59bbd8013a5da4658a3290f37a72960e5119a68b890df2bad2` |
| 7.2 | `7.2.34-32+0~20220627.74+debian9~1.gbpc7fa3c+sxphp.20261124.1` | `b9d07fdbb2e3963540f0e564333b583b57d2bc254812019c58357f098bd9d8f4` |
| 7.3 | `7.3.33-4+0~20220627.98+debian9~1.gbp40b3e4+sxphp.20261124.1` | `24bd35efac18c9f1628bc53d13de56462148e227af5b93fcf0438efbfd5aa5f5` |
| 7.4 | `1:7.4.30-3+0~20220627.69+debian9~1.gbpf2b381+sxphp.20261124.1` | `d6390a6ee1f22680340551fde7244aa4cdc9335baed28ece5823c233ccffe357` |
| 8.0 | `1:8.0.20-2+0~20220625.38+debian9~1.gbpde2407+sxphp.20261124.1` | `af5f9f9e8dbf3790d78da04ade8770e0f1120cf94272546692937830182eafcf` |
| 8.1 | `8.1.7-2+0~20220625.22+debian9~1.gbp4d1949+sxphp.20261124.1` | `f23f2d36c916a1032c7f3b3e254a4685f4cfceb147814acb7089ca85278021f5` |

## Debian 10 Buster

[StackX source index](https://mirrors.scalarx.net/stackx-php/buster/repo/Sources)

| PHP branch | StackX source revision | Debian packaging archive SHA256 |
| --- | --- | --- |
| 5.6 | `5.6.40-77+0~20240606.85+debian10~1.gbpd4d5eb+sxphp.20261124.1` | `f3f0144cf15d99ef97eca257539682cbbce5ad4cc7ecd77501380e2dee36aaeb` |
| 7.0 | `7.0.33-75+0~20240606.88+debian10~1.gbpce193b+sxphp.20261124.1` | `fd93eb25b3234312e60fae3691be597db65d86b7f0769bb939219e41becae6cc` |
| 7.1 | `7.1.33-63+0~20240606.93+debian10~1.gbpa08c53+sxphp.20261124.1` | `a104c5ef1d087a5cb03e560000deaad8fe14cbb44fe79add63156b6541a19478` |
| 7.2 | `7.2.34-50+0~20240606.95+debian10~1.gbpf31532+sxphp.20261124.1` | `d59b5d0426934581e95ffa52157facf10e03d8407da0c5df199ee14804c2b4eb` |
| 7.3 | `7.3.33-19+0~20240606.119+debian10~1.gbp87e0d7+sxphp.20261124.1` | `38ee6ecdcf4030603ef585b6d3f25e163d8070528ab9df9bf16db230e4f4a8ce` |
| 7.4 | `1:7.4.33-13+0~20240606.93+debian10~1.gbp3bbf86+sxphp.20261124.1` | `e9d0eca47e4381927ebd526c1362ffa94edebea78fa25611a51fa046c427ffa3` |
| 8.0 | `1:8.0.30-7+0~20240606.65+debian10~1.gbpe57fd4+sxphp.20261124.1` | `567033723c1f8af805de4f578b8b7a49b29e1c326681fca7caff37d1454ee494` |
| 8.1 | `8.1.29-1+0~20240606.65+debian10~1.gbp2ddf4e+sxphp.20261124.1` | `a788f0e0b3f516925fb374446be28b46de64606f6d5276c3ac34f78625d929f7` |
| 8.2 | `8.2.20-2+0~20240608.57+debian10~1.gbp6b5ea6+sxphp.20261124.1` | `f890c761fb8fb361347f56b0d6dcc9418825d22a8e4abfd4859e5f30d615581c` |
| 8.3 | `8.3.8-2+0~20240608.35+debian10~1.gbp4d7dbc+sxphp.20261124.1` | `5e370902f3e3cb9fd77fcbe02682965e5eea2cf955994dea6050ed69160dfd0d` |

## Debian 11 Bullseye

[StackX source index](https://mirrors.scalarx.net/stackx-php/bullseye/repo/Sources)

| PHP branch | StackX source revision | Debian packaging archive SHA256 |
| --- | --- | --- |
| 5.6 | `5.6.40-105+0~20261022.135+debian11~1.gbp37a17e+sxphp.20261124.1` | `143944ed32a46cc6aaef8fb4c8e698456c2a795be75e93cb2f65ec3ba55355a6` |
| 7.0 | `7.0.33-93+0~20261022.119+debian11~1.gbp952195+sxphp.20261124.1` | `d5ea6d43693922b3aae62798d8227657c99ac6d7f856cd8a699101a45b9bb37e` |
| 7.1 | `7.1.33-81+0~20261022.128+debian11~1.gbpa88ccf+sxphp.20261124.1` | `a0ce1387a01e9d64f8b4d26dd5f59fb0c378673ba039d009ebac8c6be5481062` |
| 7.2 | `7.2.34-66+0~20261021.122+debian11~1.gbpe0bcd4+sxphp.20261124.1` | `115b8c04b7c202d6651e251838186bad01f1a9d232b6137c74776ca627a22352` |
| 7.3 | `7.3.33-35+0~20261021.144+debian11~1.gbpecf76f+sxphp.20261124.1` | `80770304b97e059815a345efbaa604778c577e865c9fb4b24490a7dd5ca0aee8` |
| 7.4 | `1:7.4.33-31+0~20261021.121+debian11~1.gbpe9c428+sxphp.20261124.1` | `dfcbcc4ff3a09165d56fc06c0f8e4a4eda8d480d1ad461be9181541287cc3370` |
| 8.0 | `1:8.0.30-25+0~20261021.88+debian11~1.gbpabebea+sxphp.20261124.1` | `b79f03cb3d4026eb2ea7b9810b4b57695630a5860972b4312b8f8697790d7632` |
| 8.1 | `8.1.34-9+0~20261021.82+debian11~1.gbp4e430a+sxphp.20261124.1` | `a7e5300601b68449af56adad32f7ecf4615f4b6a0fc0c0a8c192cad99b475b70` |
| 8.2 | `8.2.35-1+0~20261021.94+debian11~1.gbp8bff78+sxphp.20261124.1` | `0b1bef2ad6ca65af3f07c42d8b08cc4c792fa2bd1cd3744eb153d0e652b94b53` |
| 8.3 | `8.3.36-1+0~20261021.88+debian11~1.gbp250f7c+sxphp.20261124.1` | `df6f66a7da10e65ade0ec5cf33ae2088c1f8dc5470ec9cfd37f2be9b84999533` |
| 8.4 | `8.4.27-1+0~20261021.57+debian11~1.gbp7636b9+sxphp.20261124.1` | `78e5d56b2aefb659abf8f4836deafc54ad66d11c31df608d5477b8e7b0ac2889` |
| 8.5 | `8.5.12-1+0~20261021.27+debian11~1.gbp1a3e8a+sxphp.20261124.1` | `01f5ae4e484704336338e48bc11a1c742275f253433fead0b444aa61405c9b20` |
