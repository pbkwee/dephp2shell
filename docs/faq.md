# Frequently asked questions

## Downloading on an old server

Old `wget` and TLS libraries can fail to negotiate HTTPS with GitHub. Errors include `unknown protocol` and `Unable to establish SSL connection`. Disabling certificate verification does not fix an unsupported TLS protocol.

Download on a current computer, inspect the file, then transfer it over SSH. The download follows `main`, the latest development version; use a reviewed tag or commit for a fixed version. Replace `OLD_SERVER` with the destination address.

```sh
wget -O dephp2shell.sh https://raw.githubusercontent.com/pbkwee/dephp2shell/main/dephp2shell.sh
less dephp2shell.sh
scp -O dephp2shell.sh root@OLD_SERVER:/root/dephp2shell.sh
```

Run the commands separately. If the download fails, do not copy an incomplete file. `scp -O` uses the legacy SCP protocol for servers without modern SFTP support. Older SCP clients that do not recognise `-O` can omit it.

If SSH reports an algorithm mismatch, add only the option needed for that connection:

| Reported mismatch | Command option |
| --- | --- |
| Server host key offers `ssh-rsa` | `-oHostKeyAlgorithms=+ssh-rsa` |
| Key exchange offers `diffie-hellman-group14-sha1` | `-oKexAlgorithms=+diffie-hellman-group14-sha1` |
| Only `diffie-hellman-group1-sha1` is offered | `-oKexAlgorithms=+diffie-hellman-group1-sha1` |
| Existing RSA login key requires SHA-1 signatures | `-oPubkeyAcceptedAlgorithms=+ssh-rsa` |

For example, when the host-key error specifically offers `ssh-rsa`:

```sh
scp -O -oHostKeyAlgorithms=+ssh-rsa \
  dephp2shell.sh root@OLD_SERVER:/root/dephp2shell.sh
```

Keep these exceptions on the individual command. Verify the destination host key; do not disable host-key checking. Some current SSH builds no longer support particular legacy algorithms. See the [OpenSSH legacy connection guide](https://www.openssh.org/legacy.html).

On the old server, inspect the received file before running a check:

```sh
less /root/dephp2shell.sh
bash /root/dephp2shell.sh --check
```

## Why does an old PHP version count as patched?

Distribution and vendor packages can backport security fixes while retaining an older upstream version number. The complete package revision and its provenance matter. DePHP2Shell recognises reviewed fixes; it does not infer a fix from a build date or provider name alone.

## Will it replace my PHP packages with Sury?

Normal `--fix` preserves package providers. Existing Sury/ondrej PHP can use a recognised fixed package from its configured source and branch.

An explicitly enabled `--enable-extra-fixes` method can attempt a closely matched native-to-Sury change. Read the [resolution options](resolution-options.md) before using it. Unsupported setups remain blocked; application compatibility still needs testing.

## Why is the result still unverified after an update?

An unreadable process, an unknown vendor backport, a failed version probe or a PHP job still using old files can prevent complete verification. Read the specific warning. If a process exited during inspection, another `--check` can resolve the gap.

A successful package command is only part of a successful update. Service state and the PHP installations found afterwards also matter.

## Can I publish the logs with a bug report?

Review and redact selected excerpts first. Detailed logs can reveal hostnames, paths, process details and repository information. Use the script revision, distribution, architecture and relevant warnings for an initial report. Keep full run directories private.

## Is a clear PHP result enough for an old server?

A clear result covers these two vulnerabilities in the inspected PHP installations. The operating system and other applications still need maintained security updates. Plan an upgrade or migration if support has ended.
