# DePHP2Shell contributor guidance

Read README.md and docs/maintainer-reference.md before changing the script.
Keep the delivered tool self-contained and compatible with Bash 3.1 and old AWK.
Preserve the documented machine records, exit statuses and source-preservation guards.
Keep command-line and environment options aligned; public options use DP2S_.

Run `python3 tests/run.py`, `bash -n dephp2shell.sh` and
`shellcheck -S warning dephp2shell.sh` for script changes. Repeat affected shell
fixtures with DP2S_TEST_BASH and DP2S_TEST_AWK when older binaries are available.
Tests must use isolated synthetic fixtures and mocked administrative commands.
Never contact or modify a live server or persistent application database to test.
Review source and documentation for private data before publication.

Keep commit.log local as the proposed commit message. Do not push or publish
without maintainer authorization.
