# Security

sops-lint is a linter for SOPS-encrypted repos, so a bug here can mean a
missed secret leak. Please report vulnerabilities privately rather than
as a public issue.

## Reporting

Open a [GitHub security advisory](https://github.com/eldpcn/sops-lint/security/advisories/new)
on this repo, or email the address in `Cargo.toml`'s repository contact
(the maintainer's GitHub profile). Include:

- What input (a file, a `.sops.yaml`, a git history shape) triggers it
- What sops-lint reports vs. what it should report
- Whether it's a false negative (a real leak missed) or false positive

False negatives are treated as higher severity than false positives, given
the tool's purpose.

## Scope

In scope: the three core checks (`escaped_encryption`, `never_encrypted`,
`no_creation_rule`), `--staged`, `--git-history`, and the `git` plumbing
in `src/git.rs`. Also in scope: a hang/DoS from malformed input (this has
happened once before, see the `MAX_CONSECUTIVE_FAILURES` guard in `lib.rs`).

Out of scope: vulnerabilities in SOPS itself, in `git`, or in dependencies
already tracked by `cargo audit` (which runs in CI on every push and
weekly) — please report those upstream instead.
