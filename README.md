# sops-lint

**A linter that understands [SOPS](https://github.com/getsops/sops).**

[![CI](https://github.com/eldpcn/sops-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/eldpcn/sops-lint/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sops-lint.svg)](https://crates.io/crates/sops-lint)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Generic secret scanners (gitleaks, trufflehog, ...) don't know what SOPS is:
they either false-positive on ciphertext, or miss the far more dangerous case
where a field *looks* encrypted at a glance but actually isn't. `sops-lint`
is built around SOPS's own rules instead of generic entropy scanning.

```console
$ sops-lint apps/
apps/payments/secret.yaml: error: stringData.apiKey is plaintext, but SOPS's own metadata says this file encrypts it
apps/payments/secret.yaml: warning: no creation_rule in any of .sops.yaml matches this path; re-encrypting today would leave it in plaintext
```

That first line is the one a generic scanner can't give you: the file *has*
a `sops:` block and looks encrypted at a glance, but a key added after the
`encrypted_regex` was written slipped through in plaintext.

## What it catches

| `check` id | What it means | Severity |
|---|---|---|
| `escaped_encryption` | A file has a `sops:` block, but a value under a key SOPS's own `encrypted_regex`/`unencrypted_regex`/`encrypted_suffix`/`unencrypted_suffix` says it covers is still plaintext. Checked at every nesting depth, matching SOPS's own `shouldBeEncrypted`: a key several levels down is covered even if none of its ancestors are. | error |
| `never_encrypted` | A file looks like a Kubernetes `Secret` (`kind: Secret`, or a filename containing "secret") but has no `sops:` block whatsoever. | error |
| `no_creation_rule` | Independent of current encryption state, the file's path doesn't match any `creation_rules[].path_regex` in `.sops.yaml`, so re-running `sops -e` today would leave it (or re-leave it) in plaintext. | warning (`--strict` to fail on it too) |
| `invalid_sops_metadata` | A file's own `encrypted_regex`/`unencrypted_regex` doesn't compile as a regex, so coverage for that document fell back to "encrypt everything" — which can itself cause false positives. | warning |
| `config_load_error` | A `.sops.yaml` (explicit `--config`, or one found during discovery) couldn't be read or parsed. Coverage results may be incomplete as a result. | error |
| `unparseable_document` | A document (or, if unreadable, a whole file) in a secret-named path couldn't be parsed as YAML at all, so it wasn't checked. | warning |

## Install

```sh
cargo install sops-lint
```

```sh
nix run github:eldpcn/sops-lint -- PATHS...
```

Or grab a prebuilt Linux (x86_64, glibc) binary from the
[releases page](https://github.com/eldpcn/sops-lint/releases) — no
`cargo`/`nix` needed.

**As a pre-commit hook:**

```yaml
repos:
  - repo: https://github.com/eldpcn/sops-lint
    rev: v0.1.1
    hooks:
      - id: sops-lint
```

## Usage

```sh
sops-lint [PATHS...]              # default: current directory
sops-lint --config path/to/.sops.yaml PATHS...
sops-lint --strict PATHS...       # also fail on creation_rule coverage gaps
sops-lint --format json PATHS...  # machine-readable findings for CI/tooling
sops-lint --staged                # check git's index content (for a pre-commit hook)
sops-lint --git-history           # scan all of HEAD's history for secrets that were ever committed
sops-lint --git-history=origin/main..HEAD  # or just a range, e.g. for one PR
```

Exit code is nonzero if any finding (error, or warning under `--strict`) was
produced; 2 means sops-lint itself couldn't run (no `git`, not a repo, ...).
`--git-history` never checks `no_creation_rule` coverage — not meaningful for
a blob that may no longer exist at its old path.

### `--format json` schema

```json
{
  "version": 1,
  "findings": [
    {
      "file": "apps/payments/secret.yaml",
      "severity": "error",
      "check": "escaped_encryption",
      "doc_index": 0,
      "key_path": "stringData.apiKey",
      "key_path_segments": ["stringData", "apiKey"],
      "commit": null,
      "message": "stringData.apiKey is plaintext, but SOPS's own metadata says this file encrypts it"
    }
  ]
}
```

Always an object, never a bare top-level array — a bare array can't gain a
field later (a summary count, say) without breaking every existing parser.
`key_path` is dotted for display only; prefer `key_path_segments` for
anything that parses it back apart, since a real Kubernetes secret can have
a literal key containing a dot (`tls.crt`, `.dockerconfigjson`) that would
otherwise be indistinguishable from two nested keys. `doc_index` is the
0-based document number within a `---`-separated multi-document file, or
`null` for a finding that isn't about any one document (a coverage gap, or
a config load failure). `commit` is set only in `--git-history` mode.

## How detection works, concretely

SOPS encrypts *values*, not the document structure: a ciphertext leaf is
always a string of the form `ENC[AES256_GCM,data:...,iv:...,tag:...,type:...]`,
and the file's own `sops:` block records which keys it intended to cover.
That means `escaped_encryption` needs no decryption and no access to your
keys: it's pure static analysis of a file against its own stated policy.

## `.sops.yaml` discovery

SOPS itself finds a file's config by walking *up* from the file's own
directory. In practice this doesn't match how multi-config repos are
actually run: it's common to keep each `.sops.yaml` wherever is convenient
and always pass `--config` explicitly rather than relying on discovery. So
`sops-lint` instead finds every `.sops.yaml`/`.sops.yml` anywhere in the
**git repository** containing each scanned path (falling back to just the
scanned path if it isn't in a git repo at all), and treats a file as
covered if *any* of them has a matching `creation_rules[].path_regex` —
computed as a true relative path (`../` segments included, same as SOPS's
own `filepath.Rel`), not requiring the file to literally live under the
config's directory. Pass `--config` to pin a single one instead.

Searching the whole repo rather than just the scanned paths matters for a
pre-commit hook specifically: it invokes `sops-lint` with individual staged
filenames, not a directory, so "everywhere under the scanned root" would be
just that one file — missing a `.sops.yaml` that sits elsewhere in the same
repo entirely.

## Known limitations (v1)

- `encrypted_comment_regex`/`unencrypted_comment_regex` (SOPS can also scope
  encryption by YAML *comments*, not just keys) aren't checked: `serde_yaml`
  discards comments entirely, so there's nothing in our document model to
  test against them. A file relying on comment-based scoping is invisible
  to the escape check either way. (`key_groups` itself — SOPS's Shamir
  multi-recipient mode — doesn't affect encryption *scope* at all, only who
  can decrypt, so it needs nothing special here.)
- No recipient/key-rotation drift check yet (comparing a file's actual `age`/
  `pgp` recipients against what `.sops.yaml` currently specifies for its
  path) — planned, not implemented.
- No generic entropy/pattern scan across arbitrary fields — deliberately
  deferred; see `sops_meta.rs`'s `unrelated_key_with_secret_shaped_name_not_flagged`
  test for the exact gap this would close (a secret added under a key your
  `encrypted_regex` never covered, so it's neither "escaped" nor "unmanaged"
  by this tool's current definitions).
- `path_regex` is matched with Rust's `regex` crate, not Go's `regexp`;
  they agree on everything typical `.sops.yaml` files use, but aren't
  byte-for-byte identical in exotic patterns.
- YAML only — SOPS also supports JSON, `.env`, and INI files, none of which
  `sops-lint` reads (the `.yaml`/`.yml` extension filter in `discover.rs`
  skips everything else). `---`-separated multi-document YAML files *are*
  handled: each document is checked independently (see `doc_index` in the
  JSON schema above).
- If a document fails to parse as YAML at all, it's silently skipped unless
  the filename contains "secret" (case-insensitive), in which case that's a
  warning instead. Not every `.yaml` file that fails to parse is suspicious
  — Helm chart templates routinely use `{{ .Values.x }}` syntax that isn't
  valid YAML on its own — so the narrower filename heuristic is there to
  avoid drowning real findings in noise from an ordinary templated repo.
  (If three documents in a row fail to parse, `sops-lint` gives up on the
  rest of that file regardless of filename and says so — a defense against
  a real `serde_yaml` bug where certain malformed input makes its
  multi-document parser loop without ever reaching the end of the stream.)
- Built on `serde_yaml`, which is unmaintained (its dependency
  `unsafe-libyaml` carries
  [RUSTSEC-2024-0449](https://rustsec.org/advisories/RUSTSEC-2024-0449.html),
  informational, not a vulnerability). `cargo audit` runs in CI on every
  push and weekly, so an actual future vulnerability fails the build;
  migrating off `serde_yaml` itself is real follow-up work, not a
  drive-by swap.

## Development

```sh
nix develop          # drops you into a shell with cargo/rustc/clippy/rustfmt
cargo test
cargo clippy --all-targets
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
