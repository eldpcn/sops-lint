# sops-lint

**A linter that understands [SOPS](https://github.com/getsops/sops).**

[![CI](https://github.com/eldpcn/sops-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/eldpcn/sops-lint/actions/workflows/ci.yml)
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

| # | Check | Severity |
|---|-------|----------|
| 1 | **Escaped encryption** — a file has a `sops:` block, but a value under a key SOPS's own `encrypted_regex`/`unencrypted_regex`/`encrypted_suffix`/`unencrypted_suffix` says it covers is still plaintext. Checked at every nesting depth, matching SOPS's own `shouldBeEncrypted`: a key several levels down is covered even if none of its ancestors are. | error |
| 2 | **Never encrypted at all** — a file looks like a Kubernetes `Secret` (`kind: Secret`, or a filename containing "secret") but has no `sops:` block whatsoever. | error |
| 3 | **No creation rule would catch it** — independent of current encryption state, the file's path doesn't match any `creation_rules[].path_regex` in `.sops.yaml`, so re-running `sops -e` today would leave it (or re-leave it) in plaintext. | warning (`--strict` to fail on it too) |

## Install

```sh
cargo install --git https://github.com/eldpcn/sops-lint
```

```sh
nix run github:eldpcn/sops-lint -- PATHS...
```

**As a pre-commit hook:**

```yaml
repos:
  - repo: https://github.com/eldpcn/sops-lint
    rev: <tag or commit>
    hooks:
      - id: sops-lint
```

## Usage

```sh
sops-lint [PATHS...]              # default: current directory
sops-lint --config path/to/.sops.yaml PATHS...
sops-lint --strict PATHS...       # also fail on creation_rule coverage gaps
sops-lint --format json PATHS...  # machine-readable findings for CI/tooling
```

Exit code is nonzero if any finding (error, or warning under `--strict`) was
produced.

## How detection works, concretely

SOPS encrypts *values*, not the document structure: a ciphertext leaf is
always a string of the form `ENC[AES256_GCM,data:...,iv:...,tag:...,type:...]`,
and the file's own `sops:` block records which keys it intended to cover.
That means check 1 needs no decryption and no access to your keys: it's
pure static analysis of a file against its own stated policy.

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

- Only the **current working tree** is scanned — no git history, unlike
  gitleaks. A secret that was ever committed plaintext and later fixed won't
  be re-flagged, but it's also still in history; a history scanner is a
  separate, complementary tool.
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
  handled: each document is checked independently, and a finding's
  `key_path` is prefixed `doc[N].` for anything past the first.
- If a document fails to parse as YAML at all, it's silently skipped unless
  the filename contains "secret" (case-insensitive), in which case that's a
  warning instead. Not every `.yaml` file that fails to parse is suspicious
  — Helm chart templates routinely use `{{ .Values.x }}` syntax that isn't
  valid YAML on its own — so the narrower filename heuristic is there to
  avoid drowning real findings in noise from an ordinary templated repo.

## Development

```sh
nix develop          # drops you into a shell with cargo/rustc/clippy/rustfmt
cargo test
cargo clippy --all-targets
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
