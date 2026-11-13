# sops-lint

A linter that understands [SOPS](https://github.com/getsops/sops), for repos
that encrypt Kubernetes `Secret`s (or anything else) with it.

Generic secret scanners (gitleaks, trufflehog, ...) don't know what SOPS is:
they either false-positive on ciphertext, or miss the far more dangerous case
where a field *looks* encrypted at a glance but actually isn't. `sops-lint`
is built around SOPS's own rules instead of generic entropy scanning, so it
catches three specific, real failure modes:

1. **Escaped encryption.** A file has a `sops:` metadata block (so someone
   ran `sops -e` on it), but some value SOPS's own `encrypted_regex` /
   `encrypted_key_groups` says it should cover is still plaintext — usually
   because a field was added after the regex was written, or the regex was
   too narrow to begin with.
2. **Never encrypted at all.** A file looks like a Kubernetes `Secret`
   (`kind: Secret`, or a filename containing "secret") but has no `sops:`
   block whatsoever — it was committed straight, in plaintext.
3. **No creation rule would catch it.** Independent of whether a file is
   currently encrypted, its path doesn't match any `creation_rules[].path_regex`
   in the nearest `.sops.yaml` — so re-running `sops -e` on it today would
   leave it (or re-leave it) in plaintext.

Checks 1 and 2 are **errors**. Check 3 is a **warning** by default — pass
`--strict` in CI to fail on it too.

## Usage

```sh
sops-lint [PATHS...]              # default: current directory
sops-lint --config path/to/.sops.yaml PATHS...
sops-lint --strict PATHS...       # also fail on creation_rule coverage gaps
```

Exit code is nonzero if any finding (error, or warning under `--strict`) was
produced — wire it into a pre-commit hook or CI step directly.

## How detection works, concretely

SOPS encrypts *values*, not the document structure: a ciphertext leaf is
always a string of the form `ENC[AES256_GCM,data:...,iv:...,tag:...,type:...]`,
and the file's own `sops:` block records which top-level keys it intended to
cover (`encrypted_regex`, `unencrypted_regex`, `encrypted_suffix`, or
`unencrypted_suffix` — defaulting to "everything" if none is set). That means
check 1 needs no decryption and no access to your keys: it's pure static
analysis of a file against its own stated policy.

## `.sops.yaml` discovery

SOPS itself finds a file's config by walking *up* from the file's own
directory. In practice this doesn't match how multi-config repos are
actually run: it's common to keep each `.sops.yaml` wherever is convenient
and always pass `--config` explicitly rather than relying on discovery (this
repo's own `nixos/.sops.yaml` says exactly that, in a comment, because its
config is a sibling of `clusters/dev/.sops.yaml` rather than an ancestor of
anything it governs). So `sops-lint` instead finds *every* `.sops.yaml` /
`.sops.yml` anywhere under the scanned root and treats a file as covered if
*any* of them has a matching `creation_rules[].path_regex` — computed as a
true relative path (`../` segments included, same as SOPS's own
`filepath.Rel`), not requiring the file to literally live under the config's
directory. Pass `--config` to pin a single one instead.

## Known limitations (v1)

- Only the **current working tree** is scanned — no git history, unlike
  gitleaks. A secret that was ever committed plaintext and later fixed won't
  be re-flagged, but it's also still in history; a history scanner is a
  separate, complementary tool.
- `encrypted_key_groups` (SOPS's multi-key-group mode) isn't parsed; files
  using it are treated as fully covered rather than risking false positives.
- No recipient/key-rotation drift check yet (comparing a file's actual `age`/
  `pgp` recipients against what `.sops.yaml` currently specifies for its
  path) — planned, not implemented.
- No generic entropy/pattern scan across arbitrary fields — deliberately
  deferred; see `sops_meta.rs`'s `new_key_outside_regex_with_secret_escapes`
  test for the exact gap this would close (a secret added under a key your
  `encrypted_regex` never covered, so it's neither "escaped" nor "unmanaged"
  by this tool's current definitions).
- `path_regex` is matched with Rust's `regex` crate, not Go's `regexp`;
  they agree on everything typical `.sops.yaml` files use, but aren't
  byte-for-byte identical in exotic patterns.

## Development

```sh
nix develop          # drops you into a shell with cargo/rustc/clippy/rustfmt
cargo test
cargo clippy --all-targets
```
