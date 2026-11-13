//! Shells out to the system `git` binary rather than linking `git2` or a
//! Rust git crate -- avoids extra dependency surface for a few plumbing
//! commands `git` already does well.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// One YAML blob that ever existed in history: the commit that
/// introduced/changed it, its path at that commit, and its blob OID.
pub struct HistoricalBlob {
    pub commit: String,
    pub path: String,
    pub oid: String,
}

/// Every YAML blob added or modified by any commit in `rev_range` (e.g.
/// `"HEAD"` or `"origin/main..HEAD"`). Deletions excluded (`--diff-filter=AM`):
/// a deleted file's content was already captured when it was added/changed.
pub fn list_historical_yaml_blobs(rev_range: &str) -> Result<Vec<HistoricalBlob>> {
    let output = Command::new("git")
        .args([
            "log",
            "--format=%H",
            "--raw",
            "--no-abbrev", // full OIDs, to match cat-file --batch's header; --full-index does NOT do this for --raw
            "--no-renames",
            "--diff-filter=AM",
        ])
        .arg(rev_range)
        .args(["--", "*.yaml", "*.yml"])
        .output()
        .context("running git log")?;
    if !output.status.success() {
        bail!(
            "git log failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(parse_raw_log(&output.stdout))
}

/// Parses `git log --format=%H --raw --no-abbrev` output: bare lines are
/// commit hashes; `:`-prefixed lines are changed paths under the commit
/// above, `:<old mode> <new mode> <old oid> <new oid> <status>\t<path>`.
fn parse_raw_log(raw: &[u8]) -> Vec<HistoricalBlob> {
    let text = String::from_utf8_lossy(raw);
    let mut blobs = Vec::new();
    let mut commit = String::new();
    for line in text.lines() {
        if let Some(diff_line) = line.strip_prefix(':') {
            let Some((fields, path)) = diff_line.split_once('\t') else {
                continue;
            };
            // [old mode, new mode, old oid, new oid, status]
            let parts: Vec<&str> = fields.split_whitespace().collect();
            let Some(new_oid) = parts.get(3) else {
                continue;
            };
            blobs.push(HistoricalBlob {
                commit: commit.clone(),
                path: path.to_string(),
                oid: new_oid.to_string(),
            });
        } else if !line.is_empty() {
            // A bare 40-hex-char line is the next commit's `%H`.
            commit = line.to_string();
        }
    }
    blobs
}

/// Fetches many blobs' contents in one `git cat-file --batch` process,
/// keyed by OID. Skips (doesn't error on) non-UTF-8 blobs.
pub fn cat_file_batch(oids: &[String]) -> Result<HashMap<String, String>> {
    if oids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning git cat-file --batch")?;

    // Writer on its own thread to avoid a deadlock: writing all of stdin
    // before reading stdout can block if the child fills its output buffer.
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let request = oids.join("\n") + "\n";
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut raw = Vec::new();
    stdout
        .read_to_end(&mut raw)
        .context("reading git cat-file --batch output")?;

    writer
        .join()
        .map_err(|_| anyhow!("git cat-file --batch stdin writer thread panicked"))??;
    let status = child.wait().context("waiting for git cat-file --batch")?;
    if !status.success() {
        bail!("git cat-file --batch exited with {status}");
    }

    parse_batch_output(&raw)
}

/// Parses `git cat-file --batch`'s documented format: `<oid> missing\n`,
/// or `<oid> <type> <size>\n` + exactly `<size>` content bytes + one `\n`.
fn parse_batch_output(raw: &[u8]) -> Result<HashMap<String, String>> {
    let mut contents = HashMap::new();
    let mut pos = 0;
    while pos < raw.len() {
        let nl = raw[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .context("truncated git cat-file --batch header")?;
        let header = std::str::from_utf8(&raw[pos..pos + nl]).context("non-UTF-8 header")?;
        pos += nl + 1;

        let fields: Vec<&str> = header.split(' ').collect();
        if fields.len() == 2 && fields[1] == "missing" {
            continue; // nothing to skip; this object simply has no content line
        }
        let [oid, _kind, size] = fields[..] else {
            bail!("unexpected git cat-file --batch header: {header:?}");
        };
        let size: usize = size.parse().context("non-numeric object size")?;

        let end = pos + size;
        if end > raw.len() {
            bail!("git cat-file --batch content shorter than its announced size");
        }
        if let Ok(text) = std::str::from_utf8(&raw[pos..end]) {
            contents.insert(oid.to_string(), text.to_string());
        }
        pos = end + 1; // the one extra `\n` cat-file always appends
    }
    Ok(contents)
}

/// Staged (index) YAML file paths, via `git diff --cached`.
pub fn staged_yaml_paths() -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .args(["--", "*.yaml", "*.yml"])
        .output()
        .context("running git diff --cached")?;
    if !output.status.success() {
        bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// Staged (index) content of `path` -- what would actually be committed.
/// `None` if not valid UTF-8.
pub fn show_staged(path: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("show")
        .arg(format!(":{path}"))
        .output()
        .context("running git show")?;
    if !output.status.success() {
        bail!(
            "git show :{path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_batch_response() {
        let raw = b"abc1234 blob 5\nhello\n";
        let parsed = parse_batch_output(raw).unwrap();
        assert_eq!(parsed.get("abc1234").unwrap(), "hello");
    }

    #[test]
    fn parses_content_without_a_trailing_newline_of_its_own() {
        // cat-file always appends one `\n`; must not be read as content.
        let raw = b"abc1234 blob 3\nabc\n";
        let parsed = parse_batch_output(raw).unwrap();
        assert_eq!(parsed.get("abc1234").unwrap(), "abc");
    }

    #[test]
    fn skips_a_missing_object_without_erroring() {
        let raw = b"deadbeef missing\nabc1234 blob 2\nhi\n";
        let parsed = parse_batch_output(raw).unwrap();
        assert!(!parsed.contains_key("deadbeef"));
        assert_eq!(parsed.get("abc1234").unwrap(), "hi");
    }

    #[test]
    fn parses_back_to_back_objects() {
        let raw = b"a blob 1\nx\nb blob 2\nyz\n";
        let parsed = parse_batch_output(raw).unwrap();
        assert_eq!(parsed.get("a").unwrap(), "x");
        assert_eq!(parsed.get("b").unwrap(), "yz");
    }

    #[test]
    fn raw_log_picks_the_new_oid_not_the_old_one() {
        // Regression: new OID is field index 3, not 2. Getting this wrong
        // resolved "modified" lines to the file's *previous* content, and
        // "added" lines to the all-zero OID (always "missing").
        let raw = b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n\n\
            :100644 100644 1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 M\tmodified.yaml\n\
            :000000 100644 0000000000000000000000000000000000000000 3333333333333333333333333333333333333333 A\tadded.yaml\n";
        let blobs = parse_raw_log(raw);
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].path, "modified.yaml");
        assert_eq!(blobs[0].oid, "2222222222222222222222222222222222222222");
        assert_eq!(blobs[1].path, "added.yaml");
        assert_eq!(blobs[1].oid, "3333333333333333333333333333333333333333");
        assert!(blobs
            .iter()
            .all(|b| b.commit == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    }

    #[test]
    fn raw_log_associates_paths_with_the_right_commit() {
        let raw = b"commit1\n\n:100644 100644 a a1 M\tfile-a.yaml\ncommit2\n\n:100644 100644 b b1 M\tfile-b.yaml\n";
        let blobs = parse_raw_log(raw);
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].commit, "commit1");
        assert_eq!(blobs[1].commit, "commit2");
    }
}
