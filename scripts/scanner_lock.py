#!/usr/bin/env python3
"""The one reader of scripts/scanner-bins.lock (hardening batch 3, Codex review round 1).

wt.py loads this file to decide which scanner programs it may run, and publish.sh runs it to refuse a release whose lock
Watchtower couldn't use. publish.sh used to grep for "<sha256>  <name>  ", so six lines with no architecture passed it while
the runtime reader skipped every one of them: an empty lock, and no scanner ran anywhere. Both now read the lock the same way.

A line is `<sha256>  <name>  <arch>  <note>`, fields separated by exactly two spaces: sha256 is 64 lowercase hex digits,
name one of NAMES, arch one of ARCHES, note free text (not empty). Blank lines and lines starting with # are comments.
Any other line is a problem: it is never used, and publish.sh stops on it.

Codex review round 2: the file is read here too (read_lock), with one size limit and one failure rule for both, so a lock
Watchtower would refuse whole (too large, not UTF-8, not a plain file) also stops publish.sh. semgrep may be listed (codescan
runs it only from the checked folder), but a release needs only the scanners in REQUIRED.
wt.py runs this file from its checked source bytes, never from a bytecode cache. Stdlib only.
"""
import os
import re
import stat
import sys

REQUIRED = ("skillspector", "husk", "gitleaks", "trufflehog", "osv-scanner", "pip-audit")   # every release lists these
NAMES = REQUIRED + ("semgrep",)                                                              # optional: codescan's semgrep
ARCHES = ("x86_64", "aarch64", "any")
RELEASE_ARCHES = ("x86_64", "any")   # a release must cover the computers Grok Bot runs on (x86_64); aarch64 lines are optional
MAX_BYTES = 1_000_000
LINE = re.compile(r"([0-9a-f]{64})  (" + "|".join(map(re.escape, NAMES)) + r")  (" + "|".join(ARCHES) + r")  (\S.*)")


def read_lock(path):
    """(text, None), or (None, why) when the lock can't be used at all: not a plain file (never a link, pipe or device), over
    MAX_BYTES, or not UTF-8. Watchtower then lists no scanner, and publish.sh stops."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        return None, f"can't be read ({type(e).__name__})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "isn't a plain file"
        data = b""
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, MAX_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) > MAX_BYTES:
            return None, f"is over {MAX_BYTES} bytes"
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "isn't UTF-8 text"
    except OSError as e:
        return None, f"can't be read ({type(e).__name__})"
    finally:
        os.close(fd)


def parse(text):
    """({(name, arch): {sha256, ...}}, [problem, ...]). Only well-formed lines give entries."""
    lock, problems = {}, []
    for n, line in enumerate(str(text or "").splitlines(), 1):
        s = line.rstrip("\r")
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        m = LINE.fullmatch(s)
        if not m:
            problems.append(f"line {n} isn't `<sha256>  <name>  <arch>  <note>` with a known name and architecture")
            continue
        lock.setdefault((m.group(2), m.group(3)), set()).add(m.group(1))
    return lock, problems


def release_problems(text):
    """Why a release with this lock would leave a scanner unrun (empty when it is complete)."""
    lock, problems = parse(text)
    out = [f"scripts/scanner-bins.lock {p}" for p in problems]
    for name in REQUIRED:
        if not any(lock.get((name, a)) for a in RELEASE_ARCHES):
            out.append(f"scripts/scanner-bins.lock has no checksum for {name}"
                       + ("" if not any(lock.get((name, a)) for a in ARCHES) else " on x86_64 (or any)"))
    return out


if __name__ == "__main__":
    text, why = read_lock(sys.argv[1] if len(sys.argv) > 1 else "scripts/scanner-bins.lock")
    found = [f"scripts/scanner-bins.lock {why}"] if why else release_problems(text)
    if found:
        print(found[0] + (f" (and {len(found) - 1} more)" if len(found) > 1 else ""))
        sys.exit(1)
