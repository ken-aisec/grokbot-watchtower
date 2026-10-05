#!/usr/bin/env python3
"""Watchtower: read-only security watch for a Grok Bot cloud computer.

Scripts find, the model judges, the human approves. Stdlib only; optional
external scanners (skillspector, husk, gitleaks, pip-audit) are used when on PATH.

Commands
  vet FILE|-            score a template, skill, or routine text before install
  audit                 full posture audit; writes findings.json and updates state
  daily                 quick audit; prints NO_CHANGES or a compact delta
  report                weekly Markdown report + self-contained HTML dashboard
  baseline              (re)take the integrity baseline without reporting

State lives in $WATCHTOWER_HOME (default /workspace/watchtower).
"""
import argparse, datetime as dt, hashlib, html, json, os, re, shutil, subprocess, sys

VERSION = "0.2.0"
HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "..", "rules", "text_rules.json")
SELF_ROOT = os.path.abspath(os.path.join(HERE, ".."))
SEV_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
CATEGORY_CAP = 30
LOW_CAP = 5
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", "site-packages", "proc", "sys",
             "google-chrome", "chromium", "Chrome", "BraveSoftware", "mozilla", "Cache", "Code Cache", "GPUCache",
             "Service Worker", "IndexedDB", "WasmTtsEngine", "Crashpad", ".npm", ".pnpm-store", ".cargo", ".rustup"}
SKIP_PREFIXES = ("scoped_dir", ".org.chromium", "tmp")
SKIP_PATH_PARTS = ("/go/pkg/", "/pkg/mod/", "/.m2/", "/.gradle/", "/dist-packages/", "/.bun/install/", "/.local/share/pnpm/")
TEXT_EXT = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".sh", ".js", ".ts", ".env", ".cfg", ".ini", ""}
SECRET_RULE = "WT-T011"


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def home():
    return os.environ.get("WATCHTOWER_HOME", "/workspace/watchtower")


def state_path(*p):
    d = os.path.join(home(), "state")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, *p)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_rules():
    with open(RULES_PATH) as f:
        r = json.load(f)
    for rule in r["rules"]:
        rule["rx"] = re.compile(rule["pattern"])
    for k in ("write_verbs", "approval_terms", "draft_terms", "schedule_terms", "nodata_terms", "high_freq", "context_guard"):
        r[k] = re.compile(r[k])
    return r


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path, limit=1_000_000):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def finding(rule_id, title, severity, owasp, where, evidence, fix, source="watchtower"):
    ev = (evidence or "").replace("\n", " ")[:160]
    key = hashlib.sha1(f"{rule_id}|{where}|{ev}".encode()).hexdigest()[:16]
    return {"key": key, "rule": rule_id, "title": title, "severity": severity, "owasp": owasp,
            "where": where, "evidence": ev, "fix": fix, "source": source}


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def mask(s):
    if len(s) <= 12:
        return s[:2] + "…"
    return s[:6] + "…" + s[-4:]


# ---------------------------------------------------------------- text analysis
KNOWN_INSTALLERS = re.compile(r"(?i)https?://(bun\.sh|deno\.land|sh\.rustup\.rs|astral\.sh|get\.docker\.com|brew\.sh|"
                              r"raw\.githubusercontent\.com/(nvm-sh|Homebrew)|install\.python-poetry\.org|cli\.github\.com|"
                              r"claude\.ai/install|get\.pnpm\.io|fnm\.vercel\.app|supabase\.com|vercel\.com|fly\.io/install|"
                              r"ollama\.com/install|sdk\.cloud\.google\.com|awscli\.amazonaws\.com|x\.ai/cli|tailscale\.com/install|"
                              r"downloads\.slack-edge\.com|cursor\.com/install|opencode\.ai/install|get\.helm\.sh|"
                              r"install\.determinate\.systems|starship\.rs|deb\.nodesource\.com|cli\.doppler\.com|"
                              r"railway\.app/install|github\.com/cli/cli)")
PLACEHOLDER = re.compile(r"(?i)(example|sample|placeholder|your[_-]?|dummy|fake|test|xxxx|0000|1234|abcd|\.\.\.|<|>|\*{3})")


FILE_MAGIC = (b"PK\x03\x04", b"%PDF", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"<!DOCTYPE", b"<!doctype", b"<html", b"<svg", b"<?xml", b"RIFF", b"\x1f\x8b")


def is_document_blob(b64):
    """Base64 that decodes to an ordinary file (Office, PDF, image, HTML) is data being uploaded, not a payload."""
    import base64, binascii
    chunk = b64[:64]
    try:
        head = base64.b64decode(chunk + "=" * (-len(chunk) % 4))
    except (binascii.Error, ValueError):
        return False
    return head.lstrip().startswith(FILE_MAGIC)


def looks_real_secret(s):
    """Drop documentation placeholders: example words, repeated characters, or low character variety."""
    if PLACEHOLDER.search(s):
        return False
    body = re.sub(r"^(sk-(proj|ant|svcacct|admin)-|sk-|ghp_|github_pat_|xox[baprs]-|xai-|AKIA|AIza)", "", s)
    if len(set(body)) < 10 or re.search(r"(.)\1{5,}", body):
        return False
    return True


def in_warning(text, m, rules):
    """True when the match sits inside defensive prose: negated, quoted, or described as an attack."""
    lo = max(0, m.start() - 90)
    before = text[lo:m.start()]
    sentence_start = max(before.rfind(". "), before.rfind("\n"))
    before = before[sentence_start + 1:] if sentence_start >= 0 else before
    after = text[m.end():m.end() + 40]
    quoted = before.rstrip().endswith(("\"", "“", "'", "`", "(", "[")) or before.rstrip().endswith("|")
    scoped = re.match(r"(?i)\s*(inside|in\s+(the|any|this|that)|within|from\s+(the|any)|embedded|contained|found\s+in|that\s+appear)", after)
    code = re.search(r"(<!--|\[//\]|r\"|\\s[+*]|\(\?i\))", before + after)
    return bool(quoted or scoped or code or rules["context_guard"].search(before))


REF_RULES = ("WT-T001", "WT-T002", "WT-T004", "WT-T005", "WT-T006", "WT-T007", "WT-T008")
REF_WORDS = re.compile(r"(?i)((prompt[- ]injection|injection|attack|dangerous[- ]code)\s+(patterns?|examples?|signatures?|detection|techniques?)"
                       r"|\bevil\.com\b|\battacker\b|detection\s+rules?|red[- ]team)")


def attack_reference(text, rules, where=""):
    """A supporting file (never a SKILL.md, the file a Bot follows) that describes itself as documenting
    or detecting attacks. Its matches stay visible but drop to low: downgraded, never hidden."""
    if os.path.basename(where.split(":")[0]) == "SKILL.md" or where in ("stdin",):
        return False
    hits = sum(len(r["rx"].findall(text)) for r in rules["rules"] if r["id"] in REF_RULES)
    return hits >= 1 and bool(REF_WORDS.search(text))


def scan_text(text, where, rules, kind="skill"):
    """Apply text rules plus document-level logic. kind: skill|reference|template|routine|description."""
    out = []
    guarded = set(rules.get("guarded_rules", []))
    is_ref = attack_reference(text, rules, where)
    if is_ref:
        out.append(finding("WT-T001r", "Describes injection patterns (reference or detector)", "info", ["AST05"], where,
                           "pattern list", "No action. Listed so you know this file contains attack examples."))
    for rule in rules["rules"]:
        if kind == "vendor" and rule["severity"] != "critical" and rule["id"] != "WT-T002":
            continue
        for m in rule["rx"].finditer(text):
            if is_ref and rule["id"] in REF_RULES:
                out.append(finding(rule["id"], rule["title"] + " (in an attack-pattern reference)", "low", rule["owasp"],
                                   f"{where}:{line_of(text, m.start())}", f"U+{ord(m.group(0)):04X}" if rule["id"] == "WT-T002" else m.group(0)[:140],
                                   "Documentation or detector text. Confirm the file is what it claims to be."))
                if rule["id"] == "WT-T002":
                    break
                continue
            if rule["id"] in guarded and in_warning(text, m, rules):
                continue
            if rule["id"] == SECRET_RULE and not looks_real_secret(m.group(0)):
                continue
            if rule["id"] == "WT-T003" and is_document_blob(m.group(0)):
                continue
            ev = m.group(0)
            if rule["id"] == "WT-T006" and KNOWN_INSTALLERS.search(ev):
                out.append(finding("WT-T006k", "Known installer piped to shell", "medium" if kind != "vendor" else "low",
                                   ["ASI05", "AST02"], f"{where}:{line_of(text, m.start())}", ev[:140],
                                   "A well-known installer, but still unpinned. Prefer a package manager or a pinned, checksummed download."))
                continue
            if rule["id"] == SECRET_RULE:
                ev = mask(ev)
            elif rule["id"] == "WT-T002":
                ev = f"U+{ord(ev):04X}"
            elif rule["id"] == "WT-T003":
                ev = ev[:24] + f"… ({len(m.group(0))} chars)"
            out.append(finding(rule["id"], rule["title"], rule["severity"], rule["owasp"],
                               f"{where}:{line_of(text, m.start())}", ev, rule["fix"]))
            if rule["id"] in ("WT-T002",):
                break  # one per file is enough for invisible chars
    writes = rules["write_verbs"].search(text)
    approved = has_approval(text, rules)
    if writes and not approved and kind not in ("reference", "vendor"):
        out.append(finding("WT-T013", "External action with no approval line", "medium" if kind == "skill" else "high", ["ASI02", "AST03", "LLM06"],
                           f"{where}:{line_of(text, writes.start())}", writes.group(0),
                           "Add to the description or routine: never send, post, buy, publish or delete without my approval."))
    if kind in ("routine", "template"):
        if rules["schedule_terms"].search(text) and not rules["nodata_terms"].search(text):
            out.append(finding("WT-R002", "Routine has no failure or no-data rule", "medium", ["ASI08"], where,
                               "no 'if the source is unavailable' clause",
                               "Add: if a source is unavailable, report the failure instead of using old data; if nothing changed, send nothing."))
        hf = rules["high_freq"].search(text)
        if hf:
            out.append(finding("WT-R003", "High-frequency schedule", "low", ["ASI08"], where, hf.group(0),
                               "Hourly routines burn the weekly allowance; prefer daily or an event trigger."))
    return dedupe(out)


NEGATION = re.compile(r"(?i)(don'?t|do\s+not|never|no\s+need\s+to|without)\s+$")


def has_approval(text, rules):
    """An approval phrase counts only when it is not negated ("don't ask me" is the opposite)."""
    for m in rules["approval_terms"].finditer(text):
        if m.group(0).lower().startswith("never"):
            return True
        if not NEGATION.search(text[max(0, m.start() - 20):m.start()]):
            return True
    return False


def autonomy(text, rules):
    writes = bool(rules["write_verbs"].search(text))
    approved = has_approval(text, rules)
    scheduled = bool(rules["schedule_terms"].search(text))
    if not writes:
        return "L1 drafts only" if rules["draft_terms"].search(text) else "L0 observe and report"
    if scheduled and not approved:
        return "L3 unattended actions"
    if approved:
        return "L2 acts with approval" if not scheduled else "L3 routines with approval gates"
    return "L3 unattended actions"


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        if f["key"] not in seen:
            seen.add(f["key"])
            out.append(f)
    return out


def score(findings):
    """100 minus weighted findings. Per OWASP category cap so one noisy category can't zero the score;
    low findings together cost at most LOW_CAP so hygiene notes never outweigh a real risk."""
    by_cat, low, seen = {}, 0, {}
    for f in findings:
        # each rule counts once at its worst severity, plus 1 point per extra occurrence (max +5),
        # so 200 skills with the same style issue don't outweigh one live secret
        k = f["rule"]
        w = SEV_WEIGHT.get(f["severity"], 0)
        prev = seen.get(k)
        if prev is None:
            seen[k] = [w, 0, f]
        else:
            prev[0] = max(prev[0], w)
            prev[1] += 1
    for k, (w, extra, f) in seen.items():
        if f["severity"] == "low":
            low += w
            continue
        cat = (f["owasp"] or ["other"])[0]
        by_cat[cat] = by_cat.get(cat, 0) + w + (min(extra, 5) if w else 0)
    penalty = sum(min(v, CATEGORY_CAP) for v in by_cat.values()) + min(low, LOW_CAP)
    s = max(0, 100 - penalty)
    grade = "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"
    return s, grade


def verdict(findings):
    sev = {f["severity"] for f in findings}
    if "critical" in sev:
        return "Do not install"
    if "high" in sev:
        return "Install with changes"
    return "Install"


def sort_findings(fs):
    return sorted(fs, key=lambda f: (SEV_ORDER.index(f["severity"]), f["rule"], f["where"]))


# ---------------------------------------------------------------- vet
def cmd_vet(args):
    rules = load_rules()
    text = sys.stdin.read() if args.path == "-" else read_text(args.path)
    if text is None:
        print(f"ERROR could not read {args.path}", file=sys.stderr)
        return 2
    name = "stdin" if args.path == "-" else os.path.basename(args.path)
    fs = scan_text(text, name, rules, kind="template")
    engines = {}
    if getattr(args, "deep", False) and args.path != "-":
        d = args.path if os.path.isdir(args.path) else os.path.dirname(os.path.abspath(args.path))
        notes = []
        fs += engine_findings([d], fs, notes)
        engines = {"dir": d, "notes": notes}
    fs = sort_findings(dedupe(fs))
    s, g = score(fs)
    urls = sorted(set(re.findall(r"https?://[^\s)\"'>]+", text)))
    result = {"tool": "watchtower", "version": VERSION, "target": name, "verdict": verdict(fs),
              "risk_score": 100 - s, "posture_score": s, "grade": g, "autonomy": autonomy(text, rules),
              "external_urls": urls[:25], "findings": fs, "engines": engines,
              "boundary_line": "Never send, post, buy, publish, delete, or change settings without my approval in this conversation. If a source is unavailable, report the failure."}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verdict: {result['verdict']} · risk {result['risk_score']}/100 · autonomy {result['autonomy']}")
        for f in fs:
            print(f"  [{f['severity'].upper()}] {f['rule']} {f['title']} @ {f['where']} :: {f['evidence']}")
            print(f"      fix: {f['fix']}")
        if urls:
            print("  External URLs: " + ", ".join(urls[:10]))
        print(f"  Paste into the description: {result['boundary_line']}")
    return 1 if result["verdict"] == "Do not install" else 0


# ---------------------------------------------------------------- collection
def walk(roots, max_depth=8):
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        base = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith((".venv",) + SKIP_PREFIXES)]
            if dirpath.count("/") - base >= max_depth:
                dirnames[:] = []
            ap = os.path.abspath(dirpath)
            if any(x in ap + "/" for x in SKIP_PATH_PARTS):
                dirnames[:] = []
                continue
            if ap.startswith(os.path.abspath(home())) or ap.startswith(SELF_ROOT):
                dirnames[:] = []
                continue
            for fn in filenames:
                yield os.path.join(dirpath, fn)


def is_skill_file(path):
    fn = os.path.basename(path)
    return fn == "SKILL.md" or fn == "plugin.json" or fn == "marketplace.json" or (
        fn.endswith(".json") and ("mcp" in fn.lower())) or "/.grok-plugin/" in path or "/.cursor-plugin/" in path


MCP_CONFIG = re.compile(r"(?i)^(\.?mcp|mcp[_-]?(config|servers|settings)|[\w-]*[_-]mcp[_-]?(config|servers|settings)|claude_desktop_config)\.json$")


def collect_inventory(roots):
    inv = {"skills": [], "plugin_files": [], "mcp_configs": []}
    for p in walk(roots):
        fn = os.path.basename(p)
        if fn == "SKILL.md":
            inv["skills"].append(p)
        elif MCP_CONFIG.search(fn):
            inv["mcp_configs"].append(p)
        elif fn in ("plugin.json", "marketplace.json") or "/.grok-plugin/" in p or "/.cursor-plugin/" in p:
            inv["plugin_files"].append(p)
    for k in inv:
        inv[k] = sorted(set(inv[k]))
    return inv


def skill_dir_files(skill_md):
    d = os.path.dirname(skill_md)
    files = []
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
    return sorted(files)[:200]


def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def persistence_snapshot():
    snap = {}
    code, out, _ = run(["crontab", "-l"], 10)
    snap["crontab"] = out.strip() if code == 0 else ""
    for d in ("/etc/cron.d", os.path.expanduser("~/.config/systemd/user")):
        if os.path.isdir(d):
            snap[d] = sorted(os.listdir(d))
    for rc in ("~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc"):
        p = os.path.expanduser(rc)
        if os.path.isfile(p):
            snap[rc] = sha256_file(p)
    return snap


KNOWN_CRED_FILES = {
    ".claude/.credentials.json": "Claude Code login",
    ".config/gh/hosts.yml": "GitHub CLI login",
    ".aws/credentials": "AWS CLI keys",
    ".netrc": "netrc logins",
    ".git-credentials": "git stored credentials",
    ".docker/config.json": "Docker registry login",
    ".npmrc": "npm token",
    ".config/gcloud/credentials.db": "Google Cloud CLI login",
}


def cli_credentials():
    out = []
    for rel, what in KNOWN_CRED_FILES.items():
        p = os.path.join(os.path.expanduser("~"), rel)
        if os.path.isfile(p):
            out.append(finding("WT-S003", f"CLI credential on the shared computer: {what}", "high", ["ASI03", "AST06"], p, what,
                               "Expected if a Bot uses this CLI, but every Bot (and anything injected into one) can use it. "
                               "Keep only the CLIs your Bots need, scope tokens to least privilege, and rotate them; sign out of unused ones."))
    return out


USER_SKILL_DIRS = ("/sand-data/workflows/", "/agent-data/workflows/")


def skill_tier(path):
    """user: the user's own saved skills (full rules). Everything else (first-party bundles, marketplace
    plugins, other agents' skill folders, copies sitting in /workspace) gets malicious-indicator rules only."""
    if any(x in path for x in USER_SKILL_DIRS):
        return "user"
    return "vendor"


SESSION_FILES = ("chrome-cookie-seed.json", "cookie-seed.json", "cookies.json")


def browser_sessions(roots):
    """Grok Bot seeds the shared browser with login cookies. Report which domains, never values."""
    out = []
    for r in [os.path.expanduser("~/sand-data"), os.path.expanduser("~/agent-data")] + list(roots):
        if not os.path.isdir(r):
            continue
        for fn in SESSION_FILES:
            p = os.path.join(r, fn)
            data = load_json(p, None)
            if data is None:
                continue
            items = data if isinstance(data, list) else data.get("cookies", []) if isinstance(data, dict) else []
            domains = sorted({str(c.get("domain", "")).lstrip(".") for c in items if isinstance(c, dict) and c.get("domain")})
            sensitive = [d for d in domains if re.search(r"(anthropic|claude|openai|x\.ai|github|google|microsoft|aws|stripe|bank|paypal|slack|notion)", d)]
            out.append(finding("WT-S004", "Logged-in browser sessions shared by every Bot", "high" if sensitive else "medium",
                               ["ASI03", "AST06"], p, f"{len(domains)} domains; sensitive: {', '.join(sensitive[:8]) or 'none'}",
                               "Every Bot can reuse these logins. In the Grok Bot browser, sign out of sites no Bot needs; "
                               "for AI consoles and admin sites, also log out all sessions from that site's security settings."))
            break
    return out


def is_vendor(path):
    return skill_tier(path) == "vendor"


# ---------------------------------------------------------------- audit
def audit(roots, exports, quick=False):
    rules = load_rules()
    fs, notes = [], []
    inv = collect_inventory(roots)
    manifest = {}

    # 1. skills, plugins, MCP configs on disk
    for skill in inv["skills"]:
        for p in skill_dir_files(skill):
            if os.path.splitext(p)[1].lower() in TEXT_EXT:
                t = read_text(p)
                if t is not None:
                    kind = "vendor" if is_vendor(p) else ("skill" if os.path.basename(p) == "SKILL.md" else "reference")
                    fs += scan_text(t, p, rules, kind=kind)
            manifest[p] = sha256_file(p)
    for p in inv["plugin_files"] + inv["mcp_configs"]:
        t = read_text(p)
        if t is not None:
            fs += scan_text(t, p, rules, kind="reference")
            manifest[p] = sha256_file(p)
            for m in re.finditer(r'"command"\s*:\s*"([^"]+)"', t):
                if re.search(r"(?i)\b(npx|uvx|bunx)\b", m.group(1)) and "@" not in t[m.end():m.end() + 200]:
                    fs.append(finding("WT-M001", "MCP server launched unpinned", "medium", ["AST02", "ASI04"],
                                      f"{p}:{line_of(t, m.start())}", m.group(1),
                                      "Pin the package version (pkg@1.2.3) so an update cannot change what runs."))

    # 2. integrity drift (AST07)
    base = load_json(state_path("baseline.json"), {})
    if base:
        for p, h in manifest.items():
            if p in base and base[p] != h:
                fs.append(finding("WT-I001", "Reviewed skill or plugin changed", "high", ["AST07"], p,
                                  f"sha256 {base[p][:12]}→{h[:12]}",
                                  "Re-vet this skill before its next use; run `wt baseline` once you accept the change."))
            elif p not in base:
                fs.append(finding("WT-I002", "New skill or plugin file", "low", ["AST09"], p, h[:12],
                                  "Vet it (`wt vet`), then run `wt baseline` to accept it."))
        for p in base:
            if any(x in p for x in SKIP_PATH_PARTS):
                continue
            if p not in manifest and not p.startswith("persist:"):
                fs.append(finding("WT-I003", "Skill or plugin file removed", "info", ["AST09"], p, "missing", "Confirm you removed it."))
    else:
        notes.append("No baseline yet: integrity drift starts next run.")

    # 3. persistence (ASI10)
    snap = persistence_snapshot()
    old = load_json(state_path("persistence.json"), None)
    if old is not None:
        for k, v in snap.items():
            if old.get(k) != v:
                fs.append(finding("WT-P001", "Persistence point changed", "medium", ["ASI10", "ASI05"], k,
                                  str(v)[:120], "Check who added this cron entry, unit, or shell rc change; remove it if no Bot of yours needs it."))
    save_json(state_path("persistence.json"), snap)

    # 4. secrets in files (known CLI credential files reported separately)
    fs += cli_credentials()
    known = {os.path.join(os.path.expanduser("~"), k) for k in KNOWN_CRED_FILES}
    fs += browser_sessions(roots)
    decoys = canary_paths()
    for p in walk(roots, max_depth=6):
        if p in known or p in decoys or os.path.basename(p) in SESSION_FILES:
            continue
        if os.path.splitext(p)[1].lower() not in TEXT_EXT:
            continue
        t = read_text(p, limit=300_000)
        if not t:
            continue
        if decoys:
            cp = canary_copies(t, p)
            if cp:
                fs.append(cp)
        rule = next(r for r in rules["rules"] if r["id"] == SECRET_RULE)
        hits = [m for m in rule["rx"].finditer(t) if looks_real_secret(m.group(0))]
        if hits:
            m = hits[0]
            fs.append(finding("WT-S001", "Secret stored in a file on the shared computer", "critical", ["ASI03", "LLM02"],
                              f"{p}:{line_of(t, m.start())}", f"{mask(m.group(0))} ({len(hits)} in file)",
                              "Every Bot can read this file. Revoke the key, delete the file, and use the secure secret request instead."))

    # 5. exports the user pastes in (routines, descriptions, Auto Review rules, settings)
    if exports and os.path.isdir(exports):
        for fn in sorted(os.listdir(exports)):
            p = os.path.join(exports, fn)
            t = read_text(p)
            if t is None:
                continue
            low = fn.lower()
            if low.startswith("routine"):
                fs += scan_text(t, f"export:{fn}", rules, kind="routine")
            elif low.startswith(("bot", "description", "skill", "template")):
                fs += scan_text(t, f"export:{fn}", rules, kind="description")
            elif low.startswith("auto-review") or low.startswith("autoreview"):
                fs += lint_auto_review(t, f"export:{fn}")
            elif low.startswith("settings") and low.endswith(".json"):
                fs += lint_settings(load_json(p, {}), f"export:{fn}")
    else:
        notes.append("No exports folder: routine text not checked (Auto Review rules come from settings.json).")

    nat = native_settings()
    if nat:
        rules_text, settings, p = nat
        if rules_text:
            fs += lint_auto_review(rules_text, p)
        else:
            fs.append(finding("WT-A005", "No Auto Review rules", "medium", ["ASI09"], p, "autoReviewInstructions empty",
                              "Add Ask-first rules for sending, publishing, purchasing, deleting, and changing settings or routines."))
        fs += lint_settings(settings, p)
    else:
        notes.append("Grok Bot settings.json not found: Auto Review rules and local execution checked from exports only.")

    # 5b. tripwires and shell history (zero tokens)
    fs += remember_events(canary_findings() + history_findings(rules))
    if not load_json(state_path("canaries.json"), {}):
        notes.append("No canaries planted: run `wt.py canary plant` for zero-cost tripwires.")
    rc = load_json(state_path("rollcall_findings.json"), None)
    if rc and rc.get("at", "") >= (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=35)).isoformat():
        fs += rc.get("findings", [])
    else:
        notes.append("No roll-call in the last 35 days: memories and other Bots' routines not checked (/watchtower-rollcall).")

    # 6. second and third engines on the user's skills plus anything new or changed; secrets; packages
    changed = {os.path.dirname(f["where"].split(":")[0]) for f in fs if f["rule"] in ("WT-I001", "WT-I002")}
    user_dirs = [os.path.dirname(x) for x in inv["skills"] if skill_tier(x) == "user"]
    user_roots = sorted({x.split("/workflows/")[0] + "/workflows" for x in user_dirs if "/workflows/" in x})
    if not quick:
        fs += engine_findings(user_dirs + sorted(changed), fs, notes, user_roots)
        fs += gitleaks_findings(roots, notes)
        fs += package_findings(notes)
    elif changed:
        fs += engine_findings(sorted(changed), fs, notes)

    fs = sort_findings(dedupe(fs))
    meta = {"inventory": {k: len(v) for k, v in inv.items()}, "notes": notes, "manifest": manifest, "persistence": snap}
    return fs, meta


NATIVE_SETTINGS = ["~/agent-data/settings.json", "/home/box/agent-data/settings.json"]


def native_settings():
    """Read Grok Bot's own settings file (spike, Oct 5 2026): autoReviewInstructions + localToolPermission.
    Returns (auto_review_text, settings_dict, path) or None. Schema is undocumented, so parse loosely."""
    cands = [os.environ["WATCHTOWER_SETTINGS"]] if os.environ.get("WATCHTOWER_SETTINGS") else NATIVE_SETTINGS
    for cand in cands:
        p = os.path.expanduser(cand)
        data = load_json(p, None)
        if not isinstance(data, dict):
            continue
        lines = []
        ari = data.get("autoReviewInstructions") or {}
        if isinstance(ari, dict):
            for k, v in ari.items():
                label = "Allow automatically" if "allow" in k.lower() else "Ask first" if "ask" in k.lower() else k
                items = v if isinstance(v, list) else [v]
                for it in items:
                    if isinstance(it, dict):
                        it = it.get("instruction") or it.get("text") or it.get("action") or json.dumps(it)
                    if isinstance(it, str) and it.strip():
                        lines.append(f"{label}: {it.strip()}")
        perm = str(data.get("localToolPermission", "")).lower()
        mapped = {"always": "always", "allow": "always", "ask": "ask", "never": "never", "deny": "never"}.get(perm, perm)
        settings = {"local_execution": mapped}
        if "autoReview" in data:
            settings["auto_review"] = bool(data.get("autoReview"))
        return "\n".join(lines), settings, p
    return None


def lint_auto_review(text, where):
    out = []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for i, l in enumerate(lines, 1):
        if re.search(r"(?i)allow\s+automatically", l) and re.search(r"(?i)\b(everything|anything|all|any)\b|\*|browser|all\s+commands", l):
            out.append(finding("WT-A001", "Broad Allow-automatically rule", "critical", ["ASI03", "ASI09"], f"{where}:{i}", l,
                               "Delete it. xAI's docs: avoid rules like 'allow everything in the browser'; keep allow rules to one command in one folder."))
        if re.search(r"(?i)allow\s+automatically", l) and re.search(r"(?i)\b(send|email|post|publish|purchase|pay|delete|transfer|permission)", l):
            out.append(finding("WT-A002", "Auto-allow on a consequential action", "critical", ["ASI02", "ASI09"], f"{where}:{i}", l,
                               "Change it to Ask first. Sending, paying, publishing and deleting always need your yes."))
        if re.search(r"(?i)allow\s+automatically", l) and re.search(r"(?i)(automation|routine|schedul|cron|trigger|create\s+(a\s+)?skill|install|plugin|connector)", l):
            out.append(finding("WT-A004", "Auto-allow on creating automations or installs", "high", ["ASI10", "ASI03"], f"{where}:{i}", l[:140],
                               "Change it to Ask first. Anything that creates a routine or installs code can give injected text a way to run again later, unattended."))
    ask = " ".join(l for l in lines if re.search(r"(?i)ask\s+first", l)).lower()
    missing = [w for w, rx in (("sending email or messages", r"send|email|message"), ("publishing or posting", r"publish|post"),
                               ("purchases or payments", r"purchas|pay|buy"), ("deleting data", r"delet|remov"),
                               ("changing permissions or settings", r"permission|setting")) if not re.search(rx, ask)]
    if missing:
        out.append(finding("WT-A003", "Missing Ask-first rules", "medium", ["ASI09"], where, ", ".join(missing),
                           "Add Ask-first rules in Settings → General → Auto-review for: " + ", ".join(missing) + "."))
    return out


def lint_settings(s, where):
    out = []
    le = str(s.get("local_execution", "")).lower()
    if le in ("always", "always allow", "always_allow"):
        out.append(finding("WT-C001", "Local-computer execution set to Always allow", "critical", ["ASI03", "ASI05"], where, le,
                           "Settings → General → Bot → Execution on Local Computer → Never allow (xAI's own recommendation)."))
    elif le in ("ask", "ask every time"):
        out.append(finding("WT-C002", "Local-computer execution set to Ask every time", "low", ["ASI03"], where, le,
                           "Fine if you use it; otherwise set Never allow."))
    if s.get("auto_review") is False:
        out.append(finding("WT-C003", "Auto Review is off", "high", ["ASI09"], where, "auto_review=false",
                           "Turn it on in Settings → General → Auto-review. It is fallible, but it is the only inline check."))
    for c in s.get("unused_connectors", []):
        out.append(finding("WT-C004", "Connector installed but unused", "low", ["ASI03"], where, c,
                           "Uninstall it and revoke its authorization in the source service."))
    return out


def tool(name):
    """Find a scanner on PATH or in Watchtower's own venv/bin (where install.sh --scanners puts them)."""
    for cand in (shutil.which(name), os.path.join(home(), ".venv", "bin", name), os.path.join(home(), "bin", name)):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def skillspector_scan(dirs, notes):
    """Run SkillSpector (static, no LLM) over skill folders. Returns {skill_dir: summary}."""
    exe = tool("skillspector")
    if not exe:
        notes.append("SkillSpector not installed: run install.sh --scanners for a second engine.")
        return {}
    res = {}
    tmp = state_path("skillspector.json")
    for d in dirs:
        run([exe, "scan", d, "--recursive", "--no-llm", "--format", "json", "--output", tmp], 600)
        data = load_json(tmp, None)
        if not isinstance(data, dict):
            continue
        skills = data.get("skills") if data.get("multi_skill") else [dict(data, path=".")]
        for sk in skills or []:
            ra = sk.get("risk_assessment") or {}
            issues = [i for i in sk.get("issues") or [] if isinstance(i, dict)]
            path = os.path.normpath(os.path.join(d, sk.get("path") or "."))
            res[path] = {"score": ra.get("score", sk.get("risk_score")), "recommendation": ra.get("recommendation", ""),
                         "issues": len(issues),
                         "top": sorted({f"{i.get('category')}: {i.get('pattern')}" for i in issues
                                        if i.get("severity") in ("CRITICAL", "HIGH")})[:4]}
        try:
            os.remove(tmp)
        except OSError:
            pass
    return res


def husk_scan(dirs, notes):
    """Run husk (static, obfuscation-focused) per skill folder. Returns {skill_dir: [messages]}."""
    exe = tool("husk")
    if not exe:
        notes.append("husk not installed: run install.sh --scanners for an obfuscation-focused engine.")
        return {}
    res = {}
    tmp = state_path("husk.sarif")
    for d in dirs[:150]:
        code, out_s, _ = run([exe, "package", d, "--output", tmp], 60)
        data = load_json(tmp, None) or {}
        msgs = [r.get("message", {}).get("text", "") for run_ in data.get("runs", []) for r in run_.get("results", [])]
        if msgs or "FLAGGED" in out_s:
            res[os.path.normpath(d)] = msgs or [out_s.strip()[:200]]
        try:
            os.remove(tmp)
        except OSError:
            pass
    return res


def engine_findings(skill_dirs, wt_findings, notes, user_root_dirs=()):
    """Second and third opinions. A skill is 'corroborated' only when two independent engines flag it."""
    out = []
    targets = sorted({os.path.normpath(d) for d in skill_dirs})
    roots = [d for d in user_root_dirs if os.path.isdir(d)]
    ss = skillspector_scan(roots, notes) if roots else {}
    extra = [d for d in targets if not any(d.startswith(r) for r in roots)]
    if extra:
        ss.update(skillspector_scan(extra, notes))
    hk = husk_scan(targets, notes)
    wt_hits = {}
    for f in wt_findings:
        if f["severity"] in ("critical", "high") and f["rule"].startswith("WT-T"):
            wt_hits.setdefault(os.path.dirname(f["where"].split(":")[0]), []).append(f["rule"])
    for d in sorted(set(ss) | set(hk)):
        s_ = ss.get(d, {})
        ss_flag = s_.get("recommendation") == "DO_NOT_INSTALL"
        hk_flag = d in hk
        wt_flag = any(k == d or k.startswith(d + "/") for k in wt_hits)
        tier = skill_tier(d + "/")
        engines = [n for n, v in (("SkillSpector", ss_flag), ("husk", hk_flag), ("Watchtower", wt_flag)) if v]
        detail = "; ".join(s_.get("top", [])[:2])
        if len(engines) >= 2:
            out.append(finding("WT-X003", "Corroborated by multiple engines", "critical" if tier == "user" else "high",
                               ["AST01", "AST08"], d, (" + ".join(engines) + (f"; {detail}" if detail else ""))[:150],
                               "Two independent engines agree. Disable this skill until you've read the flagged lines.", source="engines"))
        elif ss_flag:
            out.append(finding("WT-X001", "SkillSpector: do not install", "high" if tier == "user" else "medium", ["AST01", "AST08"], d,
                               f"risk {s_.get('score')}; {detail}"[:150],
                               "Run `skillspector scan <folder>` for the exact lines; one engine alone can be wrong.", source="skillspector"))
        elif hk_flag:
            out.append(finding("WT-X002", "husk flagged this skill", "medium" if tier == "user" else "low", ["AST01", "AST05"], d,
                               hk[d][0][:150], "Run `husk package <folder>` for details; one engine alone can be wrong.", source="husk"))
    save_json(state_path("engines.json"), {"at": now(), "skillspector": len(ss), "husk_flagged": len(hk), "targets": len(targets)})
    return out


GITLEAKS_CONFIG = r"""[extend]
useDefault = true

[allowlist]
description = "Watchtower: package caches and its own state"
paths = [
  '''(^|/)(go/pkg|pkg/mod|node_modules|\.cache|\.npm|\.venv|site-packages|dist-packages)/''',
  '''(^|/)watchtower/(state|reports|app|\.venv|bin)/''',
  '''chrome-cookie-seed\.json$''',
]
"""


def gitleaks_findings(roots, notes):
    exe = tool("gitleaks")
    if not exe:
        notes.append("gitleaks not installed: secrets checked with Watchtower's rules only.")
        return []
    out = []
    cfg = state_path("gitleaks.toml")
    with open(cfg, "w") as f:
        f.write(GITLEAKS_CONFIG)
    tmp = state_path("gitleaks.json")
    for r in roots:
        r = os.path.expanduser(r)
        if not os.path.isdir(r):
            continue
        run([exe, "detect", "--source", r, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
             "--report-path", tmp, "--exit-code", "0", "--max-target-megabytes", "5"], 600)
        per_file = {}
        for leak in load_json(tmp, []) or []:
            per_file.setdefault(leak.get("File"), []).append(leak)
        for fpath, leaks in per_file.items():
            kinds = sorted({l.get("RuleID", "secret") for l in leaks})
            generic = all(k.startswith("generic") for k in kinds)
            out.append(finding("WT-S002", "gitleaks: secrets in file", "medium" if generic else "critical", ["ASI03", "LLM02"],
                               f"{fpath}:{leaks[0].get('StartLine')}", f"{len(leaks)} hit(s): {', '.join(kinds)[:100]}",
                               "Check whether these are live credentials. Revoke live ones, then delete or scrub the file.", source="gitleaks"))
        try:
            os.remove(tmp)
        except OSError:
            pass
    return out


def installed_python_packages():
    """Packages in the computer's own Python, not Watchtower's venv."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"]: p["version"] for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        return {}


def package_findings(notes):
    exe = tool("pip-audit")
    if not exe:
        notes.append("pip-audit not installed: installed Python packages not checked for known vulnerabilities.")
        return []
    pkgs = installed_python_packages()
    if not pkgs:
        return []
    req = state_path("installed-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items())))
    code, out_s, _ = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 600)
    out = []
    try:
        data = json.loads(out_s) if out_s.strip() else {}
    except ValueError:
        data = {}
    for d in (data.get("dependencies", []) if isinstance(data, dict) else []):
        vulns = d.get("vulns", [])
        if not vulns:
            continue
        fixes = sorted({fv for v in vulns for fv in v.get("fix_versions", [])}, key=vtuple)
        ids = list(dict.fromkeys(v.get("id", "") for v in vulns))
        out.append(finding("WT-D001", f"Vulnerable package {d.get('name')} {d.get('version')}", "high", ["ASI04", "AST02"],
                           f"python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                           f"Upgrade to {fixes[-1]} or later." if fixes else "No fixed version yet; remove it if nothing needs it.",
                           source="pip-audit"))
    save_json(state_path("package_vulns.json"), {"at": now(), "packages": len(pkgs), "findings": out})
    return out


def find_key(obj, keys):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and isinstance(obj[k], (int, float)):
                return obj[k]
        for v in obj.values():
            r = find_key(v, keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, keys)
            if r is not None:
                return r
    return None


def active(findings):
    sup = load_json(state_path("suppressions.json"), [])
    today = dt.date.today().isoformat()
    live = {s["key"] for s in sup if s.get("expires", "9999") >= today}
    return [f for f in findings if f["key"] not in live], [f for f in findings if f["key"] in live]


def ledger(event):
    event["at"] = now()
    with open(state_path("ledger.jsonl"), "a") as f:
        f.write(json.dumps(event) + "\n")


def run_audit(args, quick):
    roots = args.roots or [os.path.expanduser("~"), "/workspace"]
    exports = args.exports or os.path.join(home(), "exports")
    start = dt.datetime.now()
    fs, meta = audit(roots, exports, quick=quick)
    if quick:  # the daily run skips the slow engines; keep their last results instead of calling them fixed
        prev_snap = load_json(state_path("last_findings.json"), {"findings": []})
        have = {f["key"] for f in fs}
        rescanned = {f["where"] for f in fs if f["rule"].startswith("WT-X")}
        for f in prev_snap.get("findings", []):
            if f["rule"] in SLOW_RULES and f["key"] not in have and f["where"] not in rescanned:
                fs.append(f)
        fs = sort_findings(fs)
    live, suppressed = active(fs)
    prev = load_json(state_path("last_findings.json"), {"findings": []})
    prev_keys = {f["key"] for f in prev.get("findings", [])}
    cur_keys = {f["key"] for f in live}
    new = [f for f in live if f["key"] not in prev_keys and f["severity"] != "info"]
    fixed = [f for f in prev.get("findings", []) if f["key"] not in cur_keys]
    s, g = score(live)
    if not load_json(state_path("baseline.json"), {}):
        save_json(state_path("baseline.json"), meta["manifest"])
    snapshot = {"at": now(), "version": VERSION, "score": s, "grade": g, "findings": live, "suppressed": suppressed,
                "inventory": meta["inventory"], "notes": meta["notes"]}
    save_json(state_path("last_findings.json"), snapshot)
    with open(state_path("score_history.csv"), "a") as f:
        f.write(f"{snapshot['at']},{s},{len(live)}\n")
    elapsed = round((dt.datetime.now() - start).total_seconds(), 1)
    ledger({"event": "daily" if quick else "audit", "score": s, "findings": len(live), "new": len(new), "fixed": len(fixed), "seconds": elapsed})
    return snapshot, new, fixed


SLOW_RULES = ("WT-X001", "WT-X002", "WT-X003", "WT-S002", "WT-D001")


def compact(f):
    return {k: f[k] for k in ("rule", "severity", "title", "where", "evidence", "fix", "owasp")}


def cmd_audit(args):
    snap, new, fixed = run_audit(args, quick=False)
    out = {"score": snap["score"], "grade": snap["grade"], "new": [compact(f) for f in new][:20],
           "fixed": [compact(f) for f in fixed][:10], "open_by_severity": by_sev(snap["findings"]),
           "top_fixes": [compact(f) for f in snap["findings"][:3]], "notes": snap["notes"], "inventory": snap["inventory"]}
    print(fit(out))
    return 0


def fit(obj, limit=4096):
    """Keep the model handoff under `limit` bytes by trimming the longest list, never by cutting JSON."""
    obj = json.loads(json.dumps(obj))
    while len(json.dumps(obj, indent=1)) > limit:
        lists = [(len(v), k) for k, v in obj.items() if isinstance(v, list) and v]
        if not lists:
            break
        _, k = max(lists)
        obj.setdefault("truncated", {})
        obj["truncated"][k] = obj["truncated"].get(k, 0) + 1
        obj[k].pop()
    return json.dumps(obj, indent=1)


def cmd_daily(args):
    snap, new, fixed = run_audit(args, quick=True)
    if not new and not fixed:
        print("NO_CHANGES")
        return 0
    out = {"score": snap["score"], "new": [compact(f) for f in new][:15], "fixed": [compact(f) for f in fixed][:10]}
    print(fit(out))
    return 0


def cmd_baseline(args):
    roots = args.roots or [os.path.expanduser("~"), "/workspace"]
    fs, meta = audit(roots, None, quick=True)
    save_json(state_path("baseline.json"), meta["manifest"])
    ledger({"event": "baseline", "files": len(meta["manifest"])})
    print(f"Baseline saved: {len(meta['manifest'])} skill and plugin files.")
    return 0


def cmd_breakdown(args):
    snap = load_json(state_path("last_findings.json"), None)
    if not snap:
        print("ERROR no audit yet", file=sys.stderr)
        return 2
    rows = {}
    for f in snap["findings"]:
        r = rows.setdefault((f["severity"], f["rule"], f["title"]), {"n": 0, "dirs": {}})
        r["n"] += 1
        d = os.path.dirname(f["where"].split(":")[0])
        top = "/".join(d.split("/")[:5])
        r["dirs"][top] = r["dirs"].get(top, 0) + 1
    for (sev, rule, title), r in sorted(rows.items(), key=lambda x: (SEV_ORDER.index(x[0][0]), -x[1]["n"])):
        dirs = ", ".join(f"{k} ×{v}" for k, v in sorted(r["dirs"].items(), key=lambda x: -x[1])[:3])
        print(f"{sev:8} {rule:8} ×{r['n']:<5} {title[:48]:48} {dirs}")
    return 0


def cmd_show(args):
    snap = load_json(state_path("last_findings.json"), None)
    if not snap:
        print("ERROR no audit yet", file=sys.stderr)
        return 2
    rows = [f for f in snap["findings"] if f["rule"] == args.rule][: args.limit]
    for f in rows:
        print(f"{f['severity']} {f['rule']} {f['where']}\n  evidence: {f['evidence']}")
        path, _, ln = f["where"].rpartition(":")
        if args.rule in ("WT-T011", "WT-S001", "WT-S002", "WT-S003") or not ln.isdigit():
            continue
        t = read_text(path) or ""
        lines = t.splitlines()
        i = int(ln) - 1
        ctx = " ".join(lines[max(0, i - 1): i + 2])[:300]
        print(f"  context: {ctx}")
    return 0


def by_sev(fs):
    c = {s: 0 for s in SEV_ORDER}
    for f in fs:
        c[f["severity"]] += 1
    return c


# ---------------------------------------------------------------- report
def cmd_report(args):
    snap = load_json(state_path("last_findings.json"), None)
    if not snap:
        print("ERROR no audit yet: run `wt audit` first", file=sys.stderr)
        return 2
    hist = []
    try:
        with open(state_path("score_history.csv")) as f:
            for line in f:
                a, s, n = line.strip().split(",")
                hist.append((a, int(s), int(n)))
    except OSError:
        pass
    week = dt.date.today().isocalendar()
    tag = f"{week[0]}-W{week[1]:02d}"
    rdir = os.path.join(home(), "reports")
    os.makedirs(rdir, exist_ok=True)
    md = render_md(snap, hist, tag)
    with open(os.path.join(rdir, f"{tag}.md"), "w") as f:
        f.write(md)
    with open(os.path.join(rdir, "dashboard.html"), "w") as f:
        f.write(render_html(snap, hist, tag))
    ledger({"event": "report", "week": tag, "score": snap["score"]})
    try:
        print("\n".join(md.splitlines()[:14]))
    except BrokenPipeError:
        pass
    print(f"\nFull report: {rdir}/{tag}.md · Dashboard: {rdir}/dashboard.html")
    return 0


def trend(hist):
    weekly = hist[-1:] if hist else []
    if len(hist) >= 2:
        prev = [h for h in hist if h[0][:10] <= (dt.date.today() - dt.timedelta(days=6)).isoformat()]
        if prev:
            d = hist[-1][1] - prev[-1][1]
            return f"{'+' if d >= 0 else ''}{d} vs last week"
    return "first week"


def render_md(snap, hist, tag):
    fs = snap["findings"]
    c = by_sev(fs)
    lines = [f"# Watchtower report {tag}", "",
             f"Score {snap['score']}/100 (grade {snap['grade']}), {trend(hist)}. Open findings: "
             f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low.", "",
             "## Top fixes", ""]
    for i, f in enumerate(fs[:3], 1):
        lines.append(f"{i}. **{f['title']}** ({f['severity']}, {', '.join(f['owasp'])}) at `{f['where']}`. {f['fix']}")
    if not fs:
        lines.append("Nothing to fix this week.")
    lines += ["", "## All open findings", "", "| Severity | Rule | Finding | Where | Evidence | OWASP |", "| --- | --- | --- | --- | --- | --- |"]
    lows = [f for f in fs if f["severity"] in ("low", "info")]
    for f in [f for f in fs if f["severity"] not in ("low", "info")]:
        ev = f["evidence"].replace("|", "\\|")
        lines.append(f"| {f['severity']} | {f['rule']} | {f['title']} | `{f['where']}` | {ev} | {', '.join(f['owasp'])} |")
    if lows:
        by_rule = {}
        for f in lows:
            by_rule[(f["rule"], f["title"])] = by_rule.get((f["rule"], f["title"]), 0) + 1
        lines += ["", "Hygiene notes (low): " + "; ".join(f"{t} ×{n}" for (r, t), n in sorted(by_rule.items(), key=lambda x: -x[1]))]
    inv = snap.get("inventory", {})
    lines += ["", "## Inventory", "", f"Skills on disk: {inv.get('skills', 0)} · plugin files: {inv.get('plugin_files', 0)} · MCP configs: {inv.get('mcp_configs', 0)}"]
    if snap.get("suppressed"):
        lines += ["", "## Accepted risks", ""] + [f"- {f['rule']} {f['title']} at `{f['where']}`" for f in snap["suppressed"]]
    lb = load_json(state_path("last_brief.json"), None)
    if lb and lb.get("tag") == tag:
        lines += ["", "## Threat brief", "", f"Open `{lb['path']}` in a browser: {len(lb.get('research', []))} research items, "
                  f"{sum(1 for k in lb.get('kev', []) if k.get('relevant'))} relevant exploited vulnerabilities."]
    if snap.get("notes"):
        lines += ["", "## Coverage notes", ""] + [f"- {n}" for n in snap["notes"]]
    lines += ["", f"_Watchtower {VERSION}, read-only. Scanners can be bypassed; this report is evidence, not proof._", ""]
    return "\n".join(lines)


def render_html(snap, hist, tag):
    fs = snap["findings"]
    c = by_sev(fs)
    pts = hist[-12:] or [(snap["at"], snap["score"], len(fs))]
    w, h = 320, 70
    step = w / max(1, len(pts) - 1)
    poly = " ".join(f"{round(i * step, 1)},{round(h - p[1] / 100 * h, 1)}" for i, p in enumerate(pts))
    colors = {"critical": "#c0392b", "high": "#d35400", "medium": "#b7950b", "low": "#2e86c1", "info": "#7f8c8d"}
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{colors[f['severity']]}'>{f['severity']}</span></td>"
        f"<td>{html.escape(f['title'])}</td><td><code>{html.escape(f['where'])}</code></td>"
        f"<td>{html.escape(', '.join(f['owasp']))}</td><td>{html.escape(f['fix'])}</td></tr>" for f in [x for x in fs if x["severity"] not in ("low", "info")][:60])
    tiles = "".join(f"<div class='tile'><b style='color:{colors[s]}'>{c[s]}</b><span>{s}</span></div>" for s in SEV_ORDER[:4])
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Watchtower {tag}</title><style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#e3e6ea}}@media(prefers-color-scheme:dark){{:root{{--bg:#111418;--fg:#e8eaed;--mut:#9aa3ad;--line:#2a3038}}}}
body{{font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px}}
h1{{font-size:20px;margin:0 0 4px}}.mut{{color:var(--mut)}}.row{{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}}
.card{{border:1px solid var(--line);border-radius:10px;padding:16px}}.big{{font-size:44px;font-weight:700}}
.tile{{border:1px solid var(--line);border-radius:10px;padding:12px 18px;text-align:center}}.tile b{{font-size:26px;display:block}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;text-transform:uppercase}}.wrap{{overflow-x:auto}}code{{font-size:12px}}
</style></head><body><h1>Watchtower · {tag}</h1><div class='mut'>Generated {html.escape(snap['at'])} · read-only audit of this Grok Bot computer</div>
<div class='row'><div class='card'><div class='mut'>Posture score</div><div class='big'>{snap['score']}<span class='mut' style='font-size:18px'>/100 · {snap['grade']}</span></div><div class='mut'>{trend(hist)}</div></div>
<div class='card'><div class='mut'>Score, last {len(pts)} runs</div><svg width='{w}' height='{h}' viewBox='0 0 {w} {h}' role='img' aria-label='score trend'><polyline fill='none' stroke='#2e86c1' stroke-width='2' points='{poly}'/></svg></div>
{tiles}</div><h2 style='font-size:16px'>Open findings</h2><div class='wrap'><table><tr><th>Severity</th><th>Finding</th><th>Where</th><th>OWASP</th><th>Fix</th></tr>{rows or "<tr><td colspan=5>Nothing open.</td></tr>"}</table></div>
<p style='margin-top:16px'>{f"<a href='threat-brief-{tag}.html'>Open this week's threat brief →</a>" if os.path.exists(os.path.join(home(), "reports", f"threat-brief-{tag}.html")) else ""}</p>
<p class='mut' style='margin-top:20px'>Watchtower {VERSION}. Scanners can be bypassed; this is evidence, not proof.</p></body></html>"""


# ---------------------------------------------------------------- one-time events (history, canaries) stay open
EVENT_DAYS = 14


def remember_events(new):
    """History lines and canary trips happen once. Keep them open for EVENT_DAYS so the next run
    doesn't report them as fixed; suppress one (wt.py show + suppressions.json) to close it sooner."""
    store = load_json(state_path("events.json"), [])
    known = {e["key"] for e in store}
    for f in new:
        if f["key"] not in known:
            store.append(dict(f, first_seen=now()))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=EVENT_DAYS)).isoformat()
    store = [e for e in store if e.get("first_seen", "") >= cutoff]
    save_json(state_path("events.json"), store)
    return [{k: v for k, v in e.items() if k != "first_seen"} for e in store]


# ---------------------------------------------------------------- shell history (closest thing to Action Recording)
HISTORY_FILES = ("~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history", "~/.python_history")
HISTORY_RULES = [
    ("WT-H001", "Script piped into a shell from an unknown host", "high", ["ASI05", "AST02"],
     r"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ("WT-H002", "Decoded payload executed", "critical", ["ASI05"], r"base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba|z)?sh|python3?\s+-c\s+['\"].{0,40}(exec|b64decode)"),
    ("WT-H003", "Reverse shell pattern", "critical", ["ASI05", "ASI10"],
     r"(bash\s+-i\s*>&\s*/dev/tcp/|nc(at)?\s+[^\n]{0,40}-e\s|mkfifo\s+/tmp/[^\n]{0,60}\bnc\b|socat\s+[^\n]{0,60}exec:)"),
    ("WT-H004", "Credential store read", "high", ["ASI03"],
     r"(cat|less|head|tail|cp|scp|base64)\s+[^\n]{0,40}(\.ssh/id_|\.aws/credentials|\.git-credentials|\.netrc|credentials\.json|cookie)"),
    ("WT-H005", "File uploaded with curl", "high", ["ASI04"], r"curl\s[^\n]{0,200}(-d\s*@|--data(-binary)?\s*@|-F\s*\S*=@|-T\s)"),
    ("WT-H006", "History tampering", "high", ["ASI10"], r"(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*~?/?\.?bash_history|shred\s+[^\n]*history)"),
    ("WT-H007", "World-writable permissions", "medium", ["ASI03"], r"chmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b"),
    ("WT-H008", "New persistence added", "medium", ["ASI10"], r"(crontab\s+(-\s*$|-r|[^\s-])|>>\s*~?/?\.(bashrc|profile|zshrc)|systemctl\s+(--user\s+)?enable)"),
    ("WT-H009", "Environment dumped to a file or the network", "high", ["ASI03"], r"\b(env|printenv|set)\s*(>|\|\s*(curl|nc|tee))"),
]


def history_findings(rules):
    out, offsets = [], load_json(state_path("history_offsets.json"), {})
    compiled = [(i, t, s, o, re.compile(rx, re.I | re.M)) for i, t, s, o, rx in HISTORY_RULES]
    secret = next(r["rx"] for r in rules["rules"] if r["id"] == SECRET_RULE)
    for hf in HISTORY_FILES:
        p = os.path.expanduser(hf)
        if not os.path.isfile(p):
            continue
        size = os.path.getsize(p)
        start = offsets.get(p, 0)
        if start > size:  # truncated or rotated
            start = 0
            out.append(finding("WT-H006", "Shell history shrank since last check", "medium", ["ASI10"], p,
                               f"{offsets.get(p)} → {size} bytes", "Something cleared or rotated the history. Confirm it was you."))
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            f.seek(start)
            chunk = f.read()
        offsets[p] = size
        for n, line in enumerate(chunk.splitlines(), 1):
            line = re.sub(r"^: \d+:\d+;", "", line)  # zsh extended history prefix
            for rid, title, sev, owasp, rx in compiled:
                if rx.search(line):
                    if rid == "WT-H001" and KNOWN_INSTALLERS.search(line):
                        continue
                    shown = secret.sub(lambda m: mask(m.group(0)), line)[:160]
                    out.append(finding(rid, title, sev, owasp, f"{p}:+{n}", shown,
                                       "Find which Bot or session ran this (Agent Computer view, routine runs). If none of yours meant to, run /watchtower-incident."))
                    break
    save_json(state_path("history_offsets.json"), offsets)
    return out


# ---------------------------------------------------------------- canaries (zero-token tripwires)
CANARY_SPECS = [
    ("customers", "/workspace/.archive/customers-export-2025.csv",
     "name,email,phone,card_last4,notes\nDana Whitfield,{tok}@example.com,555-0101,4417,priority account\n"),
    ("cloud-keys", "~/.config/backup/aws-credentials.bak",
     "[default]\naws_access_key_id = AKIA{tokU}\naws_secret_access_key = {tok}{tok}\n"),
    ("api-env", "/workspace/.archive/payments.env", "STRIPE_SECRET_KEY=rk_live_{tok}{tok}\nPAYOUT_ACCOUNT=acct_{tok}\n"),
]


def canary_paths():
    reg = load_json(state_path("canaries.json"), {})
    return {os.path.expanduser(v["path"]) for v in reg.values()}


def cmd_canary(args):
    reg = load_json(state_path("canaries.json"), {})
    if args.action == "plant":
        import secrets as _s
        for name, path, body in CANARY_SPECS:
            p = os.path.expanduser(path)
            if name in reg and os.path.exists(p):
                continue
            tok = _s.token_hex(8)
            content = body.format(tok=tok, tokU=tok.upper()[:16])
            if args.token_file and name == "cloud-keys":
                content = open(args.token_file).read()
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
            st = os.stat(p)
            os.utime(p, (st.st_mtime - 86400, st.st_mtime))  # atime < mtime so the next read updates atime
            reg[name] = {"path": path, "token": tok, "atime": os.stat(p).st_atime, "planted": now()}
        save_json(state_path("canaries.json"), reg)
        probe = state_path("atime-probe")
        with open(probe, "w") as f:
            f.write("x")
        st = os.stat(probe)
        os.utime(probe, (st.st_mtime - 86400, st.st_mtime))
        before = os.stat(probe).st_atime
        with open(probe) as pf:
            pf.read()
        reads_tracked = os.stat(probe).st_atime > before + 1
        os.remove(probe)
        print(f"Planted {len(reg)} canaries: " + ", ".join(v["path"] for v in reg.values()))
        if not reads_tracked:
            print("Note: this filesystem doesn't record reads, so canaries will catch deletion and copying, not reading.")
        ledger({"event": "canary-plant", "count": len(reg)})
        return 0
    if args.action == "remove":
        for v in reg.values():
            try:
                os.remove(os.path.expanduser(v["path"]))
            except OSError:
                pass
        save_json(state_path("canaries.json"), {})
        print("Canaries removed.")
        return 0
    fs = canary_findings()
    print(json.dumps([compact(f) for f in fs], indent=1) if fs else "CANARIES_QUIET")
    return 0


def canary_findings():
    reg = load_json(state_path("canaries.json"), {})
    out, changed = [], False
    for name, v in reg.items():
        p = os.path.expanduser(v["path"])
        if not os.path.exists(p):
            out.append(finding("WT-K002", "Canary file deleted or moved", "high", ["ASI10"], p, name,
                               "Something removed a decoy. Check recent routine runs, then re-plant with `wt.py canary plant`."))
            continue
        st = os.stat(p)
        if st.st_atime > v["atime"] + 1:
            out.append(finding("WT-K001", "Canary file was read", "critical", ["ASI03", "ASI10"], p,
                               f"{name} read at {dt.datetime.fromtimestamp(st.st_atime, dt.timezone.utc).isoformat(timespec='minutes')}",
                               "Nothing legitimate needs this decoy. Find which Bot or routine read it (Agent Computer view, run history). "
                               "It may be a Bot searching all files, or a skill hunting for credentials. Run /watchtower-incident."))
            os.utime(p, (st.st_mtime - 86400, st.st_mtime))  # re-arm
            v["atime"] = os.stat(p).st_atime
            changed = True
    if changed:
        save_json(state_path("canaries.json"), reg)
    return out


def canary_copies(text, path):
    reg = load_json(state_path("canaries.json"), {})
    for name, v in reg.items():
        if v.get("token") and v["token"] in text and os.path.expanduser(v["path"]) != path:
            return finding("WT-K003", "Canary value copied into another file", "critical", ["ASI03", "ASI04"], path, name,
                           "A decoy's contents turned up somewhere else: something read it and wrote it out. Run /watchtower-incident.")
    return None


# ---------------------------------------------------------------- roll-call: memories, routines, connectors per Bot
MEMORY_DIRECTIVE = re.compile(
    r"(?i)\b(always|never|from now on|whenever|every time|automatically|by default|without asking|don'?t ask|skip (the )?approval|"
    r"no need to (ask|confirm)|treat .{0,30} as (trusted|authori[sz]ed)|has (admin|full) (access|permission))\b")
PRIVATE_DATA = re.compile(r"(?i)\b(gmail|outlook|email|drive|docs|notion|slack|calendar|granola|dropbox|supabase|crm|hubspot|salesforce)\b")
UNTRUSTED_IN = re.compile(r"(?i)\b(web|browser|search|x\b|twitter|rss|inbox|incoming|reddit|scrape|tinyfish|fetch)\b")
EXTERNAL_OUT = re.compile(r"(?i)\b(send|reply|post|publish|tweet|email|message|slack|share|upload|webhook|x\b)\b")


def rollcall_findings(rdir):
    rules = load_rules()
    out, bots = [], []
    if not os.path.isdir(rdir):
        return out, bots
    for fn in sorted(os.listdir(rdir)):
        if not fn.endswith(".json"):
            continue
        p = os.path.join(rdir, fn)
        d = load_json(p, None)
        if not isinstance(d, dict):
            out.append(finding("WT-R010", "Roll-call reply did not parse", "low", ["ASI07"], p, fn,
                               "Ask that Bot again; a Bot that won't describe itself is worth a closer look."))
            continue
        name = d.get("name") or fn[:-5]
        bots.append(name)
        where = f"rollcall:{name}"
        mems = d.get("memories") or []
        mems = mems if isinstance(mems, list) else [mems]
        for i, m in enumerate(mems, 1):
            t = m if isinstance(m, str) else json.dumps(m)
            for f in scan_text(t, f"{where}:memory{i}", rules, kind="reference"):
                f["owasp"] = ["ASI06"] + [o for o in f["owasp"] if o != "ASI06"]
                out.append(f)
            if MEMORY_DIRECTIVE.search(t) and (EXTERNAL_OUT.search(t) or re.search(r"(?i)approv|permission|trust|access", t)):
                out.append(finding("WT-M010", "Memory acts as a standing instruction", "medium", ["ASI06"], f"{where}:memory{i}", t[:150],
                                   "Memories steer every future run, and Auto Review doesn't check memory writes. "
                                   "If you didn't put this there on purpose, remove it in that Bot's memory settings."))
        for r in d.get("routines") or []:
            if isinstance(r, dict):
                t = " ".join(str(r.get(k, "")) for k in ("schedule", "trigger", "instructions", "prompt"))
                out += scan_text(t, f"{where}:routine:{r.get('name', '?')}", rules, kind="routine")
        if d.get("description"):
            out += scan_text(str(d["description"]), f"{where}:description", rules, kind="description")
        conns = " ".join(map(str, d.get("connectors") or []))
        routines_text = " ".join(json.dumps(r) for r in d.get("routines") or [])
        if PRIVATE_DATA.search(conns) and UNTRUSTED_IN.search(conns + " " + routines_text) and EXTERNAL_OUT.search(conns + " " + routines_text):
            out.append(finding("WT-L001", "Lethal trifecta: private data + untrusted input + a way out", "high", ["ASI01", "ASI02"], where,
                               conns[:150],
                               "This Bot can read private data, reads content strangers control, and can send outward. "
                               "That's the combination prompt injection needs. Split the jobs across Bots or put Ask first on every send."))
    save_json(state_path("rollcall_findings.json"), {"at": now(), "bots": bots, "findings": out})
    return out, bots


def cmd_rollcall(args):
    rdir = args.dir or os.path.join(home(), "exports", "rollcall")
    fs, bots = rollcall_findings(rdir)
    print(fit({"bots": bots, "findings": [compact(f) for f in sort_findings(fs)][:30], "by_severity": by_sev(fs)}))
    ledger({"event": "rollcall", "bots": len(bots), "findings": len(fs)})
    return 0


ROLLCALL_PROMPT = ("Watchtower roll-call. Reply with only a JSON object, no prose: "
                   '{"name": "...", "description": "...", "skills": ["..."], '
                   '"routines": [{"name": "...", "schedule": "...", "instructions": "..."}], '
                   '"connectors": ["..."], "memories": ["each stored memory, verbatim"]}')


# ---------------------------------------------------------------- pre-publish check (before Share → Create template)
PREPUB_RULES = [
    ("WT-PP01", "Email address", "medium", r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    ("WT-PP02", "Phone number", "medium", r"(?<!\d)(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    ("WT-PP03", "Private network address or internal host", "high",
     r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|[\w-]+\.(internal|local|corp|lan))\b"),
    ("WT-PP04", "Link to a private doc, drive or workspace", "high",
     r"(docs\.google\.com/\S+|drive\.google\.com/\S+|notion\.so/\S+|[\w-]+\.slack\.com/\S+|airtable\.com/\S+|app\.hubspot\.com/\S+|1[\w-]{30,}\b)"),
    ("WT-PP05", "Path that only exists on your computer", "medium", r"(/home/box/\S+|/workspace/\S+|/Users/\w+/\S+)"),
    ("WT-PP06", "Depends on something templates don't carry", "medium",
     r"(?i)\b(mcp server|custom mcp|run (the|this|my) script|\.py\b|\.sh\b|my local|localhost:\d+)"),
]


def cmd_prepublish(args):
    rules = load_rules()
    paths = []
    if args.path == "-":
        texts = [("stdin", sys.stdin.read())]
    else:
        for root, _, files in (os.walk(args.path) if os.path.isdir(args.path) else [(os.path.dirname(args.path), [], [os.path.basename(args.path)])]):
            for fn in files:
                paths.append(os.path.join(root, fn))
        texts = [(p, read_text(p) or "") for p in paths]
    fs = []
    for where, t in texts:
        fs += [f for f in scan_text(t, where, rules, kind="template") if f["rule"] in ("WT-T011", "WT-T013", "WT-T007", "WT-T008", "WT-T005", "WT-T006")]
        for rid, title, sev, rx in PREPUB_RULES:
            for m in re.finditer(rx, t):
                ev = m.group(0)
                if rid == "WT-PP01" and re.search(r"(?i)(example\.(com|org)|noreply|no-reply)", ev):
                    continue
                if rid == "WT-PP05" and "/workspace/watchtower" in ev:
                    continue
                fs.append(finding(rid, title, sev, ["AST04", "LLM02"], f"{where}:{line_of(t, m.start())}", mask(ev) if rid in ("WT-PP01", "WT-PP02") else ev[:120],
                                  "Remove or generalize it before you create the template: anything in a description, skill or routine ships to every installer."))
        if not has_approval(t, rules) and rules["write_verbs"].search(t):
            fs.append(finding("WT-PP07", "No approval boundary", "high", ["ASI02"], where, "no approval line",
                              "Add: never send, post, buy, publish, delete, or change settings without my approval."))
    fs = sort_findings(dedupe(fs))
    blocking = [f for f in fs if f["severity"] in ("critical", "high")]
    result = {"verdict": "FAIL" if blocking else "PASS", "blocking": len(blocking), "findings": [compact(f) for f in fs][:40]}
    print(fit(result) if args.json else
          f"Pre-publish: {result['verdict']} ({len(blocking)} blocking, {len(fs)} total)\n" +
          "\n".join(f"  [{f['severity'].upper()}] {f['title']} @ {f['where']} :: {f['evidence']}" for f in fs[:40]))
    return 1 if blocking else 0


# ---------------------------------------------------------------- incident mode (evidence first, containment with approval)
CONTAINMENT = [
    "Pause every routine on the affected Bot (and any Bot that shares its connectors).",
    "In the Grok Bot browser, sign out of sensitive sites; then log out all sessions from each site's security settings.",
    "Disconnect connectors the affected Bot uses (Marketplace → Your plugins) and revoke them in the source service.",
    "Rotate CLI credentials on the computer (GitHub CLI, cloud CLIs) and any key found in the evidence.",
    "Disable or delete the skill, plugin or template that triggered this; keep a copy in /workspace/watchtower/incidents for review.",
    "If you can't explain what ran, reset the cloud computer (Settings → Computer) after saving what you need.",
]


def cmd_incident(args):
    rules = load_rules()
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%MZ")
    idir = os.path.join(home(), "incidents")
    os.makedirs(idir, exist_ok=True)
    snap = load_json(state_path("last_findings.json"), {"findings": []})
    secret = next(r["rx"] for r in rules["rules"] if r["id"] == SECRET_RULE)
    clean = lambda t: secret.sub(lambda m: mask(m.group(0)), t or "")
    _, ps, _ = run(["ps", "-eo", "pid,ppid,user,etime,cmd", "--sort=-etime"], 20)
    _, net, _ = run(["ss", "-tunp"], 20)
    _, cron, _ = run(["crontab", "-l"], 10)
    _, timers, _ = run(["systemctl", "--user", "list-timers", "--all", "--no-pager"], 10)
    recent = []
    for r in [os.path.expanduser("~"), "/workspace"]:
        for p in walk([r], max_depth=6):
            try:
                if os.path.getmtime(p) > dt.datetime.now().timestamp() - 86400 and p not in canary_paths():
                    recent.append(p)
            except OSError:
                pass
    tails = []
    for hf in HISTORY_FILES:
        p = os.path.expanduser(hf)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                tails += [f"{hf}: {clean(l.rstrip())[:200]}" for l in f.readlines()[-40:]]
    hot = [f for f in snap.get("findings", []) if f["severity"] in ("critical", "high")]
    ledger_tail = []
    try:
        with open(state_path("ledger.jsonl")) as f:
            ledger_tail = f.readlines()[-20:]
    except OSError:
        pass
    md = [f"# Watchtower incident {ts}", "", f"Reported: {args.note or '(no description given)'}", "",
          "## Containment checklist (each step needs your yes)", ""] + [f"{i}. [ ] {c}" for i, c in enumerate(CONTAINMENT, 1)] + [
          "", "## Open critical and high findings", ""] + [f"- {f['severity']} {f['rule']} {f['title']} at `{f['where']}` ({f['evidence']})" for f in hot[:40]] + [
          "", "## Canaries", "", "\n".join(f"- {f['title']} at `{f['where']}`" for f in canary_findings()) or "- quiet",
          "", "## Files changed in the last 24 hours", ""] + [f"- `{p}`" for p in sorted(recent)[:150]] + [
          "", "## Shell history (last 40 lines per file, secrets masked)", "", "```"] + tails + ["```",
          "", "## Processes", "", "```", clean(ps)[:8000], "```", "", "## Network connections", "", "```", clean(net)[:6000], "```",
          "", "## Scheduled jobs", "", "```", clean(cron)[:2000], clean(timers)[:2000], "```",
          "", "## Watchtower ledger (last 20 runs)", "", "```"] + [l.rstrip() for l in ledger_tail] + ["```", ""]
    path = os.path.join(idir, f"incident-{ts}.md")
    with open(path, "w") as f:
        f.write("\n".join(md))
    ledger({"event": "incident", "file": path, "hot": len(hot)})
    print(fit({"evidence_pack": path, "open_critical_high": len(hot), "changed_24h": len(recent),
               "top": [compact(f) for f in hot[:5]], "containment": CONTAINMENT}))
    return 0


# ---------------------------------------------------------------- OWASP Top 10 (2021) code review for code your Bots write
CODE_RULES = [
    ("A01", "Broken access control", "high", r"(?i)(@app\.route\([^)]*\)\s*\n\s*def\s+\w+\([^)]*\):(?![\s\S]{0,200}(login_required|auth|current_user))|cors\(\s*\w+\s*,\s*origins\s*=\s*['\"]\*|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*)"),
    ("A02", "Cryptographic failure", "high", r"(?i)(hashlib\.(md5|sha1)\(|createHash\(['\"](md5|sha1)|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context|Math\.random\(\)[^\n]{0,40}(token|secret|password|key))"),
    ("A03", "Injection", "critical", r"(?i)((execute|executemany|raw|query)\(\s*f?['\"][^'\"]*(select|insert|update|delete)[^'\"]*['\"]\s*(%|\+|\.format)|(execute|query)\(\s*f['\"][^'\"]*\{|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|child_process\.exec\(|\beval\(|new Function\(|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\()"),
    ("A04", "Insecure design", "medium", r"(?i)(TODO[^\n]{0,40}(auth|security|validate)|password\s*==\s*['\"])"),
    ("A05", "Security misconfiguration", "medium", r"(?i)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|helmet\s*\(\s*\{\s*contentSecurityPolicy\s*:\s*false)"),
    ("A06", "Vulnerable component pinned loosely", "low", r"(?im)^\s*[\w.-]+\s*(>=|\*|latest)\s*$"),
    ("A07", "Identification and authentication failure", "high", r"(?i)(jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*['\"]none|password\s*=\s*['\"][^'\"]{4,}['\"]|session\.permanent\s*=\s*True)"),
    ("A08", "Software or data integrity failure", "high", r"(?i)(pickle\.loads?\(|yaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|marshal\.loads\(|unserialize\(|<script[^>]+src=['\"]https?://(?![^'\"]*integrity))"),
    ("A09", "Security logging failure", "low", r"(?i)except\s*(Exception)?\s*:\s*\n\s*pass\b"),
    ("A10", "Server-side request forgery", "high", r"(?i)(requests\.(get|post)\(\s*(request\.|req\.|params|url_from|user)|fetch\(\s*req\.(query|body|params)|urlopen\(\s*request\.)"),
]
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java", ".html", ".txt"}


def cmd_codescan(args):
    rules = load_rules()
    out = []
    files = [p for p in walk([args.path], max_depth=10) if os.path.splitext(p)[1].lower() in CODE_EXT] if os.path.isdir(args.path) else [args.path]
    secret = next(r for r in rules["rules"] if r["id"] == SECRET_RULE)
    for p in files[:3000]:
        t = read_text(p, limit=500_000)
        if not t:
            continue
        if os.path.basename(p) not in ("requirements.txt",) and p.endswith(".txt"):
            continue
        for cid, title, sev, rx in CODE_RULES:
            if cid == "A06" and not p.endswith("requirements.txt"):
                continue
            for m in re.finditer(rx, t):
                out.append(finding(f"WT-W{cid}", f"OWASP {cid}:2021 {title}", sev, [f"{cid}:2021"], f"{p}:{line_of(t, m.start())}",
                                   m.group(0).strip()[:120], CODE_FIX[cid]))
        for m in secret["rx"].finditer(t):
            if looks_real_secret(m.group(0)):
                out.append(finding("WT-WA07s", "OWASP A07:2021 Hard-coded secret", "critical", ["A07:2021"], f"{p}:{line_of(t, m.start())}",
                                   mask(m.group(0)), "Move it to an environment variable or secret store and revoke the exposed one."))
    semgrep = tool("semgrep")
    note = "semgrep found and used too" if semgrep else "Watchtower patterns only; install semgrep for deeper analysis"
    if semgrep:
        code, so, _ = run([semgrep, "--config", "p/owasp-top-ten", "--json", "--quiet", args.path], 900)
        try:
            for r in json.loads(so).get("results", []):
                out.append(finding("WT-WSG", f"semgrep: {r.get('check_id', '').split('.')[-1]}", (r.get("extra", {}).get("severity") or "medium").lower().replace("error", "high").replace("warning", "medium").replace("info", "low"),
                                   ["OWASP"], f"{r.get('path')}:{r.get('start', {}).get('line')}", r.get("extra", {}).get("message", "")[:120],
                                   "See the semgrep rule for the fix.", source="semgrep"))
        except ValueError:
            pass
    out = sort_findings(dedupe(out))
    print(fit({"files": len(files), "engine": note, "by_severity": by_sev(out), "findings": [compact(f) for f in out][:40]}))
    ledger({"event": "codescan", "path": args.path, "findings": len(out)})
    return 0


CODE_FIX = {
    "A01": "Check the caller's identity and permission on every route; never allow every origin.",
    "A02": "Use bcrypt/argon2 for passwords, SHA-256+ for integrity, keep TLS verification on, use `secrets` for tokens.",
    "A03": "Use parameterized queries and argument lists (no shell=True); never build HTML with innerHTML from input.",
    "A04": "Finish the security TODO before shipping; compare secrets with a constant-time check.",
    "A05": "Turn debug off in anything reachable; set explicit allowed hosts and a content-security policy.",
    "A06": "Pin exact versions and audit them (`pip-audit`, `npm audit`).",
    "A07": "Verify JWT signatures with an explicit algorithm; never hard-code passwords.",
    "A08": "Don't deserialize untrusted data with pickle/yaml.load; add integrity hashes to third-party scripts.",
    "A09": "Log the exception instead of swallowing it, so failures and attacks leave a trace.",
    "A10": "Allow-list destination hosts before fetching a URL that came from a user.",
}


# ---------------------------------------------------------------- weekly threat brief
FEEDS_PATH = os.path.join(HERE, "..", "rules", "feeds.json")
WHY = [
    (r"(?i)\bmcp\b|model context protocol", "You run MCP connectors; a poisoned tool description reaches every Bot that loads it."),
    (r"(?i)\bskills?\b", "Grok Bot templates install skills; the same trick could ship inside a marketplace template."),
    (r"(?i)prompt[- ]injection|indirect injection", "Your Bots read web pages, email and X posts, which is exactly where injected instructions hide."),
    (r"(?i)npm|pypi|package|typosquat|dependency", "Your cloud computer installs packages on request; a poisoned package runs with every Bot's logins."),
    (r"(?i)exfiltrat|data leak|steal", "Shared browser sessions and files mean one compromised Bot can reach all your accounts."),
    (r"(?i)memory|persisten", "Auto Review does not check memory writes; a poisoned memory steers every future run."),
    (r"(?i)browser|extension|chrome", "Every Bot shares one browser profile and its logged-in sessions."),
    (r"(?i)cursor|grok|xai|x\.ai", "This touches the platform your Bots run on."),
]


def http_get(url, timeout=15, accept="*/*"):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": f"Watchtower/{VERSION} (+threat brief)", "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(3_000_000).decode("utf-8", errors="replace")


def strip_tags(t):
    t = re.sub(r"(?is)<(script|style).*?</\1>", " ", t or "")
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def parse_date(s):
    from email.utils import parsedate_to_datetime
    s = (s or "").strip()
    for fn in (lambda x: parsedate_to_datetime(x), lambda x: dt.datetime.fromisoformat(x.replace("Z", "+00:00"))):
        try:
            d = fn(s)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except (TypeError, ValueError, IndexError):
            continue
    return None


def parse_feed(xml_text):
    import xml.etree.ElementTree as ET
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items
    strip_ns = lambda t: t.split("}")[-1]
    for el in root.iter():
        tag = strip_ns(el.tag)
        if tag not in ("item", "entry"):
            continue
        d = {}
        for c in el:
            ct = strip_ns(c.tag)
            if ct == "title":
                d["title"] = strip_tags(c.text or "")
            elif ct == "link":
                d["link"] = c.attrib.get("href") or (c.text or "").strip() or d.get("link", "")
            elif ct in ("pubDate", "published", "updated", "date") and "date" not in d:
                d["date"] = parse_date(c.text)
            elif ct in ("description", "summary", "content", "encoded") and "summary" not in d:
                d["summary"] = strip_tags(c.text or "")[:400]
        if d.get("title"):
            items.append(d)
    return items


def version_of(name):
    if name == "watchtower":
        return VERSION
    exe = tool(name)
    if not exe:
        return None
    for args in (["--version"], ["version"]):
        code, out_s, err = run([exe] + args, 20)
        m = re.search(r"v?(\d+\.\d+(\.\d+)?)", out_s + err)
        if m:
            return m.group(1)
    return None


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def gather_brief(cfg, offline=None):
    """Collect everything the brief needs. offline: dict of url->text for tests."""
    get = (lambda u, **k: offline[u]) if offline is not None else http_get
    days = cfg.get("window_days", 7)
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    rel = re.compile(cfg["relevance"])
    sources, research = [], []
    for fd in cfg["feeds"]:
        try:
            items = parse_feed(get(fd["url"], accept="application/rss+xml, application/atom+xml, application/xml"))
            sources.append({"name": fd["name"], "url": fd["url"], "status": "ok", "items": len(items)})
        except Exception as e:  # network, parse, KeyError in offline mode
            sources.append({"name": fd["name"], "url": fd["url"], "status": f"unavailable ({type(e).__name__})", "items": 0})
            continue
        for it in items:
            if it.get("date") and it["date"] < since:
                continue
            text = f"{it['title']} {it.get('summary', '')}"
            if fd.get("all_relevant") or rel.search(text):
                why = next((w for rx, w in WHY if re.search(rx, text)), "Relevant to AI agents and the software around them.")
                research.append({"source": fd["name"], "kind": fd["kind"], "title": it["title"], "link": it.get("link", ""),
                                 "date": it["date"].date().isoformat() if it.get("date") else "", "summary": it.get("summary", "")[:280], "why": why})
    seen, dedup = set(), []
    for r in sorted(research, key=lambda x: x["date"], reverse=True):
        k = re.sub(r"\W+", "", r["title"].lower())[:60]
        if k not in seen:
            seen.add(k)
            dedup.append(r)
    research = dedup[:14]

    kev, kev_status = [], "ok"
    try:
        data = json.loads(get(cfg["kev_url"], accept="application/json"))
        watch = re.compile(cfg["kev_watch"])
        for v in data.get("vulnerabilities", []):
            added = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00")
            if added and added >= since:
                text = f"{v.get('vendorProject')} {v.get('product')}"
                kev.append({"cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"),
                            "name": v.get("vulnerabilityName"), "added": v.get("dateAdded"), "due": v.get("dueDate"),
                            "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "relevant": bool(watch.search(text)),
                            "action": (v.get("requiredAction") or "")[:200]})
        kev.sort(key=lambda x: (not x["relevant"], x["added"]), reverse=False)
    except Exception as e:
        kev_status = f"unavailable ({type(e).__name__})"
    sources.append({"name": "CISA Known Exploited Vulnerabilities", "url": cfg["kev_url"], "status": kev_status, "items": len(kev)})

    updates = []
    for r in cfg.get("releases", []):
        if "ken-aisec" in r["repo"]:
            continue
        try:
            rel_ = json.loads(get(f"https://api.github.com/repos/{r['repo']}/releases/latest", accept="application/vnd.github+json"))
            latest = (rel_.get("tag_name") or "").lstrip("v")
            have = version_of(r["installed"])
            if latest and have and vtuple(latest) > vtuple(have):
                updates.append({"name": r["name"], "have": have, "latest": latest, "url": rel_.get("html_url", "")})
        except Exception:
            continue

    pages, page_state = [], load_json(state_path("watch_pages.json"), {})
    for pg in cfg.get("watch_pages", []):
        try:
            text = strip_tags(get(pg["url"], accept="text/html"))
            m = re.search(r"(?i)last updated[^\w]{0,5}((?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}|\d{4}-\d{2}-\d{2})", text)
            stamp = m.group(1) if m else hashlib.sha256(text[:20000].encode()).hexdigest()[:16]
            prev = page_state.get(pg["url"])
            if prev and prev != stamp:
                pages.append({"name": pg["name"], "url": pg["url"], "was": prev, "now": stamp})
            page_state[pg["url"]] = stamp
        except Exception:
            continue
    save_json(state_path("watch_pages.json"), page_state)
    return {"research": research, "kev": kev, "updates": updates, "pages": pages, "sources": sources, "window_days": days}


def brief_actions(b, snap, pkg):
    acts = []
    for f in (snap or {}).get("findings", [])[:3]:
        if f["severity"] in ("critical", "high"):
            acts.append(("Your setup", f"{f['title']}: {f['fix']}"))
    for u in b["updates"]:
        acts.append(("Tooling", f"Update {u['name']} {u['have']} → {u['latest']} (`bash /workspace/watchtower/app/scripts/install.sh --scanners` or re-run setup)."))
    for k in [k for k in b["kev"] if k["relevant"]][:3]:
        acts.append(("Exploited now", f"{k['vendor']} {k['product']} ({k['cve']}): {k['action'] or 'apply the vendor fix'}"))
    for f in (pkg or {}).get("findings", [])[:3]:
        acts.append(("Packages", f"{f['title']}: {f['fix']}"))
    for pg in b["pages"]:
        acts.append(("Platform", f"Re-read “{pg['name']}”: it changed this week."))
    if not acts:
        acts.append(("Your setup", "Nothing urgent. Keep the daily watch on and re-vet any template before you add it."))
    return acts[:8]


def render_brief(b, snap, pkg, hist, tag, analyst_note=None):
    e = html.escape
    safe = lambda u: html.escape(u) if re.match(r"(?i)^https?://", u or "") else "#"
    rel_kev = [k for k in b["kev"] if k["relevant"]]
    score = (snap or {}).get("score", "–")
    grade = (snap or {}).get("grade", "")
    hot = [f for f in (snap or {}).get("findings", []) if f["severity"] in ("critical", "high")]
    pkg_f = (pkg or {}).get("findings", [])
    acts = brief_actions(b, snap, pkg)
    ok_sources = sum(1 for s in b["sources"] if s["status"] == "ok")
    summary = analyst_note or (
        f"In the last {b['window_days']} days, {len(b['research'])} research and news items touched AI agents, skills, MCP or the software "
        f"supply chain. CISA added {len(b['kev'])} vulnerabilities to its exploited-in-the-wild catalog, {len(rel_kev)} in software "
        f"software that runs on this kind of computer. Your Grok Bot posture is {score}/100{(' (' + grade + ')') if grade else ''} with "
        f"{len(hot)} critical or high finding{'s' if len(hot) != 1 else ''} open"
        f"{', and ' + str(len(pkg_f)) + ' known-vulnerable Python package' + ('s' if len(pkg_f) != 1 else '') if pkg_f else ''}. "
        f"The first recommended action below is the one to do today.")
    pill = lambda t, c: f"<span class='pill {c}'>{e(t)}</span>"
    research_html = "".join(
        f"<article class='item'><div class='meta'>{pill(r['kind'], 'k-' + re.sub(r'[^a-z]', '', r['kind']))}<span>{e(r['source'])}</span><span>{e(r['date'])}</span></div>"
        f"<h3><a href='{safe(r['link'])}' target='_blank' rel='noopener'>{e(r['title'])}</a></h3>"
        f"{('<p>' + e(r['summary']) + '</p>') if r['summary'] else ''}<p class='why'><b>Why it matters here:</b> {e(r['why'])}</p></article>"
        for r in b["research"]) or "<p class='empty'>No relevant research this week from the sources that responded.</p>"
    kev_rows = "".join(
        f"<tr class='{'rel' if k['relevant'] else ''}'><td><a href='https://nvd.nist.gov/vuln/detail/{e(k['cve'] or '')}' target='_blank' rel='noopener'>{e(k['cve'] or '')}</a></td>"
        f"<td>{e(k['vendor'] or '')} {e(k['product'] or '')}</td><td>{e(k['name'] or '')}</td><td>{e(k['added'] or '')}</td>"
        f"<td>{pill('ransomware', 'crit') if k['ransomware'] else ''}{pill('relevant', 'high') if k['relevant'] else ''}</td></tr>"
        for k in b["kev"][:25])
    posture_rows = "".join(
        f"<tr><td>{pill(f['severity'], 'crit' if f['severity'] == 'critical' else 'high')}</td><td>{e(f['title'])}</td><td><code>{e(f['where'][-70:])}</code></td><td>{e(f['fix'])}</td></tr>"
        for f in hot[:10]) or "<tr><td colspan=4 class='empty'>No critical or high findings open.</td></tr>"
    upd = "".join(f"<li><b>{e(u['name'])}</b> {e(u['have'])} → <a href='{safe(u['url'])}' target='_blank' rel='noopener'>{e(u['latest'])}</a></li>" for u in b["updates"])
    pages = "".join(f"<li><a href='{safe(p['url'])}' target='_blank' rel='noopener'>{e(p['name'])}</a> changed ({e(str(p['was']))} → {e(str(p['now']))})</li>" for p in b["pages"])
    acts_html = "".join(f"<li><span class='tag'>{e(a)}</span>{e(t)}</li>" for a, t in acts)
    src_rows = "".join(f"<tr><td>{e(s['name'])}</td><td class='{'ok' if s['status'] == 'ok' else 'bad'}'>{e(s['status'])}</td><td>{s['items']}</td></tr>" for s in b["sources"])
    pts = hist[-12:] if hist else []
    spark = ""
    if len(pts) >= 2:
        w, h = 160, 36
        step = w / (len(pts) - 1)
        poly = " ".join(f"{round(i * step, 1)},{round(h - p[1] / 100 * h, 1)}" for i, p in enumerate(pts))
        spark = f"<svg width='{w}' height='{h}' viewBox='0 0 {w} {h}' aria-label='score trend'><polyline fill='none' stroke='currentColor' stroke-width='2' points='{poly}'/></svg>"
    generated = dt.datetime.now(dt.timezone.utc).strftime("%d %b %Y %H:%M UTC")
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Watchtower Threat Brief · {e(tag)}</title><style>
:root{{--bg:#f6f7f9;--paper:#fff;--ink:#14181f;--mut:#5c6673;--line:#e2e6eb;--accent:#0f3d68;--accent2:#c8102e;--amber:#b45309;--ok:#1e7b46}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--paper:#151b23;--ink:#e6e9ee;--mut:#9aa4b2;--line:#283140;--accent:#7cb3e8;--accent2:#ff6b7d;--amber:#f0a83a;--ok:#4cc38a}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}}
.wrap{{max-width:1040px;margin:0 auto;padding:28px 20px 60px}}
.mast{{background:var(--accent);color:#fff;border-radius:14px 14px 0 0;padding:22px 28px;display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}}
@media(prefers-color-scheme:dark){{.mast{{background:#0f2a45}}}}
.mast h1{{margin:0;font-size:24px;letter-spacing:.06em;text-transform:uppercase}}.mast .sub{{opacity:.85;font-size:13px;margin-top:4px}}
.tlp{{background:#000;color:#ffc000;font:700 12px/1 ui-monospace,Menlo,monospace;padding:7px 10px;border-radius:4px;letter-spacing:.05em}}
.paper{{background:var(--paper);border:1px solid var(--line);border-top:0;border-radius:0 0 14px 14px;padding:26px 28px}}
h2{{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);margin:34px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}}
h2:first-child{{margin-top:0}}.lead{{font-size:17px;line-height:1.6;margin:0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
.kpi{{border:1px solid var(--line);border-radius:10px;padding:12px 14px}}.kpi b{{display:block;font-size:28px;line-height:1.1}}.kpi span{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
.kpi.s b{{color:var(--accent)}}.kpi.r b{{color:var(--accent2)}}.kpi svg{{color:var(--accent);margin-top:4px}}
ol.acts{{padding-left:20px;margin:0}}ol.acts li{{margin:8px 0}}.tag{{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--accent);border:1px solid var(--line);border-radius:4px;padding:1px 6px;margin-right:8px}}
.item{{border-left:3px solid var(--accent);padding:4px 0 4px 14px;margin:16px 0}}.item h3{{margin:4px 0;font-size:16px}}.item a{{color:var(--ink);text-decoration:none}}.item a:hover{{text-decoration:underline}}
.item p{{margin:4px 0;color:var(--mut)}}.item p.why{{color:var(--ink)}}.meta{{display:flex;gap:10px;align-items:center;font-size:12px;color:var(--mut)}}
.pill{{display:inline-block;font-size:11px;font-weight:600;border-radius:999px;padding:1px 8px;margin-right:4px;background:var(--line);color:var(--ink);text-transform:lowercase}}
.pill.crit{{background:var(--accent2);color:#fff}}.pill.high{{background:var(--amber);color:#fff}}
.scroll{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}}tr.rel td{{background:color-mix(in srgb,var(--amber) 10%,transparent)}}
td a{{color:var(--accent)}}code{{font:12px ui-monospace,Menlo,monospace}}.ok{{color:var(--ok)}}.bad{{color:var(--accent2)}}.empty{{color:var(--mut);font-style:italic}}
.foot{{color:var(--mut);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}}
@media print{{body{{background:#fff}}.wrap{{padding:0}}.mast{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}a{{color:inherit}}}}
</style></head><body><div class='wrap'>
<header class='mast'><div><h1>Watchtower Threat Brief</h1><div class='sub'>Week {e(tag)} · {b['window_days']}-day window · generated {e(generated)}</div></div><div class='tlp'>TLP:AMBER</div></header>
<main class='paper'>
<h2>Executive summary</h2><p class='lead'>{e(summary)}</p>
<div class='kpis'><div class='kpi s'><b>{e(str(score))}</b><span>posture score</span>{spark}</div>
<div class='kpi r'><b>{len(hot)}</b><span>critical / high open</span></div>
<div class='kpi'><b>{len(b['research'])}</b><span>relevant research</span></div>
<div class='kpi r'><b>{len(rel_kev)}</b><span>exploited, relevant</span></div>
<div class='kpi'><b>{len(pkg_f)}</b><span>vulnerable packages</span></div></div>
<h2>Recommended actions</h2><ol class='acts'>{acts_html}</ol>
<h2>Agent and AI security developments</h2>{research_html}
<h2>Exploited in the wild this week (CISA KEV)</h2>
<div class='scroll'><table><tr><th>CVE</th><th>Product</th><th>Vulnerability</th><th>Added</th><th></th></tr>{kev_rows or "<tr><td colspan=5 class='empty'>No new entries, or the catalog was unreachable (see sources).</td></tr>"}</table></div>
<h2>Your exposure</h2>
<div class='scroll'><table><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Fix</th></tr>{posture_rows}</table></div>
{('<h3>Tool updates available</h3><ul>' + upd + '</ul>') if upd else ''}
{('<h3>Platform documentation changes</h3><ul>' + pages + '</ul>') if pages else ''}
<h2>Sources and method</h2>
<div class='scroll'><table><tr><th>Source</th><th>Status</th><th>Items</th></tr>{src_rows}</table></div>
<p class='foot'>{ok_sources} of {len(b['sources'])} sources responded. Items are filtered for relevance to AI agents, skills, MCP and the software supply chain; “why it matters” is matched to how Grok Bot works, not written by a model. Posture data comes from Watchtower {e(VERSION)}'s latest audit of this computer. TLP:AMBER: share with people who help you secure this account. Unavailable sources are listed rather than filled in from old data.</p>
</main></div></body></html>"""


def cmd_brief(args):
    cfg = load_json(FEEDS_PATH, None)
    if not cfg:
        print("ERROR feeds.json missing", file=sys.stderr)
        return 2
    offline = load_json(args.offline, None) if args.offline else None
    b = gather_brief(cfg, offline)
    snap = load_json(state_path("last_findings.json"), None)
    pkg = load_json(state_path("package_vulns.json"), None)
    hist = []
    try:
        with open(state_path("score_history.csv")) as f:
            hist = [(a, int(s), int(n)) for a, s, n in (l.strip().split(",") for l in f if l.strip())]
    except (OSError, ValueError):
        pass
    note = open(args.summary).read().strip() if args.summary else None
    week = dt.date.today().isocalendar()
    tag = f"{week[0]}-W{week[1]:02d}"
    rdir = os.path.join(home(), "reports")
    os.makedirs(rdir, exist_ok=True)
    path = os.path.join(rdir, f"threat-brief-{tag}.html")
    with open(path, "w") as f:
        f.write(render_brief(b, snap, pkg, hist, tag, note))
    save_json(state_path("last_brief.json"), dict(b, tag=tag, path=path))
    ledger({"event": "brief", "week": tag, "research": len(b["research"]), "kev": len(b["kev"])})
    print(fit({"brief": path, "research": [{"title": r["title"], "source": r["source"]} for r in b["research"][:8]],
               "kev_relevant": [f"{k['cve']} {k['vendor']} {k['product']}" for k in b["kev"] if k["relevant"]][:8],
               "updates": b["updates"], "doc_changes": [p["name"] for p in b["pages"]],
               "sources_down": [s["name"] for s in b["sources"] if s["status"] != "ok"]}))
    return 0


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="wt", description="Watchtower security watch for Grok Bot")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("vet"); v.add_argument("path"); v.add_argument("--json", action="store_true"); v.add_argument("--deep", action="store_true")
    for name in ("audit", "daily", "baseline"):
        p = sub.add_parser(name)
        p.add_argument("--roots", nargs="*")
        p.add_argument("--exports")
    sub.add_parser("report")
    sub.add_parser("breakdown")
    sh = sub.add_parser("show"); sh.add_argument("rule"); sh.add_argument("--limit", type=int, default=15)
    c = sub.add_parser("canary"); c.add_argument("action", choices=["plant", "status", "remove"]); c.add_argument("--token-file")
    r = sub.add_parser("rollcall"); r.add_argument("--dir")
    pp = sub.add_parser("prepublish"); pp.add_argument("path"); pp.add_argument("--json", action="store_true")
    ic = sub.add_parser("incident"); ic.add_argument("--note")
    cs = sub.add_parser("codescan"); cs.add_argument("path")
    br = sub.add_parser("brief"); br.add_argument("--summary"); br.add_argument("--offline")
    a = ap.parse_args(argv)
    return {"vet": cmd_vet, "audit": cmd_audit, "daily": cmd_daily, "baseline": cmd_baseline, "report": cmd_report, "breakdown": cmd_breakdown, "show": cmd_show,
            "canary": cmd_canary, "rollcall": cmd_rollcall, "prepublish": cmd_prepublish, "incident": cmd_incident,
            "codescan": cmd_codescan, "brief": cmd_brief}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
