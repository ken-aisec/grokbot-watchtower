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

VERSION = "0.1.4"
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
                              r"ollama\.com/install|sdk\.cloud\.google\.com|awscli\.amazonaws\.com)")
PLACEHOLDER = re.compile(r"(?i)(example|sample|placeholder|your[_-]?|dummy|fake|test|xxxx|0000|1234|abcd|\.\.\.|<|>|\*{3})")


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


def attack_reference(text, rules):
    """A file that lists several injection patterns is documentation or a detector, not an attack."""
    rx = next(r["rx"] for r in rules["rules"] if r["id"] == "WT-T001")
    return len(rx.findall(text)) >= 3 or bool(re.search(r"(?i)(prompt[- ]injection|injection)\s+(patterns?|examples?|signatures?|detection)", text))


def scan_text(text, where, rules, kind="skill"):
    """Apply text rules plus document-level logic. kind: skill|reference|template|routine|description."""
    out = []
    guarded = set(rules.get("guarded_rules", []))
    is_ref = attack_reference(text, rules)
    if is_ref:
        out.append(finding("WT-T001r", "Describes injection patterns (reference or detector)", "info", ["AST05"], where,
                           "pattern list", "No action. Listed so you know this file contains attack examples."))
    for rule in rules["rules"]:
        if is_ref and rule["id"] in ("WT-T001", "WT-T008", "WT-T007"):
            continue
        if kind == "vendor" and rule["severity"] != "critical" and rule["id"] != "WT-T002":
            continue
        for m in rule["rx"].finditer(text):
            if rule["id"] in guarded and in_warning(text, m, rules):
                continue
            if rule["id"] == SECRET_RULE and not looks_real_secret(m.group(0)):
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
    fs = sort_findings(scan_text(text, name, rules, kind="template"))
    s, g = score(fs)
    urls = sorted(set(re.findall(r"https?://[^\s)\"'>]+", text)))
    result = {"tool": "watchtower", "version": VERSION, "target": name, "verdict": verdict(fs),
              "risk_score": 100 - s, "posture_score": s, "grade": g, "autonomy": autonomy(text, rules),
              "external_urls": urls[:25], "findings": fs,
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


def collect_inventory(roots):
    inv = {"skills": [], "plugin_files": [], "mcp_configs": []}
    for p in walk(roots):
        fn = os.path.basename(p)
        if fn == "SKILL.md":
            inv["skills"].append(p)
        elif "mcp" in fn.lower() and fn.endswith(".json"):
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
    for p in walk(roots, max_depth=6):
        if p in known or os.path.basename(p) in SESSION_FILES:
            continue
        if os.path.splitext(p)[1].lower() not in TEXT_EXT:
            continue
        t = read_text(p, limit=300_000)
        if not t:
            continue
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

    # 6. optional external scanners
    if not quick:
        fs += external_scanners(inv["skills"], roots, notes)

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


def external_scanners(skills, roots, notes):
    out = []
    if shutil.which("skillspector"):
        for s in skills[:40]:
            d = os.path.dirname(s)
            tmp = state_path("skillspector.json")
            code, _, err = run(["skillspector", "scan", d, "--no-llm", "--format", "json", "--output", tmp], 180)
            data = load_json(tmp, None) or {}
            issues = data.get("issues", []) if isinstance(data, dict) else []
            risk = find_key(data.get("risk_assessment", {}), ("risk_score", "score", "overall_score")) if isinstance(data, dict) else None
            sevs = [str(i.get("severity", "")).lower() for i in issues if isinstance(i, dict)]
            worst = next((x for x in ("critical", "high") if x in sevs), None)
            if worst or (isinstance(risk, (int, float)) and risk >= 50):
                sev = worst or ("critical" if risk >= 75 else "high")
                first = next((i for i in issues if isinstance(i, dict)), {})
                out.append(finding("WT-X001", f"SkillSpector: {len(issues)} issue(s)", sev, ["AST01", "AST08"], d,
                                   f"risk={risk}; {first.get('title') or first.get('rule_id') or ''}"[:140],
                                   "Open the SkillSpector report for the exact patterns.", source="skillspector"))
    else:
        notes.append("SkillSpector not installed: skill scan used Watchtower rules only.")
    if shutil.which("gitleaks"):
        tmp = state_path("gitleaks.json")
        for r in roots:
            r = os.path.expanduser(r)
            if os.path.isdir(r):
                run(["gitleaks", "detect", "--source", r, "--no-git", "--redact", "--report-format", "json", "--report-path", tmp, "--exit-code", "0"], 300)
                per_file = {}
                for leak in load_json(tmp, []) or []:
                    per_file.setdefault(leak.get("File"), []).append(leak)
                for fpath, leaks in per_file.items():
                    kinds = sorted({l.get("RuleID", "secret") for l in leaks})
                    out.append(finding("WT-S002", "gitleaks: secrets in file", "critical" if len(leaks) else "high", ["ASI03", "LLM02"],
                                       f"{fpath}:{leaks[0].get('StartLine')}", f"{len(leaks)} hit(s): {', '.join(kinds)[:100]}",
                                       "Check whether these are live credentials. Revoke live ones, then delete or scrub the file.", source="gitleaks"))
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    if shutil.which("pip-audit"):
        code, out_s, _ = run(["pip-audit", "-f", "json"], 300)
        data = None
        try:
            data = json.loads(out_s) if out_s.strip() else None
        except ValueError:
            pass
        deps = data.get("dependencies", []) if isinstance(data, dict) else (data or [])
        for d in deps:
            for v in d.get("vulns", []):
                out.append(finding("WT-D001", f"Vulnerable package {d.get('name')} {d.get('version')}", "high", ["ASI04", "AST02"],
                                   "pip", v.get("id", ""), f"Upgrade to {', '.join(v.get('fix_versions', [])) or 'a fixed version'}.", source="pip-audit"))
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
<p class='mut' style='margin-top:20px'>Watchtower {VERSION}. Scanners can be bypassed; this is evidence, not proof.</p></body></html>"""


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="wt", description="Watchtower security watch for Grok Bot")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("vet"); v.add_argument("path"); v.add_argument("--json", action="store_true")
    for name in ("audit", "daily", "baseline"):
        p = sub.add_parser(name)
        p.add_argument("--roots", nargs="*")
        p.add_argument("--exports")
    sub.add_parser("report")
    sub.add_parser("breakdown")
    sh = sub.add_parser("show"); sh.add_argument("rule"); sh.add_argument("--limit", type=int, default=15)
    a = ap.parse_args(argv)
    return {"vet": cmd_vet, "audit": cmd_audit, "daily": cmd_daily, "baseline": cmd_baseline, "report": cmd_report, "breakdown": cmd_breakdown, "show": cmd_show}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
