"""The Code Flaw Hunter — one instance per language.

Python is analysed with the real AST, which is why those rules can tell
`eval(literal)` from `eval(user_input)`. JavaScript, TypeScript and Go are
matched with anchored patterns, which is weaker and is reported as weaker.

Honest scope: this is a focused rule set for the flaw classes that actually
turn into incidents — injection, unsafe deserialisation, command execution,
disabled TLS verification, weak crypto and debug left on. It is not a
replacement for Semgrep's thousands of rules. Where `semgrep` is on PATH we
defer to it; this exists so the product works with nothing installed.
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from app.scanners.base import RawFinding, ScanContext

log = logging.getLogger(__name__)

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "vendors", "third_party", "thirdparty",
    "dist", "build", "target", ".venv", "venv", "__pycache__", ".next", ".nuxt",
    "site-packages", ".tox", "migrations", "bower_components", "jquery-ui",
}

# Vendored front-end libraries are somebody else's code shipped verbatim. Flagging
# innerHTML inside materialize.js tells the owner nothing they can act on, and it
# buries the findings in their own code. Dependency advisories already cover the
# library itself, which is the correct place to report it.
VENDOR_DIR_HINTS = ("/static/js/", "/static/vendor/", "/assets/js/vendor/",
                    "/public/js/lib/", "/js/lib/", "/libs/", "/lib/vendor/")
VENDOR_FILE_HINTS = (
    "jquery", "bootstrap", "materialize", "lodash", "underscore", "angular",
    "backbone", "ember", "moment", "d3.", "chart.", "popper", "modernizr",
    "prototype.js", "mootools", "swiper", "slick", "select2", "datatables",
    "tinymce", "ckeditor", "highlight.", "prism.", "three.", "pdf.",
)


def is_vendored(rel: str) -> bool:
    low = "/" + rel.lower()
    if any(h in low for h in VENDOR_DIR_HINTS):
        return True
    name = low.rsplit("/", 1)[-1]
    return any(h in name for h in VENDOR_FILE_HINTS)


MAX_FILE_BYTES = 1_500_000

LANG_EXT = {
    ".py": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go",
}
SLUG = {"Python": "flaw_py", "JavaScript": "flaw_js", "TypeScript": "flaw_ts", "Go": "flaw_go"}


def _finding(rule: str, title: str, sev: str, cwe: str, rel: str, line: int,
             lang: str, why: str, fix: list[str], conf: float) -> RawFinding:
    return RawFinding(
        scanner="semgrep", agent_slug=SLUG.get(lang, "flaw_py"),
        title=title, file=rel, line=line, rule_id=rule, cwe=cwe,
        severity_label=sev, summary=why, remediation=fix,
        extra={"language": lang, "confidence": conf, "engine": "builtin"},
    )


# ===========================================================================
# Python — real AST, so these rules know what is actually being passed.
# ===========================================================================
class TaintCollector(ast.NodeVisitor):
    """Names assigned an interpolated string inside one function body.

    Real code almost never interpolates at the call site. It builds the string
    on one line and executes it on another:

        q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {"name": name})
        await cur.execute(q)

    Without this pass the second line looks like a parameterised query and the
    injection is missed entirely.
    """

    def __init__(self) -> None:
        self.tainted: dict[str, int] = {}      # name -> line where it was built

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if PyVisitor._is_dynamic_string(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted[t.id] = node.lineno
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None and PyVisitor._is_dynamic_string(node.value):
            if isinstance(node.target, ast.Name):
                self.tainted[node.target.id] = node.lineno
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        # q += f"AND name = {x}"  -- concatenation onto an existing query
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            if PyVisitor._is_dynamic_string(node.value) or isinstance(node.value, ast.JoinedStr):
                self.tainted[node.target.id] = node.lineno
        self.generic_visit(node)

    # Do not descend into nested functions; each gets its own scope.
    def visit_FunctionDef(self, node): pass        # noqa: N802, D102
    def visit_AsyncFunctionDef(self, node): pass   # noqa: N802, D102


class PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.out: list[RawFinding] = []
        self.tainted: dict[str, int] = {}

    # -- helpers
    @staticmethod
    def _name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{PyVisitor._name(node.value)}.{node.attr}"
        return ""

    @staticmethod
    def _is_literal(node: ast.AST) -> bool:
        try:
            ast.literal_eval(node)
            return True
        except (ValueError, TypeError, SyntaxError, MemoryError):
            return False

    @staticmethod
    def _is_dynamic_string(node: ast.AST) -> bool:
        """f-string, % format, .format() or + concatenation — i.e. interpolation."""
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return node.func.attr == "format"
        return False

    def _enter_scope(self, node) -> dict[str, int]:
        collector = TaintCollector()
        for child in node.body:
            collector.visit(child)
        previous, self.tainted = self.tainted, collector.tainted
        return previous

    def visit_FunctionDef(self, node) -> None:  # noqa: N802
        previous = self._enter_scope(node)
        self.generic_visit(node)
        self.tainted = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def add(self, rule, title, sev, cwe, node, why, fix, conf=0.85):
        self.out.append(_finding(rule, title, sev, cwe, self.rel,
                                 getattr(node, "lineno", 0), "Python", why, fix, conf))

    # -- rules
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = self._name(node.func)
        args = node.args

        if fn in ("eval", "exec") and args and not self._is_literal(args[0]):
            self.add("py.dynamic-exec", f"{fn}() called on a non-literal expression",
                     "CRITICAL", "CWE-95", node,
                     f"{fn}() receives a value the analyser cannot prove is constant. If any part "
                     f"of it reaches user input this is remote code execution.",
                     ["Replace with an explicit dispatch table or ast.literal_eval().",
                      "If dynamic execution is genuinely required, allow-list the permitted inputs."])

        if fn in ("pickle.loads", "pickle.load", "cPickle.loads", "dill.loads",
                  "shelve.open", "joblib.load"):
            self.add("py.unsafe-deserialize", "Unsafe deserialisation of untrusted data",
                     "CRITICAL", "CWE-502", node,
                     "Loading a pickle executes whatever the pickle says to execute. Anyone who "
                     "can write to the source of this data has code execution.",
                     ["Use a data-only format: JSON, or safetensors for model artefacts.",
                      "If the format cannot change, sign the artefact and verify before loading."])

        if fn in ("yaml.load",) and not any(
            k.arg == "Loader" and "Safe" in self._name(k.value) for k in node.keywords
        ):
            self.add("py.yaml-unsafe-load", "yaml.load() without SafeLoader",
                     "HIGH", "CWE-502", node,
                     "The default YAML loader can construct arbitrary Python objects.",
                     ["Use yaml.safe_load(), or pass Loader=yaml.SafeLoader."])

        if fn.endswith(("subprocess.run", "subprocess.call", "subprocess.Popen",
                        "subprocess.check_output", "os.system", "os.popen")):
            shell_true = any(k.arg == "shell" and getattr(k.value, "value", False) is True
                             for k in node.keywords)
            if shell_true or fn in ("os.system", "os.popen"):
                dynamic = bool(args) and not self._is_literal(args[0])
                self.add("py.shell-injection",
                         "Shell command built at runtime",
                         "CRITICAL" if dynamic else "MODERATE", "CWE-78", node,
                         "A shell is being invoked. With an interpolated argument this is command "
                         "injection; even with a constant it is an unnecessary shell.",
                         ["Pass a list of arguments and leave shell=False.",
                          "Never interpolate user input into a command string."],
                         conf=0.9 if dynamic else 0.5)

        if fn in ("hashlib.md5", "hashlib.sha1"):
            self.add("py.weak-hash", f"{fn.split('.')[-1]} used for hashing",
                     "MODERATE", "CWE-327", node,
                     "MD5 and SHA-1 are broken for any security purpose. They remain acceptable "
                     "only for non-security checksums.",
                     ["Use hashlib.sha256 for integrity.",
                      "Use bcrypt, scrypt or argon2 for passwords — never a bare hash."],
                     conf=0.6)

        # requests(..., verify=False)
        if fn.startswith(("requests.", "httpx.")) or fn in ("request", "get", "post"):
            for k in node.keywords:
                if k.arg == "verify" and getattr(k.value, "value", None) is False:
                    self.add("py.tls-verify-disabled", "TLS certificate verification disabled",
                             "HIGH", "CWE-295", node,
                             "verify=False accepts any certificate, which removes the protection "
                             "TLS exists to provide and makes interception trivial.",
                             ["Remove verify=False.",
                              "For an internal CA, pass verify='/path/to/ca-bundle.pem'."])

        # SQL built by interpolation then executed - inline, or via a local
        if fn.endswith(("execute", "executemany", "raw", "execute_sql", "executescript")) and args:
            built_at = None
            if self._is_dynamic_string(args[0]):
                built_at = getattr(args[0], "lineno", node.lineno)
            elif isinstance(args[0], ast.Name) and args[0].id in self.tainted:
                built_at = self.tainted[args[0].id]

            if built_at is not None:
                same_line = built_at == node.lineno
                where = ("in the call itself" if same_line
                         else f"on line {built_at}, then executed here")
                self.add("py.sql-injection", "SQL statement assembled by string interpolation",
                         "CRITICAL", "CWE-89", node,
                         f"The query text is built by interpolation {where}, rather than passed "
                         f"as parameters, so any value reaching it can change the statement.",
                         ["Use parameter binding: cursor.execute(sql, (a, b)).",
                          "Never format user input into SQL, even after escaping."],
                         conf=0.9 if same_line else 0.8)

        if fn in ("tempfile.mktemp",):
            self.add("py.insecure-temp", "tempfile.mktemp() is race-prone",
                     "MODERATE", "CWE-377", node,
                     "mktemp() returns a name, not a file, so another process can win the race.",
                     ["Use tempfile.NamedTemporaryFile or mkstemp()."], conf=0.7)

        if fn.startswith("random.") and fn.split(".")[-1] in ("random", "randint", "choice", "randrange"):
            self.out.append(_finding(
                "py.weak-random", "Non-cryptographic randomness", "LOW", "CWE-338",
                self.rel, node.lineno, "Python",
                "random is a Mersenne Twister and is predictable from past output. It is fine for "
                "simulation and wrong for anything a user should not be able to guess.",
                ["Use the secrets module for tokens, passwords and identifiers."], 0.35))

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802
        src = ast.dump(node.test)
        if any(w in src.lower() for w in ("auth", "permission", "is_admin", "role", "token")):
            self.add("py.assert-auth", "Authorisation enforced with assert",
                     "HIGH", "CWE-617", node,
                     "assert statements are removed when Python runs with -O, so this check "
                     "can silently disappear in production.",
                     ["Raise an explicit exception instead of asserting."], conf=0.6)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> None:  # noqa: N802
        if node.arg == "debug" and getattr(node.value, "value", None) is True:
            self.add("py.debug-enabled", "Debug mode enabled", "HIGH", "CWE-489", node,
                     "Debug mode exposes stack traces, configuration and in some frameworks an "
                     "interactive console to anyone who triggers an error.",
                     ["Drive it from an environment variable and default it to off."], conf=0.75)
        self.generic_visit(node)


def scan_python(path: Path, rel: str) -> list[RawFinding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=rel)
    except (SyntaxError, ValueError, OSError):
        return []
    v = PyVisitor(rel)
    v.visit(tree)
    return v.out


# ===========================================================================
# JavaScript / TypeScript / Go — anchored patterns, lower confidence, and the
# findings say so.
# ===========================================================================
# (rule, title, severity, cwe, regex, why, fixes, confidence)
JS_RULES = [
    ("js.eval", "eval() on a runtime value", "CRITICAL", "CWE-95",
     re.compile(r"\beval\s*\(\s*(?!['\"`][^'\"`]*['\"`]\s*\))"),
     "eval() executes whatever string it is given.",
     ["Replace with JSON.parse for data, or an explicit dispatch object."], 0.7),
    ("js.new-function", "new Function() built at runtime", "HIGH", "CWE-95",
     re.compile(r"\bnew\s+Function\s*\("),
     "new Function() compiles a string into code, with the same risk as eval.",
     ["Use a lookup table of real functions."], 0.7),
    ("js.child-process-interpolated", "Shell command with an interpolated value", "CRITICAL", "CWE-78",
     re.compile(r"\b(?:exec|execSync)\s*\(\s*[`'\"][^`'\"]*\$\{"),
     "A template literal is being interpolated into a shell command.",
     ["Use execFile or spawn with an argument array."], 0.8),
    ("js.innerhtml", "innerHTML assigned a non-literal", "HIGH", "CWE-79",
     re.compile(r"\.innerHTML\s*=\s*(?!['\"`][^'\"`]*['\"`]\s*[;\n])"),
     "Assigning to innerHTML parses the value as HTML, so any script in it runs.",
     ["Use textContent, or sanitise with DOMPurify before assigning."], 0.6),
    ("js.dangerously-set-html", "dangerouslySetInnerHTML", "HIGH", "CWE-79",
     re.compile(r"dangerouslySetInnerHTML"),
     "React escapes by default; this opts out of that protection.",
     ["Sanitise the HTML before it reaches this prop."], 0.5),
    ("js.jwt-none", "JWT verification accepting the none algorithm", "CRITICAL", "CWE-327",
     re.compile(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]"),
     "The none algorithm means an unsigned token is accepted as valid.",
     ["Pin algorithms to the one you actually issue, e.g. ['RS256']."], 0.9),
    ("js.sql-template", "SQL built with a template literal", "CRITICAL", "CWE-89",
     re.compile(r"\.(?:query|execute|raw)\s*\(\s*`[^`]*\$\{"),
     "Interpolating into SQL lets a value change the statement.",
     ["Use parameterised queries with placeholders."], 0.8),
    ("js.tls-disabled", "TLS verification disabled", "HIGH", "CWE-295",
     re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
     "Certificate checking is switched off, so interception is undetectable.",
     ["Remove the override and trust a proper CA bundle."], 0.9),
    ("js.math-random-token", "Math.random() used for a token", "MODERATE", "CWE-338",
     re.compile(r"(?i)(?:token|secret|key|nonce|otp|session)\s*[:=][^;\n]*Math\.random\s*\("),
     "Math.random is predictable and must not generate anything secret.",
     ["Use crypto.randomUUID() or crypto.randomBytes()."], 0.75),
]

GO_RULES = [
    ("go.sql-sprintf", "SQL assembled with Sprintf", "CRITICAL", "CWE-89",
     re.compile(r"(?:Query|Exec|QueryRow)(?:Context)?\s*\(\s*(?:[a-zA-Z_]\w*\s*,\s*)?fmt\.Sprintf"),
     "fmt.Sprintf into a query means the value can change the statement.",
     ["Use placeholders and pass arguments: db.Query(\"... WHERE id = $1\", id)."], 0.85),
    ("go.command-injection", "Command built from a variable", "HIGH", "CWE-78",
     re.compile(r"exec\.Command\s*\(\s*(?:\"(?:sh|bash|cmd|powershell)\"|[a-zA-Z_]\w*\s*[,)])"),
     "Invoking a shell, or a command name held in a variable, allows injection.",
     ["Call the binary directly with a fixed name and an argument slice."], 0.6),
    ("go.tls-skip-verify", "InsecureSkipVerify enabled", "HIGH", "CWE-295",
     re.compile(r"InsecureSkipVerify\s*:\s*true"),
     "The TLS certificate is not checked, so the connection can be intercepted.",
     ["Remove it, or pin a RootCAs pool for an internal CA."], 0.95),
    ("go.weak-hash", "MD5 or SHA-1 in use", "MODERATE", "CWE-327",
     re.compile(r"\b(?:md5|sha1)\.(?:New|Sum)\b"),
     "Both are broken for security use.",
     ["Use sha256, or a password KDF for credentials."], 0.6),
]

COMMENT = re.compile(r"^\s*(?://|#|\*|/\*)")


def scan_patterns(path: Path, rel: str, lang: str) -> list[RawFinding]:
    rules = GO_RULES if lang == "Go" else JS_RULES
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out: list[RawFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000 or COMMENT.match(line):
            continue
        for rule, title, sev, cwe, rx, why, fix, conf in rules:
            if rx.search(line):
                out.append(_finding(rule, title, sev, cwe, rel, lineno, lang,
                                    why + " Detected by pattern match, so confirm before acting.",
                                    fix, conf))
    return out


# ===========================================================================
def detect_languages(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in root.rglob("*"):
        if p.suffix.lower() in LANG_EXT and not any(d in p.parts for d in SKIP_DIRS):
            counts[LANG_EXT[p.suffix.lower()]] = counts.get(LANG_EXT[p.suffix.lower()], 0) + 1
    return counts


def scan(ctx: ScanContext, languages: set[str] | None = None) -> list[RawFinding]:
    out: list[RawFinding] = []
    for path in ctx.root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        lang = LANG_EXT.get(path.suffix.lower())
        if not lang or (languages and lang not in languages):
            continue
        if any(d in path.parts for d in SKIP_DIRS):
            continue
        if path.name.endswith((".min.js", ".bundle.js", ".test.js", "_test.go", ".spec.ts")):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = path.relative_to(ctx.root).as_posix()
        if not ctx.touched(rel) or is_vendored(rel):
            continue
        out.extend(scan_python(path, rel) if lang == "Python" else scan_patterns(path, rel, lang))

    log.info("code: %d findings", len(out))
    return out
