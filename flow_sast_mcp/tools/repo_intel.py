"""
tools/repo_intel.py
────────────────────
PRE-PHASE tool: Codebase Intelligence

Extract from real file structure (no predefined patterns):
  - framework & tech stack
  - authentication / authorization mechanism
  - key architectural notes (security-relevant)

Output: catalog/repo_intel.json
        catalog/repo_intel.md   ← human-readable summary

Strategy:
  1. Scan manifest files (package.json, composer.json, requirements.txt, ...)
     to determine language, framework, dependencies
  2. Scan config files (.env.example, config/*.php, application.yml, ...)
     to identify auth methods (JWT, session, OAuth2, API key, etc.)
  3. Use gitnexus Cypher queries (if available) to find auth middleware,
     guards, authentication classes in the actual call graph
  4. Scan README / docs for system overview
  5. Heuristic scan of top-level file tree structure to infer architecture
  6. Save structured output + Claude-readable markdown summary
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

GITNEXUS_TIMEOUT = int(os.environ.get("GITNEXUS_TIMEOUT", "120"))


def _resolve_gitnexus_binary() -> str:
    """Resolve gitnexus binary, falling back to shutil.which for MCP subprocess PATH gaps."""
    import shutil
    explicit = os.environ.get("GITNEXUS_BINARY", "")
    if explicit:
        return explicit
    found = shutil.which("gitnexus")
    return found if found else "gitnexus"


GITNEXUS_BINARY = _resolve_gitnexus_binary()


# ── Manifest files → framework/language detection ─────────────────────────────

MANIFEST_FILES = [
    # Node / JS / TS
    "package.json",
    # PHP
    "composer.json",
    # Python
    "requirements.txt", "requirements/*.txt", "pyproject.toml", "setup.py", "Pipfile",
    # Java / Kotlin
    "pom.xml", "build.gradle", "build.gradle.kts",
    # Go
    "go.mod",
    # Ruby
    "Gemfile",
    # Rust
    "Cargo.toml",
    # .NET / C#
    "**/*.csproj", "**/*.sln",
    # Generic
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
]

# Patterns to detect framework from manifest content
FRAMEWORK_SIGNATURES: list[tuple[str, str, str]] = [
    # (pattern_in_content, framework_name, language)
    (r'"laravel/framework"',        "Laravel",       "PHP"),
    (r'"symfony/symfony"',          "Symfony",       "PHP"),
    (r'"slim/slim"',                "Slim",          "PHP"),
    (r'"codeigniter4/framework"',   "CodeIgniter 4", "PHP"),
    (r'"yiisoft/yii2"',             "Yii2",          "PHP"),
    (r'"cakephp/cakephp"',          "CakePHP",       "PHP"),
    (r'"express"',                  "Express.js",    "Node.js"),
    (r'"fastify"',                  "Fastify",       "Node.js"),
    (r'"nestjs/core"',              "NestJS",        "Node.js/TS"),
    (r'"koa"',                      "Koa.js",        "Node.js"),
    (r'"hapi/hapi"',                "Hapi.js",       "Node.js"),
    (r'"next"',                     "Next.js",       "Node.js/React"),
    (r'\bDjango\b|\bdjango\b',      "Django",        "Python"),
    (r'\bFlask\b|\bflask\b',        "Flask",         "Python"),
    (r'\bFastAPI\b|\bfastapi\b',    "FastAPI",       "Python"),
    (r'\bTornado\b|\btornado\b',    "Tornado",       "Python"),
    (r'org\.springframework',       "Spring Boot",   "Java"),
    (r'"io\.quarkus"',              "Quarkus",       "Java"),
    (r'"io\.micronaut"',            "Micronaut",     "Java"),
    (r'\bgin-gonic/gin\b',          "Gin",           "Go"),
    (r'\becho\b.*labstack',         "Echo",          "Go"),
    (r'\bfiber\b.*gofiber',         "Fiber",         "Go"),
    (r'\bruby on rails\b|\brails\b',"Ruby on Rails", "Ruby"),
    (r'\bsinatra\b',                "Sinatra",       "Ruby"),
    (r'Microsoft\.AspNetCore',      "ASP.NET Core",  ".NET/C#"),
    (r'Microsoft\.NET\.Sdk\.Web',   "ASP.NET Core",  ".NET/C#"),
]

# Auth mechanism signatures — found in config/env/doc files
AUTH_SIGNATURES: list[tuple[str, str]] = [
    # (pattern, mechanism)
    (r'\bjwt\b|\bJSON Web Token\b',    "JWT"),
    (r'\boauth2?\b|\bopenid\b',         "OAuth2/OIDC"),
    (r'\bpassport\b',                   "Passport.js"),
    (r'\bsanctum\b',                    "Laravel Sanctum"),
    (r'\bfortify\b',                    "Laravel Fortify"),
    (r'\btymon.*jwt\b',                 "tymondesigns/jwt-auth (Laravel)"),
    (r'\bjwt-auth\b',                   "JWT Auth"),
    (r'\bsession\b',                    "Session-based"),
    (r'\bapi.?key\b',                   "API Key"),
    (r'\bbasic.?auth\b',                "Basic Auth"),
    (r'\bbearer\b',                     "Bearer Token"),
    (r'\bcasbin\b',                     "Casbin (RBAC/ABAC)"),
    (r'\bspring.?security\b',           "Spring Security"),
    (r'\bkeycloak\b',                   "Keycloak"),
    (r'\bauth0\b',                      "Auth0"),
    (r'\bbouncer\b',                    "Bouncer (Laravel RBAC)"),
    (r'\bspatie.*permission\b',         "Spatie Laravel-Permission"),
    (r'\bguard\b.*auth',                "Guard-based auth"),
    (r'\bmiddleware.*auth\b',           "Auth Middleware"),
    (r'\bFirebase.*auth\b',             "Firebase Auth"),
    (r'\bcognito\b',                    "AWS Cognito"),
]


# ── Annotation / decorator signatures (scan source code files) ─────────────────
# Grouped by language/framework for clarity.
# Each entry: (regex, annotation_name, language, security_implication)

ANNOTATION_SIGNATURES: list[tuple[str, str, str, str]] = [
    # ── Java / Spring ────────────────────────────────────────────────────────
    (r'@PreAuthorize\s*\(',              "@PreAuthorize",           "Java/Spring",  "method-level RBAC — check SpEL expression"),
    (r'@PostAuthorize\s*\(',             "@PostAuthorize",          "Java/Spring",  "post-auth on return value — check expression"),
    (r'@Secured\s*\(',                   "@Secured",                "Java/Spring",  "role check — check role list is complete"),
    (r'@RolesAllowed\s*\(',              "@RolesAllowed",           "Java/JSR-250", "JSR-250 role check"),
    (r'@PermitAll\b',                    "@PermitAll",              "Java/JSR-250", "⚠️ public endpoint — no auth required"),
    (r'@DenyAll\b',                      "@DenyAll",                "Java/JSR-250", "always denied"),
    (r'@Authenticate\b',                 "@Authenticate",          "Java",         "custom auth annotation"),
    (r'@WithMockUser\b',                 "@WithMockUser",           "Java/Test",    "test-only: ensure not in production paths"),
    (r'@EnableWebSecurity\b',            "@EnableWebSecurity",     "Java/Spring",  "Spring Security config class"),
    (r'@EnableGlobalMethodSecurity\b',   "@EnableGlobalMethodSecurity", "Java/Spring", "enables method-level security"),
    (r'@EnableMethodSecurity\b',         "@EnableMethodSecurity",  "Java/Spring",  "Spring 6 method security"),

    # ── .NET / C# ─────────────────────────────────────────────────────────────
    (r'\[Authorize\b',                   "[Authorize]",            ".NET/C#",     "requires authentication"),
    (r'\[AllowAnonymous\]',              "[AllowAnonymous]",       ".NET/C#",     "⚠️ public endpoint — bypasses auth"),
    (r'\[Authorize\s*\(Roles\s*=',       "[Authorize(Roles=...)]", ".NET/C#",     "role-based auth — check roles list"),
    (r'\[Authorize\s*\(Policy\s*=',      "[Authorize(Policy=...)]",".NET/C#",     "policy-based auth — check policy definition"),
    (r'\[RequireHttps\]',                "[RequireHttps]",         ".NET/C#",     "HTTPS enforcement"),
    (r'\[ValidateAntiForgeryToken\]',    "[ValidateAntiForgeryToken]",".NET/C#", "CSRF protection"),
    (r'\[IgnoreAntiforgeryToken\]',      "[IgnoreAntiforgeryToken]",".NET/C#",  "⚠️ CSRF protection disabled"),
    (r'\[Authorize\s*\(AuthenticationSchemes\s*=', "[Authorize(AuthenticationSchemes=...)]", ".NET/C#", "multi-scheme auth"),
    (r'\[ClaimsPrincipalPermission\b',   "[ClaimsPrincipalPermission]",".NET/C#","claims-based access"),
    (r'\[Authorize\s*\(Roles\s*=\s*".*Admin', "[Authorize(Roles=Admin)]",".NET/C#", "admin-role protected endpoint"),

    # ── Python ────────────────────────────────────────────────────────────────
    (r'@login_required\b',               "@login_required",        "Python/Django","requires login"),
    (r'@permission_required\s*\(',        "@permission_required",   "Python/Django","specific permission check"),
    (r'@staff_member_required\b',        "@staff_member_required", "Python/Django","staff only"),
    (r'@superuser_required\b',           "@superuser_required",    "Python/Django","superuser only"),
    (r'@user_passes_test\s*\(',          "@user_passes_test",      "Python/Django","custom predicate check"),
    (r'@jwt_required\b',                 "@jwt_required",          "Python/Flask-JWT","JWT required"),
    (r'@jwt_optional\b',                 "@jwt_optional",          "Python/Flask-JWT","⚠️ JWT optional — auth not enforced"),
    (r'@fresh_jwt_required\b',           "@fresh_jwt_required",    "Python/Flask-JWT","fresh JWT required"),
    (r'@token_required\b',               "@token_required",        "Python/Flask",  "custom token check"),
    (r'@require_http_methods\s*\(',       "@require_http_methods",  "Python/Django","HTTP method restriction"),
    (r'@Depends\s*\(',                   "@Depends",               "Python/FastAPI", "dependency injection — check if security dep"),
    (r'Security\s*\(\s*oauth2_scheme',   "Security(oauth2_scheme)","Python/FastAPI", "OAuth2 scope enforcement"),
    (r'HTTPBearer\s*\(\)',               "HTTPBearer",             "Python/FastAPI", "Bearer token auth"),
    (r'HTTPBasic\s*\(\)',                "HTTPBasic",              "Python/FastAPI", "Basic auth"),

    # ── PHP / Laravel / Symfony ───────────────────────────────────────────────
    (r'\*\s*@Security\s*\(',             "@Security (annotation)", "PHP/Symfony",  "Symfony security annotation"),
    (r'\*\s*@IsGranted\s*\(',            "@IsGranted",             "PHP/Symfony",  "Symfony attribute auth"),
    (r'#\[Route.*\bname\b.*\]',          "#[Route]",               "PHP/Symfony",  "Symfony route (check security)"),
    (r'#\[IsGranted\s*\(',               "#[IsGranted]",           "PHP/Symfony",  "Symfony 6 attribute auth"),
    (r'->middleware\s*\(',               "->middleware()",         "PHP/Laravel",  "Laravel route middleware — check auth guards"),
    (r'->withoutMiddleware\s*\(',        "->withoutMiddleware()",  "PHP/Laravel",  "⚠️ middleware bypassed explicitly"),
    (r'auth\s*\(\s*\)',                  "auth() helper",          "PHP/Laravel",  "auth() call — check gate/policy"),
    (r'Gate::\s*(allows|denies|check|authorize)\s*\(', "Gate::",  "PHP/Laravel",  "Gate authorization check"),
    (r'\$this->authorize\s*\(',          "$this->authorize()",     "PHP/Laravel",  "Controller authorize call"),
    (r'Policy\b.*\bauthorize\b',         "Policy authorize",       "PHP/Laravel",  "policy-based authorization"),

    # ── Node.js / NestJS / Express ────────────────────────────────────────────
    (r'@UseGuards\s*\(',                 "@UseGuards",             "NestJS",       "guard applied — check guard implementation"),
    (r'@Roles\s*\(',                     "@Roles",                 "NestJS",       "role decorator — check RolesGuard impl"),
    (r'@Public\s*\(\)',                  "@Public()",              "NestJS",       "⚠️ public endpoint — no auth required"),
    (r'@Auth\s*\(',                      "@Auth",                  "NestJS",       "custom auth decorator"),
    (r'@Permissions\s*\(',               "@Permissions",           "NestJS",       "permission decorator"),
    (r'passport\.authenticate\s*\(',     "passport.authenticate()","Node.js",      "Passport.js strategy"),
    (r'requireAuth\b',                   "requireAuth",            "Node.js",      "custom auth middleware"),
    (r'isAuthenticated\s*\(\)',          "isAuthenticated()",      "Node.js",      "Passport isAuthenticated check"),
    (r'verifyToken\b',                   "verifyToken",            "Node.js",      "custom JWT verify middleware"),

    # ── Go ────────────────────────────────────────────────────────────────────
    (r'middleware\.Auth\b',              "middleware.Auth",        "Go",           "auth middleware"),
    (r'AuthMiddleware\b',                "AuthMiddleware",         "Go",           "auth middleware"),
    (r'RequireAuth\b',                   "RequireAuth",            "Go",           "require auth helper"),
    (r'jwt\.ParseWithClaims\s*\(',       "jwt.ParseWithClaims",   "Go",           "JWT parse — check claims validation"),
    (r'claims\.Valid\s*\(\)',            "claims.Valid()",         "Go",           "JWT claims validation"),

    # ── Ruby on Rails ─────────────────────────────────────────────────────────
    (r'before_action\s*:authenticate',   "before_action :authenticate","Ruby/Rails","auth before action"),
    (r'before_action\s*:require_login',  "before_action :require_login","Ruby/Rails","login required"),
    (r'authorize\s*!\b',                 "authorize!",             "Ruby/CanCanCan","CanCan authorization"),
    (r'can\?\s*\(',                      "can?",                   "Ruby/CanCanCan","CanCan ability check"),
    (r'policy\s*\(',                     "policy()",               "Ruby/Pundit",  "Pundit policy check"),
    (r'pundit_authorize\b|authorize\s+@', "authorize @",           "Ruby/Pundit",  "Pundit authorize call"),
    (r'skip_before_action\s*:authenticate',"skip_before_action :authenticate","Ruby/Rails","⚠️ auth skipped for some actions"),

    # ── Rust ─────────────────────────────────────────────────────────────────
    (r'#\[protect\b',                    "#[protect]",             "Rust/Actix",   "route protection attribute"),
    (r'require_auth\b',                  "require_auth",           "Rust",         "auth middleware"),
]


def _run_gitnexus_cypher(repo: str, cypher: str) -> list[dict]:
    """Run a Cypher query against gitnexus. Returns rows or empty list on failure."""
    try:
        result = subprocess.run(
            [GITNEXUS_BINARY, "query", "--cypher", cypher,
             "--repo", repo, "--format", "json"],
            capture_output=True, text=True,
            timeout=GITNEXUS_TIMEOUT,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "rows" in data:
                return data["rows"]
    except Exception:
        pass
    return []


def _read_file_safe(path: Path, max_bytes: int = 32_768) -> str:
    """Read a file up to max_bytes. Returns empty string on any error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except Exception:
        return ""


def _detect_framework(repo: Path) -> dict:
    """Scan manifest files to detect language, framework, major dependencies."""
    detected_frameworks: list[str] = []
    detected_languages: set[str] = set()
    dependencies: dict[str, list[str]] = {}
    notes: list[str] = []

    manifest_paths = []
    for pattern in MANIFEST_FILES:
        if "*" in pattern:
            manifest_paths.extend(repo.glob(pattern))
        else:
            p = repo / pattern
            if p.exists():
                manifest_paths.append(p)

    for mf in manifest_paths:
        content = _read_file_safe(mf)
        if not content:
            continue

        # --- Language detection from extension ---
        if mf.name == "package.json":
            detected_languages.add("Node.js / JavaScript")
            try:
                pkg = json.loads(content)
                deps = list(pkg.get("dependencies", {}).keys()) + \
                       list(pkg.get("devDependencies", {}).keys())
                dependencies["node"] = deps[:50]
                if any("typescript" in d for d in deps):
                    detected_languages.add("TypeScript")
            except Exception:
                pass
        elif mf.name == "composer.json":
            detected_languages.add("PHP")
            try:
                pkg = json.loads(content)
                deps = list(pkg.get("require", {}).keys())
                dependencies["php"] = deps[:50]
                php_ver = pkg.get("require", {}).get("php", "unknown")
                if php_ver != "unknown":
                    notes.append(f"PHP version constraint: {php_ver}")
            except Exception:
                pass
        elif mf.name in ("requirements.txt", "Pipfile") or "requirements" in str(mf):
            detected_languages.add("Python")
            deps = [l.split("==")[0].split(">=")[0].strip()
                    for l in content.splitlines() if l and not l.startswith("#")]
            dependencies["python"] = deps[:50]
        elif mf.name == "pyproject.toml":
            detected_languages.add("Python")
        elif mf.name == "pom.xml":
            detected_languages.add("Java")
        elif mf.name in ("build.gradle", "build.gradle.kts"):
            detected_languages.add("Java / Kotlin")
        elif mf.name == "go.mod":
            detected_languages.add("Go")
            deps = [l.split()[0] for l in content.splitlines()
                    if l.startswith("\t") and "/" in l]
            dependencies["go"] = deps[:30]
        elif mf.name == "Gemfile":
            detected_languages.add("Ruby")
        elif mf.name == "Cargo.toml":
            detected_languages.add("Rust")
        elif mf.suffix in (".csproj", ".sln"):
            detected_languages.add(".NET / C#")
        elif mf.name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            notes.append(f"Containerized deployment detected: {mf.name}")

        # --- Framework signature scan ---
        for pattern, fw, lang in FRAMEWORK_SIGNATURES:
            if re.search(pattern, content, re.IGNORECASE):
                if fw not in detected_frameworks:
                    detected_frameworks.append(fw)
                detected_languages.add(lang)

    return {
        "frameworks": detected_frameworks,
        "languages": sorted(detected_languages),
        "dependencies": dependencies,
        "notes": notes,
    }


def _detect_auth(repo: Path, gitnexus_available: bool) -> dict:
    """Detect auth/authz mechanisms from config files, annotations, and code structure."""
    found_mechanisms: list[str] = []
    auth_files: list[str] = []
    auth_notes: list[str] = []
    found_annotations: list[dict] = []  # {annotation, language, file, implication}

    # Source file extensions to scan for annotations
    SOURCE_EXTS = {
        ".java", ".kt",                   # Java/Kotlin
        ".cs",                             # C#/.NET
        ".py",                             # Python
        ".php",                            # PHP
        ".ts", ".js",                      # Node.js/NestJS
        ".go",                             # Go
        ".rb",                             # Ruby
        ".rs",                             # Rust
    }
    # Dirs to skip
    SKIP_DIRS = {"node_modules", ".git", ".gradle", "vendor",
                 "dist", "build", "target", "__pycache__"}

    # --- Scan config / env / docs / bootstrap files ---
    scan_globs = [
        "*.env*", ".env.example", ".env.sample",
        "config/**/*.php", "config/**/*.yml", "config/**/*.yaml",
        "config/**/*.json", "src/config/**/*",
        "bootstrap/**/*.php", "bootstrap/**/*.py",
        "app/Http/Middleware/**/*.php",
        "app/Http/Kernel.php",
        "app/Providers/AuthServiceProvider.php",
        "security/**/*", "auth/**/*", "authentication/**/*", "authorization/**/*",
        "middleware/**/*",
        "application.yml", "application.yaml", "application.properties",
        "appsettings.json",
        "README.md", "docs/**/*.md",
    ]
    scan_found = []
    for g in scan_globs:
        scan_found.extend(repo.glob(g))

    # Limit to reasonable number
    for path in scan_found[:80]:
        if not path.is_file():
            continue
        content = _read_file_safe(path, max_bytes=8_192)
        if not content:
            continue
        for pattern, mechanism in AUTH_SIGNATURES:
            if re.search(pattern, content, re.IGNORECASE):
                if mechanism not in found_mechanisms:
                    found_mechanisms.append(mechanism)
                rel = str(path.relative_to(repo))
                if rel not in auth_files:
                    auth_files.append(rel)

    # --- Scan source files for auth annotations/decorators ---
    annotation_files_seen: set[str] = set()
    scanned_count = 0
    for src_file in repo.rglob("*"):
        if scanned_count >= 500:
            break
        if not src_file.is_file():
            continue
        # Skip heavy dirs
        if any(skip in src_file.parts for skip in SKIP_DIRS):
            continue
        if src_file.suffix not in SOURCE_EXTS:
            continue

        content = _read_file_safe(src_file, max_bytes=16_384)
        if not content:
            continue
        scanned_count += 1
        rel = str(src_file.relative_to(repo))

        for pattern, annotation, lang, implication in ANNOTATION_SIGNATURES:
            if re.search(pattern, content, re.IGNORECASE):
                # Track unique annotation occurrences
                found_annotations.append({
                    "annotation": annotation,
                    "language":   lang,
                    "file":       rel,
                    "implication": implication,
                })
                # Add file to auth_files if not already there
                if rel not in annotation_files_seen:
                    annotation_files_seen.add(rel)
                    if rel not in auth_files:
                        auth_files.append(rel)

                # Surface ⚠️ annotations as notes
                if "⚠️" in implication:
                    note = f"⚠️  `{annotation}` in `{rel}` — {implication}"
                    if note not in auth_notes:
                        auth_notes.append(note)

    # Deduplicate annotations (by annotation+file)
    seen_ann: set[tuple] = set()
    deduped_annotations = []
    for a in found_annotations:
        key = (a["annotation"], a["file"])
        if key not in seen_ann:
            seen_ann.add(key)
            deduped_annotations.append(a)

    # Extract annotation-implied mechanisms
    ann_mechanism_map = {
        "@PreAuthorize":  "Spring Security (RBAC)",
        "@Secured":       "Spring Security (RBAC)",
        "@RolesAllowed":  "JSR-250 Role-based",
        "[Authorize]":    ".NET Authorization",
        "[AllowAnonymous]": ".NET Authorization",
        "@login_required": "Django Auth",
        "@jwt_required":  "Flask-JWT",
        "@UseGuards":     "NestJS Guards",
        "authorize!": "CanCanCan (Ruby)",
        "policy()":   "Pundit (Ruby)",
        "@IsGranted": "Symfony Authorization",
        "#[IsGranted": "Symfony Authorization",
        "$this->authorize()": "Laravel Gate/Policy",
        "Gate::":      "Laravel Gate",
    }
    for a in deduped_annotations:
        for key, mech in ann_mechanism_map.items():
            if key in a["annotation"] and mech not in found_mechanisms:
                found_mechanisms.append(mech)

    # --- Multi-tenant signal ---
    tenant_hints = [
        "company_id", "tenant_id", "organization_id", "workspace_id", "account_id"
    ]
    for pattern in tenant_hints:
        hits = list(repo.rglob(f"*{pattern}*"))
        if hits:
            auth_notes.append(f"Multi-tenant indicator found: `{pattern}` in {len(hits)} locations")
            break

    # --- Roles / permissions scan ---
    role_files = list(repo.rglob("*role*")) + list(repo.rglob("*permission*"))
    if role_files[:5]:
        auth_notes.append(
            f"RBAC/permission files detected: "
            + ", ".join(str(f.relative_to(repo)) for f in role_files[:5])
        )

    # --- gitnexus query: find auth middleware classes ---
    gitnexus_auth: list[dict] = []
    if gitnexus_available:
        auth_cypher = (
            "MATCH (n:Symbol) "
            "WHERE n.name =~ '(?i).*(auth|jwt|guard|middleware|token|session|login|logout|authenticate|authorize).*' "
            "RETURN n.name AS name, n.filePath AS file, n.type AS type "
            "LIMIT 30"
        )
        rows = _run_gitnexus_cypher(str(repo), auth_cypher)
        if rows:
            gitnexus_auth = rows
            # Extract unique files
            auth_files_gn = list({r.get("file", "") for r in rows if r.get("file")})
            auth_files.extend([f for f in auth_files_gn if f not in auth_files])

    return {
        "mechanisms": found_mechanisms,
        "auth_relevant_files": auth_files[:30],
        "notes": auth_notes,
        "annotations": deduped_annotations[:50],   # raw annotation hits
        "gitnexus_symbols": gitnexus_auth,
    }


# ── Permission matrix patterns ────────────────────────────────────────────────

# Extract role names from common annotation/decorator patterns
_ROLE_FROM_ANN_PATTERNS: list[tuple[str, int]] = [
    # (regex, capture group that holds role name)
    (r'hasRole\s*\(\s*["\']([^"\']+)["\']',               1),   # Spring SpEL
    (r'hasAuthority\s*\(\s*["\']([^"\']+)["\']',           1),   # Spring SpEL
    (r'@Secured\s*\(\s*\{["\']([^"\']+)["\']',             1),   # Spring @Secured
    (r'@RolesAllowed\s*\(\s*\{?["\']([^"\']+)["\']',       1),   # JSR-250
    (r'\[Authorize\s*\(Roles\s*=\s*"([^"]+)"\)',           1),   # .NET
    (r'\[Authorize\s*\(Policy\s*=\s*"([^"]+)"\)',          1),   # .NET Policy
    (r'@Roles\s*\(\s*(?:Role\.)?([\w.]+)',                 1),   # NestJS @Roles
    (r'@Permissions\s*\(\s*["\']([^"\']+)["\']',           1),   # NestJS @Permissions
    (r'->middleware\s*\(\s*["\']can:([^"\']+)["\']',       1),   # Laravel can:
    (r'Gate::define\s*\(\s*["\']([^"\']+)["\']',           1),   # Laravel Gate::define
    (r'\$this->authorize\s*\(\s*["\']([^"\']+)["\']',      1),   # Laravel authorize()
]

# Role/permission constant patterns (scan source)
_ROLE_CONST_RE = re.compile(
    r'(?:'
    r'(?:const|ROLE_|enum\s+\w+\s*\{|Role\.\w+\s*=)\s*["\']?([A-Z][A-Z0-9_]{2,})["\']?'  # ROLE_ADMIN, const ADMIN
    r'|["\']([a-z]+:[a-z_]+)["\']'   # permission strings like "read:orders"
    r')',
)

# Policy / permission file name patterns
_POLICY_FILE_PATTERNS = [
    "app/Policies/*.php",            # Laravel
    "app/policies/**/*.rb",          # Pundit (Rails)
    "src/**/policy*.{java,kt}",      # Spring
    "src/**/*Policy.{ts,js}",        # NestJS
    "**/*Permission*.{php,py,ts,rb,java,cs}",
    "**/*Role*.{php,py,ts,rb,java,cs}",
    "**/*Gate*.{php,java}",
    "config/policies/**/*",
    "src/security/**/*",
    "src/auth/**/*",
]


def _detect_permission_matrix(repo: Path, auth_annotations: list[dict]) -> dict:
    """
    Build a coarse permission matrix from static signals:
      - roles_found: role names extracted from annotations + constants
      - permissions_found: permission strings (read:orders, write:users)
      - endpoint_role_map: [{file, line, annotation, role}] — which endpoints require which roles
      - policy_files: policy/permission definition file locations
      - public_endpoints: files/annotations explicitly marked no-auth

    NOTE: This is structural evidence only. Dynamic logic (DB-driven roles,
    runtime SpEL, Policy can() bodies) is NOT captured — flag for manual review.
    """
    roles_found: set[str] = set()
    permissions_found: set[str] = set()
    endpoint_role_map: list[dict] = []
    policy_files: list[str] = []
    public_endpoints: list[dict] = []

    # --- Extract role/permission from already-scanned annotations ---
    public_markers = {"@Public()", "[AllowAnonymous]", "@PermitAll",
                      "->withoutMiddleware()", "@jwt_optional"}
    for ann in auth_annotations:
        raw = ann.get("annotation", "")
        file_ = ann.get("file", "")
        # Check public markers
        if any(m in raw for m in public_markers):
            public_endpoints.append({"annotation": raw, "file": file_,
                                      "note": "⚠️ explicitly no-auth"})
        # Extract role from annotation string
        for pattern, grp in _ROLE_FROM_ANN_PATTERNS:
            m = re.search(pattern, raw, re.IGNORECASE)
            if m:
                role = m.group(grp).strip()
                roles_found.add(role)
                endpoint_role_map.append({
                    "file": file_,
                    "annotation": raw,
                    "role": role,
                })
                break

    # --- Scan source files for role/permission constants ---
    SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build",
                 "target", "__pycache__", ".gradle"}
    SOURCE_EXTS = {".php", ".java", ".kt", ".cs", ".py", ".ts", ".js", ".rb"}
    scanned = 0
    for src in repo.rglob("*"):
        if scanned >= 300:
            break
        if not src.is_file() or src.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(skip in src.parts for skip in SKIP_DIRS):
            continue
        # Prioritize files with role/permission in name
        name_lower = src.name.lower()
        is_priority = any(k in name_lower for k in
                          ("role", "permission", "policy", "gate", "ability", "auth", "guard"))
        if not is_priority and scanned > 100:
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")[:12_288]
        except OSError:
            continue
        scanned += 1
        for m in _ROLE_CONST_RE.finditer(content):
            val = m.group(1) or m.group(2)
            if not val:
                continue
            if ":" in val:
                permissions_found.add(val)          # read:orders style
            elif len(val) >= 3:
                roles_found.add(val)                # ADMIN, USER, MODERATOR

    # --- Collect policy/permission definition files ---
    seen_policy: set[str] = set()
    for pat in _POLICY_FILE_PATTERNS:
        for p in repo.glob(pat):
            if p.is_file():
                rel = str(p.relative_to(repo))
                if rel not in seen_policy:
                    seen_policy.add(rel)
                    policy_files.append(rel)

    # Deduplicate endpoint_role_map (same file+role)
    seen_ep: set[tuple] = set()
    deduped_map = []
    for entry in endpoint_role_map:
        key = (entry["file"], entry["role"])
        if key not in seen_ep:
            seen_ep.add(key)
            deduped_map.append(entry)

    return {
        "roles_found": sorted(roles_found)[:40],
        "permissions_found": sorted(permissions_found)[:40],
        "endpoint_role_map": deduped_map[:60],
        "policy_files": policy_files[:20],
        "public_endpoints": public_endpoints[:20],
        "note": (
            "Static extraction only. Dynamic role assignment (DB seeders, "
            "runtime SpEL, Policy can() logic) requires manual review."
        ),
    }


_QUEUE_DIR_NAMES = frozenset({
    "queue", "queues", "jobs", "job",
    "workers", "worker",
    "consumers", "consumer",
    "listeners", "listener",
    "events", "event",
    "tasks", "task",
    "processors", "processor",
    "subscribers", "subscriber",
    "handlers", "handler",      # ambiguous but common in async context
    "schedulers", "scheduler",
    "commands", "command",      # Laravel Artisan commands / console jobs
    "messaging",
})

# Framework-specific async annotations / base-class patterns (source-level signals)
_QUEUE_SOURCE_PATTERNS: list[tuple[str, str]] = [
    # Java / Spring
    (r'@Scheduled\b',                "Spring @Scheduled"),
    (r'@RabbitListener\b',           "Spring RabbitMQ listener"),
    (r'@KafkaListener\b',            "Spring Kafka listener"),
    (r'@JmsListener\b',              "Spring JMS listener"),
    (r'@SqsListener\b',              "Spring Cloud AWS SQS listener"),
    (r'@Async\b',                    "Spring @Async"),
    (r'implements\s+Job\b',          "Quartz/Spring Job"),
    (r'extends\s+QuartzJobBean\b',   "Quartz job"),
    # C# / .NET
    (r'\bBackgroundService\b',       ".NET BackgroundService"),
    (r'\bIHostedService\b',          ".NET IHostedService"),
    (r'\bIBackgroundTask\b',         ".NET background task"),
    (r'\[Queue\b',                   ".NET queue attribute"),
    (r'\bHangfire\b',                "Hangfire background jobs (.NET)"),
    (r'\bMassTransit\b',             "MassTransit consumer (.NET)"),
    # Python
    (r'@app\.task\b|@shared_task\b', "Celery task"),
    (r'\bcelery\b',                  "Celery"),
    (r'\brq\.job\b|@job\b',          "RQ (Redis Queue) job"),
    (r'\bdramatiq\b',                "Dramatiq task"),
    # Node.js / TS
    (r'@Processor\s*\(',             "BullMQ/Bull processor (NestJS)"),
    (r'@Process\s*\(',               "Bull queue process"),
    (r'\bQueue\.process\b',          "Bull queue process"),
    (r'\bnew\s+Worker\s*\(',         "BullMQ Worker"),
    # Go
    (r'\basynq\.NewWorker\b',        "Asynq worker (Go)"),
    (r'\bmachinery\.NewWorker\b',    "Machinery worker (Go)"),
    # Laravel / PHP
    (r'implements\s+ShouldQueue\b',  "Laravel queued job"),
    (r'extends\s+Mailable\b',        "Laravel Mailable (queued)"),
    (r'implements\s+ShouldBroadcast\b', "Laravel broadcast event"),
    (r'\bSchedule::\b',              "Laravel task scheduler"),
]

_QUEUE_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build",
                    "target", "__pycache__", ".gradle", "coverage"}
_QUEUE_SOURCE_EXTS = {
    ".php", ".java", ".kt",
    ".cs",
    ".py",
    ".ts", ".js",
    ".go",
    ".rb",
    ".rs",
}


def _detect_queue(repo: Path) -> str | None:
    """
    Three-layer async/queue detection — returns a note string if detected, else None.

    Layer 1: top-level dir names (fast)
    Layer 2: any subdirectory anywhere in the repo named after queue patterns
    Layer 3: source-file annotation / base-class scan (framework-specific)
    """
    # Layer 1: top-level dirs (fast path)
    top_dirs = {d.name.lower() for d in repo.iterdir()
                if d.is_dir() and not d.name.startswith(".")}
    if top_dirs & _QUEUE_DIR_NAMES:
        return "Async job/queue processing detected"

    # Layer 2: any subdirectory anywhere named after queue patterns
    for d in repo.rglob("*"):
        if not d.is_dir():
            continue
        if any(skip in d.parts for skip in _QUEUE_SKIP_DIRS):
            continue
        if d.name.lower() in _QUEUE_DIR_NAMES:
            return "Async job/queue processing detected"

    # Layer 3: source-file annotation / base-class scan
    scanned = 0
    for src in repo.rglob("*"):
        if scanned >= 600:
            break
        if not src.is_file() or src.suffix.lower() not in _QUEUE_SOURCE_EXTS:
            continue
        if any(skip in src.parts for skip in _QUEUE_SKIP_DIRS):
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")[:16_384]
        except OSError:
            continue
        scanned += 1
        for pattern, _ in _QUEUE_SOURCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return "Async job/queue processing detected"

    return None


def _detect_architecture(repo: Path) -> dict:
    """Infer architecture from directory structure and source-level signals."""
    notes: list[str] = []
    dirs = sorted([d.name for d in repo.iterdir() if d.is_dir()
                   and not d.name.startswith(".")])

    # Microservice signals
    if any(d in dirs for d in ("services", "apps", "packages", "microservices")):
        notes.append("Monorepo / microservice structure detected")

    # API-first signals
    if any(d in dirs for d in ("api", "rest", "graphql", "grpc", "proto")):
        notes.append("API-first architecture")

    # Queue / async signals — 3-layer detection (top-level + subdir + source scan)
    queue_note = _detect_queue(repo)
    if queue_note:
        notes.append(queue_note)

    # File upload signals
    upload_hints = list(repo.rglob("*upload*")) + list(repo.rglob("*storage*"))
    if upload_hints[:3]:
        notes.append(f"File upload/storage functionality present")

    # Admin panel
    admin_hints = list(repo.rglob("*admin*"))
    if admin_hints[:3]:
        notes.append("Admin panel detected — check for separate auth path")

    # Public API
    public_hints = list(repo.rglob("*public*")) + list(repo.rglob("*guest*"))
    if public_hints[:3]:
        notes.append("Public/guest-accessible routes likely present")

    # Payment
    pay_hints = list(repo.rglob("*payment*")) + list(repo.rglob("*billing*")) + list(repo.rglob("*checkout*"))
    if pay_hints[:3]:
        notes.append("Payment/billing functionality detected — business-critical flows")

    # Webhooks
    webhook_hints = list(repo.rglob("*webhook*")) + list(repo.rglob("*callback*"))
    if webhook_hints[:3]:
        notes.append("Webhook/callback endpoints detected — validate sender identity")

    return {
        "top_level_dirs": dirs,
        "inferred_notes": notes,
    }


def _check_gitnexus(repo: str) -> bool:
    """Return True if gitnexus is installed and the repo has been analyzed."""
    try:
        result = subprocess.run(
            [GITNEXUS_BINARY, "--version"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _build_markdown_report(intel: dict) -> str:
    """Build a clean Claude-readable markdown from the intel dict."""
    fw = intel.get("framework_detection", {})
    auth = intel.get("auth_detection", {})
    arch = intel.get("architecture", {})
    perm = intel.get("permission_matrix", {})

    lines = [
        "# Codebase Intelligence Report",
        f"**Repo:** `{intel.get('repo', '')}`",
        "",
        "---",
        "",
        "## Tech Stack",
        f"- **Languages:** {', '.join(fw.get('languages', [])) or 'Unknown'}",
        f"- **Frameworks:** {', '.join(fw.get('frameworks', [])) or 'Unknown'}",
    ]

    for note in fw.get("notes", []):
        lines.append(f"- {note}")

    dep_summary = []
    for lang, deps in fw.get("dependencies", {}).items():
        if deps:
            dep_summary.append(f"  - {lang}: {', '.join(deps[:15])}")
    if dep_summary:
        lines.append("\n**Key dependencies:**")
        lines.extend(dep_summary)

    lines += [
        "",
        "---",
        "",
        "## Authentication & Authorization",
        f"- **Detected mechanisms:** {', '.join(auth.get('mechanisms', [])) or 'None detected'}",
    ]

    for note in auth.get("notes", []):
        lines.append(f"- {note}")

    auth_files = auth.get("auth_relevant_files", [])
    if auth_files:
        lines.append("\n**Auth-relevant files:**")
        for f in auth_files[:15]:
            lines.append(f"  - `{f}`")

    gn_syms = auth.get("gitnexus_symbols", [])
    if gn_syms:
        lines.append("\n**Auth symbols (from gitnexus):**")
        for sym in gn_syms[:15]:
            lines.append(f"  - `{sym.get('name')}` — `{sym.get('file', '')}`")

    annotations = auth.get("annotations", [])
    if annotations:
        lines.append("\n**Auth annotations/decorators found in source code:**")
        # Group by annotation, show first file + implication
        seen_ann_md: dict[str, str] = {}
        for a in annotations:
            ann = a["annotation"]
            if ann not in seen_ann_md:
                seen_ann_md[ann] = (
                    f"  - `{ann}` [{a['language']}] — {a['implication']} "
                    f"*(e.g. `{a['file']}`)*"
                )
        for line in seen_ann_md.values():
            lines.append(line)

    # Permission matrix section
    if perm.get("roles_found") or perm.get("policy_files") or perm.get("public_endpoints"):
        lines += ["", "---", "", "## Permission Matrix (Static)"]
        lines.append(f"> {perm.get('note', '')}")
        lines.append("")

        if perm.get("roles_found"):
            lines.append(f"**Roles detected:** {', '.join(f'`{r}`' for r in perm['roles_found'])}")
        if perm.get("permissions_found"):
            lines.append(f"**Permissions detected:** {', '.join(f'`{p}`' for p in perm['permissions_found'])}")

        if perm.get("policy_files"):
            lines.append("\n**Policy/permission definition files:**")
            for f in perm["policy_files"]:
                lines.append(f"  - `{f}`")

        if perm.get("public_endpoints"):
            lines.append("\n**⚠️ Explicitly public / no-auth endpoints:**")
            for ep in perm["public_endpoints"]:
                lines.append(f"  - `{ep['annotation']}` in `{ep['file']}`")

        ep_map = perm.get("endpoint_role_map", [])
        if ep_map:
            lines.append("\n**Endpoint → role requirements:**")
            for entry in ep_map[:30]:
                lines.append(
                    f"  - `{entry['file']}` — `{entry['annotation']}` → role: **{entry['role']}**"
                )
            if len(ep_map) > 30:
                lines.append(f"  - *(+{len(ep_map)-30} more — see permission_matrix in repo_intel.json)*")

    lines += [
        "",
        "---",
        "",
        "## Architecture Notes",
        f"- **Top-level dirs:** {', '.join(arch.get('top_level_dirs', []))}",
    ]
    for note in arch.get("inferred_notes", []):
        lines.append(f"- ⚠️  {note}")

    lines += [
        "",
        "---",
        "",
        "## Security Considerations",
        "> These are extracted from the codebase structure — "
        "Claude should use them to guide the audit.",
        "",
    ]
    all_notes = intel.get("security_notes", [])
    for note in all_notes:
        lines.append(f"- {note}")

    return "\n".join(lines)


def run(run_id: str, repo: str) -> dict:
    """
    Extract codebase intelligence before Phase 1 audit.

    Returns structured intel dict and saves:
      - catalog/repo_intel.json   (structured)
      - catalog/repo_intel.md     (human-readable)
    """
    ensure_run_dirs(run_id)
    repo_path = Path(repo).resolve()

    if not repo_path.exists():
        return {"error": f"Repo path not found: {repo}"}

    gitnexus_ok = _check_gitnexus(repo)

    # Run all detection passes
    fw = _detect_framework(repo_path)
    auth = _detect_auth(repo_path, gitnexus_ok)
    arch = _detect_architecture(repo_path)
    perm = _detect_permission_matrix(repo_path, auth.get("annotations", []))

    # Synthesize top-level security notes
    security_notes: list[str] = []
    security_notes.extend(fw.get("notes", []))
    security_notes.extend(auth.get("notes", []))
    security_notes.extend(arch.get("inferred_notes", []))

    # Deduplicate
    seen = set()
    security_notes_dedup = []
    for n in security_notes:
        if n not in seen:
            seen.add(n)
            security_notes_dedup.append(n)

    intel = {
        "run_id": run_id,
        "repo": str(repo_path),
        "gitnexus_available": gitnexus_ok,
        "framework_detection": fw,
        "auth_detection": auth,
        "architecture": arch,
        "permission_matrix": perm,
        "security_notes": security_notes_dedup,
    }

    # Save JSON
    saved_json = write(run_id, "catalog", "repo_intel.json", intel)

    # Save Markdown
    md_content = _build_markdown_report(intel)
    md_path = Path(saved_json).parent / "repo_intel.md"
    md_path.write_text(md_content, encoding="utf-8")

    return {
        **intel,
        "saved_json": saved_json,
        "saved_md": str(md_path),
    }
