"""
tools/api_parser.py
────────────────────
MCP tool: api_parse

Input:  run_id, repo, stack
Output: { endpoints[], saved_to }
Saves:  catalog/endpoints.json
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Dict, List

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

# ── Language → file extensions ────────────────────────────────────────────────
LANG_EXTS: Dict[str, List[str]] = {
    "python": [".py"],
    "java":   [".java"],
    "js":     [".js", ".cjs", ".mjs"],
    "ts":     [".ts"],
    "go":     [".go"],
    "php":    [".php"],
    "ruby":   [".rb"],
    "csharp": [".cs"],
}
ALL_EXTS = [e for exts in LANG_EXTS.values() for e in exts]

# ── Regex patterns ─────────────────────────────────────────────────────────────
PY_DECORATOR_RE = re.compile(
    r'@(?:\w+\.)*(?:get|post|put|delete|patch|options|head|route)\s*'
    r'\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PY_MULTI_METHOD_RE = re.compile(r'methods\s*=\s*\[([^\]]+)\]', re.IGNORECASE)
PY_PARAM_RE = re.compile(
    r'(\w+)\s*:\s*(?:Optional\[)?(\w+)(?:\])?\s*=\s*(Query|Body|Form|File|Header|Cookie|Path)\(',
    re.IGNORECASE,
)
SPRING_MAPPING_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\('
    r'(?:value\s*=\s*)?["\']([^"\']+)["\']',
    re.IGNORECASE,
)
SPRING_PARAM_RE = re.compile(
    r'@(RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody)'
    r'(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)',
    re.IGNORECASE,
)
JS_ROUTE_RE = re.compile(
    r'(?:app|router|fastify)\.(get|post|put|delete|patch|options|use)\s*'
    r'\(\s*["`]([^"`]+)["`]',
    re.IGNORECASE,
)
JS_PARAM_ACCESS = re.compile(r'req\.(query|body|params|headers|cookies)\.(\w+)')
NESTJS_RE = re.compile(r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']*)["\']')
NESTJS_PARAM_RE = re.compile(r'@(Query|Body|Param|Headers|Cookies)\(\s*["\']?(\w*)["\']?\)')
GO_ROUTE_RE = re.compile(
    r'(?:r|e|g|router)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s*\(\s*"([^"]+)"',
    re.IGNORECASE,
)
GO_QUERY_RE = re.compile(r'c\.(?:Query|PostForm|DefaultQuery)\s*\(\s*"(\w+)"')
GO_PARAM_RE  = re.compile(r'c\.Param\s*\(\s*"(\w+)"')
PHP_ROUTE_RE = re.compile(
    r'Route::(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
RAILS_ROUTE_RE = re.compile(
    r'(get|post|put|delete|patch|resources?)\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)
CS_ROUTE_RE = re.compile(
    r'\[(?:Http)?(Get|Post|Put|Delete|Patch)(?:\s*\(\s*["\']([^"\']+)["\']\s*\))?\]',
    re.IGNORECASE,
)
CS_BASE_ROUTE_RE = re.compile(
    r'\[Route\(\s*["\']([^"\']+)["\']\s*\)\]',
    re.IGNORECASE,
)
CS_PARAM_RE = re.compile(
    r'\[(FromQuery|FromBody|FromRoute|FromHeader|FromForm)\]\s+(?:[\w<>,\[\]]+\s+)?(\w+)',
    re.IGNORECASE,
)
PATH_PARAM_RE = re.compile(r'\{(\w+)\}|:(\w+)|<(?:[\w]+:)?(\w+)>')
SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "dist", "build",
             ".tox", "venv", ".env", "migrations"}

# ── Auth tag extraction ───────────────────────────────────────────────────────
# Universal: auth-related annotations/decorators (all frameworks)
AUTH_ANN_RE = re.compile(
    r'(?:@|\[)(?:'
    r'UseGuards|Roles|Permissions|Public|ApiBearerAuth|ApiSecurity|SetMetadata|'  # NestJS
    r'PreAuthorize|Secured|RolesAllowed|IsAuthenticated|HasRole|HasAuthority|'    # Spring
    r'login_required|permission_classes|requires_auth|'                           # Python
    r'authenticate|authorized|auth_required|'                                     # generic
    r'Authorize|AllowAnonymous'                                                   # C#
    r')(?:\([^)]*\))?(?:\])?',
    re.IGNORECASE,
)
# PHP/Laravel: ->middleware('auth') or ->middleware(['auth', 'jwt'])
PHP_MIDDLEWARE_RE = re.compile(
    r'->middleware\(\s*[\["\']([^"\')\]]+)["\'\]]',
    re.IGNORECASE,
)
# FastAPI: Depends(get_current_user) — only Depends that look auth-related
FASTAPI_AUTH_DEPENDS_RE = re.compile(
    r'Depends\(\s*(\w*(?:auth|user|current|login|token|verify|jwt|guard)\w*)\s*\)',
    re.IGNORECASE,
)
# Express: middleware args between path and handler function
# router.get('/path', authenticate, isAdmin, (req, res) => {...})
EXPRESS_MIDDLEWARE_ARGS_RE = re.compile(
    r'(?:app|router)\.\w+\s*\(\s*["`][^"`]*["`]\s*,\s*((?:[\w.]+(?:\([^)]*\))?\s*,\s*)+)',
    re.IGNORECASE,
)
# Rails: before_action :authenticate_user!, only: [:show, :edit]
RAILS_BEFORE_ACTION_RE = re.compile(
    r'before_action\s+:(\w+)(?:[^#\n]*only:\s*\[([^\]]*)\])?',
    re.IGNORECASE,
)
# Java/Spring controller class annotation pattern
SPRING_CLASS_RE = re.compile(r'@(?:RestController|Controller)\b')
# NestJS controller class pattern
NESTJS_CONTROLLER_RE = re.compile(r'@Controller\s*\(')


def run(run_id: str, repo: str, stack: str) -> dict:
    """Parse API routes and params across all frameworks."""
    ensure_run_dirs(run_id)

    repo_path = Path(repo)
    endpoints: List[dict] = []

    for src_file in _iter_source_files(repo_path, stack):
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(src_file.relative_to(repo_path))
        ext = src_file.suffix.lower()

        if ext == ".py":
            endpoints.extend(_parse_python(content, rel_path, stack))
        elif ext == ".java":
            endpoints.extend(_parse_java(content, rel_path))
        elif ext in (".js", ".ts", ".cjs", ".mjs"):
            endpoints.extend(_parse_js_ts(content, rel_path, ext))
        elif ext == ".go":
            endpoints.extend(_parse_go(content, rel_path))
        elif ext == ".php":
            endpoints.extend(_parse_php(content, rel_path))
        elif ext == ".rb":
            endpoints.extend(_parse_ruby(content, rel_path))
        elif ext == ".cs":
            endpoints.extend(_parse_csharp(content, rel_path))

    # Deduplicate
    seen: set[str] = set()
    unique: List[dict] = []
    for ep in endpoints:
        if ep["id"] not in seen:
            seen.add(ep["id"])
            unique.append(ep)

    # Flag IDOR candidates: endpoints with ID-like params + no ownership check
    idor_candidates = [
        {"id": ep["id"], "method": ep["method"], "path": ep["path"],
         "id_params": [p["name"] for p in ep.get("params", [])
                       if _IDOR_PARAM_RE.match(p.get("name", ""))
                       and p.get("location") in ("path", "query")],
         "auth_tags": ep.get("auth_tags", []),
         "auth_required": ep.get("auth_required"),
         "file": ep["file"], "line": ep["line"]}
        for ep in unique if _idor_risk(ep)
    ]

    saved_to = write(run_id, "catalog", "endpoints.json", unique)
    return {
        "endpoints": unique,
        "endpoint_count": len(unique),
        "idor_candidates": idor_candidates,
        "idor_candidate_count": len(idor_candidates),
        "saved_to": saved_to,
    }


# ── Auth helpers ─────────────────────────────────────────────────────────────

def _class_auth_tags(lines: List[str], endpoint_lineno: int) -> List[str]:
    """
    Walk backwards from endpoint_lineno to find the enclosing class/controller
    definition, then return auth annotations found in the 10 lines before it.
    Covers NestJS @UseGuards on controller class and Spring @PreAuthorize on class.
    """
    tags: List[str] = []
    # Find nearest class/controller line above endpoint
    class_lineno = -1
    for i in range(endpoint_lineno - 2, -1, -1):
        if SPRING_CLASS_RE.search(lines[i]) or NESTJS_CONTROLLER_RE.search(lines[i]):
            class_lineno = i
            break
        # Java class keyword
        if re.search(r'\bclass\s+\w+', lines[i]) and i < endpoint_lineno - 2:
            class_lineno = i
            break
    if class_lineno == -1:
        return tags
    # Scan annotations immediately before the class definition (up to 10 lines)
    for i in range(max(0, class_lineno - 10), class_lineno + 1):
        for m in AUTH_ANN_RE.finditer(lines[i]):
            tag = m.group(0).strip()
            if tag not in tags:
                tags.append(tag)
    return tags


def _local_auth_tags(lines: List[str], lineno: int) -> List[str]:
    """
    Scan a window of lines around the route definition for auth tags.
    Covers method-level annotations, PHP middleware chain, FastAPI Depends,
    and Express named middleware args.
    """
    tags: List[str] = []
    start = max(0, lineno - 8)
    end   = min(len(lines), lineno + 6)
    for line in lines[start:end]:
        # Universal annotations
        for m in AUTH_ANN_RE.finditer(line):
            tag = m.group(0).strip()
            if tag not in tags:
                tags.append(tag)
        # PHP ->middleware(...)
        for m in PHP_MIDDLEWARE_RE.finditer(line):
            tag = f"middleware:{m.group(1).strip()}"
            if tag not in tags:
                tags.append(tag)
        # FastAPI Depends(auth_fn)
        for m in FASTAPI_AUTH_DEPENDS_RE.finditer(line):
            tag = f"Depends({m.group(1)})"
            if tag not in tags:
                tags.append(tag)
    return tags


def _php_group_auth_tags(lines: List[str], lineno: int) -> List[str]:
    """
    Walk backwards up to 60 lines tracking brace depth to detect enclosing
    Route::middleware([...])->group(function() { ... }) context.
    """
    tags: List[str] = []
    depth = 0
    for i in range(lineno - 1, max(0, lineno - 60), -1):
        line = lines[i]
        depth += line.count('}') - line.count('{')
        if depth < 0:
            # Crossed a group boundary — check this line for middleware context
            for m in PHP_MIDDLEWARE_RE.finditer(line):
                tag = f"middleware:{m.group(1).strip()}"
                if tag not in tags:
                    tags.append(tag)
            depth = 0
    return tags


def _express_middleware_tags(line: str) -> List[str]:
    """
    Extract named middleware between the route path and the handler function
    in an Express route definition.
    Example: router.get('/path', authenticate, isAdmin, (req, res) => {})
    Returns: ['express_mw:authenticate', 'express_mw:isAdmin']
    """
    tags: List[str] = []
    m = EXPRESS_MIDDLEWARE_ARGS_RE.search(line)
    if not m:
        return tags
    raw = m.group(1)
    for part in raw.split(','):
        name = part.strip().rstrip(',').strip()
        if name and not name.startswith('(') and not name.startswith('async'):
            # Skip obvious non-middleware: short generic names or empty
            if len(name) > 2:
                tags.append(f"express_mw:{name}")
    return tags


def _rails_before_actions(content: str) -> List[tuple]:
    """
    Parse all before_action declarations in a Rails controller file.
    Returns list of (action_name, only_set_or_None) tuples.
    """
    result = []
    for m in RAILS_BEFORE_ACTION_RE.finditer(content):
        action = m.group(1)
        only_raw = m.group(2)
        only_set = None
        if only_raw:
            only_set = {s.strip().strip(':') for s in only_raw.split(',')}
        result.append((action, only_set))
    return result


def _auth_required(tags: List[str]) -> bool | None:
    """
    Infer whether the endpoint requires authentication from collected tags.
    Returns True if auth tags found, False if @Public found, None if unknown.
    """
    if not tags:
        return None
    # NestJS @Public() means explicitly no auth
    if any('Public' in t for t in tags):
        return False
    return True


# ── Per-language parsers ──────────────────────────────────────────────────────

def _parse_python(content: str, file_path: str, stack: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        m = PY_DECORATOR_RE.search(stripped)
        if m:
            path = m.group(1)
            method_m = PY_MULTI_METHOD_RE.search(stripped)
            if method_m:
                methods = [x.strip().strip("\"'") for x in method_m.group(1).split(",")]
            else:
                mw = re.search(r'\.(get|post|put|delete|patch|options|head|route)\s*\(', stripped, re.I)
                methods = [mw.group(1).upper() if mw else "GET"]
            handler = _next_function(lines, lineno)
            params = _extract_path_params(path) + _parse_fastapi_params(lines, lineno)
            auth_tags = _local_auth_tags(lines, lineno)
            for method in methods:
                endpoints.append(_make_ep(method.upper(), path, params, handler, file_path, lineno, stack, auth_tags))
    return endpoints


def _parse_fastapi_params(lines: List[str], decorator_line: int) -> List[dict]:
    params = []
    fn_text = ""
    in_fn = False
    for i in range(decorator_line, min(decorator_line + 20, len(lines))):
        ln = lines[i]
        if "def " in ln:
            in_fn = True
        if in_fn:
            fn_text += " " + ln
            if ":" in ln and not ln.strip().endswith(","):
                break
    for m in PY_PARAM_RE.finditer(fn_text):
        name, ptype, loc = m.group(1), m.group(2), m.group(3).lower()
        params.append({"name": name, "type": ptype, "location": loc})
    return params


def _parse_java(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = SPRING_MAPPING_RE.search(line)
        if m:
            method = m.group(1).upper()
            path   = m.group(2)
            if method == "REQUEST":
                method = "GET"
            params = _extract_path_params(path)
            for j in range(lineno, min(lineno + 30, len(lines))):
                pm = SPRING_PARAM_RE.search(lines[j])
                if pm:
                    ann, name = pm.group(1), pm.group(2)
                    loc_map = {"requestparam": "query", "pathvariable": "path",
                               "requestheader": "header", "cookievalue": "cookie", "requestbody": "body"}
                    params.append({"name": name, "type": "string", "location": loc_map.get(ann.lower(), "query")})
                if re.search(r'(public|private|protected)\s+\w+\s+\w+\s*\(', lines[j]) and j > lineno:
                    break
            hm = re.search(r'(public|private|protected)\s+\w+\s+(\w+)\s*\(', content[content.find(m.group(0)):])
            handler = hm.group(2) if hm else ""
            # Method-level auth annotations + class-level inheritance
            auth_tags = _local_auth_tags(lines, lineno) + _class_auth_tags(lines, lineno)
            auth_tags = list(dict.fromkeys(auth_tags))  # deduplicate
            endpoints.append(_make_ep(method, path, params, handler, file_path, lineno, "spring", auth_tags))
    return endpoints


def _parse_js_ts(content: str, file_path: str, ext: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for m in NESTJS_RE.finditer(line):
            method, path = m.group(1).upper(), m.group(2)
            # Method-level + controller class-level (e.g. @UseGuards on class)
            auth_tags = _local_auth_tags(lines, lineno) + _class_auth_tags(lines, lineno)
            auth_tags = list(dict.fromkeys(auth_tags))
            endpoints.append(_make_ep(method, path or "/", _extract_path_params(path), "",
                                      file_path, lineno, "nestjs", auth_tags))
        m = JS_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            if method == "USE":
                method = "ALL"
            params = _extract_path_params(path) + _extract_js_params(lines, lineno)
            auth_tags = _local_auth_tags(lines, lineno) + _express_middleware_tags(line)
            auth_tags = list(dict.fromkeys(auth_tags))
            endpoints.append(_make_ep(method, path, params, "", file_path, lineno, "express", auth_tags))
    return endpoints


def _extract_js_params(lines: List[str], start: int, window: int = 40) -> List[dict]:
    params = []
    seen: set = set()
    loc_map = {"query": "query", "body": "body", "params": "path", "headers": "header", "cookies": "cookie"}
    for i in range(start, min(start + window, len(lines))):
        for m in JS_PARAM_ACCESS.finditer(lines[i]):
            location, name = m.group(1), m.group(2)
            key = (name, location)
            if key not in seen:
                seen.add(key)
                params.append({"name": name, "type": "string", "location": loc_map.get(location, "query")})
    return params


def _parse_go(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = GO_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            params = _extract_path_params(path)
            for j in range(lineno, min(lineno + 40, len(lines))):
                for qm in GO_QUERY_RE.finditer(lines[j]):
                    params.append({"name": qm.group(1), "type": "string", "location": "query"})
                for pm in GO_PARAM_RE.finditer(lines[j]):
                    params.append({"name": pm.group(1), "type": "string", "location": "path"})
            # Go middleware is typically via route groups — local window may catch named middleware
            auth_tags = _local_auth_tags(lines, lineno)
            endpoints.append(_make_ep(method, path, params, "", file_path, lineno, "gin", auth_tags))
    return endpoints


def _parse_php(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = PHP_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            # Inline ->middleware() on same line + enclosing Route::middleware group
            auth_tags = _local_auth_tags(lines, lineno) + _php_group_auth_tags(lines, lineno)
            auth_tags = list(dict.fromkeys(auth_tags))
            endpoints.append(_make_ep(method, path, _extract_path_params(path), "",
                                      file_path, lineno, "laravel", auth_tags))
    return endpoints


def _parse_ruby(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    # Parse file-level before_action declarations (apply to all actions unless :only scoped)
    before_actions = _rails_before_actions(content)
    for lineno, line in enumerate(lines, start=1):
        m = RAILS_ROUTE_RE.search(line)
        if m:
            verb, path = m.group(1).lower(), m.group(2)
            if verb in ("resources", "resource"):
                for action_method, ap in [("GET", f"/{path}"), ("POST", f"/{path}"),
                                           ("GET", f"/{path}/{{id}}"), ("PUT", f"/{path}/{{id}}"),
                                           ("DELETE", f"/{path}/{{id}}")]:
                    # Rails auth tags from before_action — apply broadly (no :only scoping here)
                    auth_tags = [f"before_action:{a}" for a, _ in before_actions]
                    endpoints.append(_make_ep(action_method, ap, _extract_path_params(ap), "",
                                              file_path, lineno, "rails", auth_tags))
            else:
                auth_tags = [f"before_action:{a}" for a, _ in before_actions]
                endpoints.append(_make_ep(verb.upper(), path, _extract_path_params(path), "",
                                          file_path, lineno, "rails", auth_tags))
    return endpoints


def _parse_csharp(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    base_path = ""
    # Find class-level route
    for line in lines[:50]:
        m = CS_BASE_ROUTE_RE.search(line)
        if m:
            base_path = m.group(1).lstrip('/')
            break

    for lineno, line in enumerate(lines, start=1):
        m = CS_ROUTE_RE.search(line)
        if m:
            method = m.group(1).upper()
            sub_path = m.group(2) or ""
            # Combine base_path + sub_path
            path_parts = []
            if base_path: path_parts.append(base_path.rstrip('/'))
            if sub_path: path_parts.append(sub_path.lstrip('/'))
            full_path = "/" + "/".join(path_parts)
            if not full_path:
                full_path = "/"
            
            params = _extract_path_params(full_path)
            for j in range(lineno, min(lineno + 15, len(lines))):
                for pm in CS_PARAM_RE.finditer(lines[j]):
                    ann, name = pm.group(1), pm.group(2)
                    loc_map = {"FromQuery": "query", "FromRoute": "path", "FromHeader": "header", 
                               "FromForm": "form", "FromBody": "body"}
                    params.append({"name": name, "type": "string", "location": loc_map.get(ann, "query")})
                if re.search(r'(public|private|protected|internal)\s+', lines[j]) and j > lineno:
                    break

            # Controller class annotations (line 1 to method) + local annotations
            auth_tags = _local_auth_tags(lines[:lineno], lineno - 1)
            endpoints.append(_make_ep(method, full_path, params, "", file_path, lineno, "aspnet", auth_tags))
    return endpoints


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_path_params(path: str) -> List[dict]:
    params = []
    for m in PATH_PARAM_RE.finditer(path):
        name = next((g for g in m.groups() if g), None)
        if name:
            params.append({"name": name, "type": "string", "location": "path"})
    return params


def _next_function(lines: List[str], decorator_line: int, lookahead: int = 5) -> str:
    for i in range(decorator_line, min(decorator_line + lookahead, len(lines))):
        m = re.search(r'(?:async\s+)?def\s+(\w+)\s*\(', lines[i])
        if m:
            return m.group(1)
    return ""


def _make_ep(method: str, path: str, params: List[dict], handler: str,
             file_path: str, line: int, framework: str,
             auth_tags: List[str] | None = None) -> dict:
    uid = hashlib.md5(f"{method}:{path}:{file_path}:{line}".encode()).hexdigest()[:12]
    tags = auth_tags or []
    return {
        "id": uid, "method": method, "path": path, "params": params,
        "handler": handler, "file": file_path, "line": line, "framework": framework,
        "auth_tags": tags,
        "auth_required": _auth_required(tags),
    }


# ID-like path/query param names → IDOR candidate signal
_IDOR_PARAM_RE = re.compile(
    r'^(?:id|uuid|guid|pk|'
    r'\w+_id|\w+_uuid|\w+_pk|'          # order_id, user_id, account_uuid
    r'id_\w+|'                           # id_order (less common)
    r'\w+Id|\w+Uuid|\w+Guid'             # camelCase: orderId, userId
    r')$',
    re.IGNORECASE,
)

# Ownership-check annotations — if present, lower IDOR risk
_OWNERSHIP_ANN_MARKERS = {
    "hasPermission", "@PostAuthorize", "can?", "policy()", "authorize!",
    "authorize()", "@IsGranted", "Gate::", "$this->authorize",
}


def _idor_risk(endpoint: dict) -> bool:
    """
    Flag endpoint as IDOR candidate when:
    - Has path/query param that looks like an object ID  AND
    - No ownership-check annotation in auth_tags
    GET/POST/PUT/DELETE all count — IDOR can affect read AND write.
    """
    # Check for ID-like params
    has_id_param = any(
        _IDOR_PARAM_RE.match(p.get("name", ""))
        for p in endpoint.get("params", [])
        if p.get("location") in ("path", "query")
    )
    if not has_id_param:
        return False
    # If we have an ownership-check annotation, risk is lower (not a definitive FP)
    tags = " ".join(endpoint.get("auth_tags", []))
    has_ownership_check = any(marker in tags for marker in _OWNERSHIP_ANN_MARKERS)
    return not has_ownership_check


def _iter_source_files(repo: Path, stack: str):
    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in ALL_EXTS:
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        yield f
