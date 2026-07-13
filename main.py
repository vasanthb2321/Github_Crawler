from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import httpx
import re
import asyncio
import base64
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
import uuid
import os
GITHUB_DEFAULT_TOKEN = os.getenv("GITHUB_TOKEN") or "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"

app = FastAPI(title="GitHub Secret Scanner API", version="1.0.0")

templates = Jinja2Templates(directory="templates")

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores
scan_results: dict = {}
repo_cache: dict = {}  # key: repo_url → cached findings + stats
 
# ─── Secret Patterns ─────────────────────────────────────────────────────────
 
SECRET_PATTERNS = {
    "AWS Access Key":     r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":     r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:]["\'\`]?\s*([A-Za-z0-9/+=]{40})',
    "Google API Key":     r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":       r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}',
    "Slack Token":        r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Stripe Secret Key":  r'sk_live_[0-9a-zA-Z]{24,34}',
    "Private Key Header": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "Hardcoded Password": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\',;]{6,})',
    "Hardcoded Email":    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "API Key Generic":    r'(?i)api[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,64})',
    "Bearer Token":       r'(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)',
    "Database URL":       r'(?i)(?:mongodb|postgres|mysql|redis):\/\/[^\s"\']+',
    "JWT Token":          r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
}
 
SEVERITY_MAP = {
    "AWS Access Key":     "critical",
    "AWS Secret Key":     "critical",
    "Stripe Secret Key":  "critical",
    "Private Key Header": "critical",
    "GitHub Token":       "high",
    "Google API Key":     "high",
    "Slack Token":        "high",
    "JWT Token":          "high",
    "Database URL":       "medium",
    "API Key Generic":    "medium",
    "Bearer Token":       "medium",
    "Hardcoded Password": "low",
    "Hardcoded Email":    "info",
}
 
EXTENSIONS_TO_SCAN = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".yaml", ".yml",
    ".toml", ".cfg", ".ini", ".conf", ".sh", ".bash", ".rb", ".go",
    ".java", ".php", ".cs", ".cpp", ".c", ".h", ".tf", ".txt", ".md"
}
 
# ✅ Feature 1: Skip test/mock/fixture files — they flood results with fake secrets
TEST_FILE_PATTERNS = [
    r'(^|/)test[s]?/',          # tests/, test/
    r'(^|/)__tests__/',         # __tests__/
    r'(^|/)spec[s]?/',          # specs/, spec/
    r'(^|/)mock[s]?/',          # mocks/, mock/
    r'(^|/)fixture[s]?/',       # fixtures/
    r'(^|/)stub[s]?/',          # stubs/
    r'(^|/)fake[s]?/',          # fakes/
    r'(^|/)sample[s]?/',        # samples/
    r'(^|/)example[s]?/',       # examples/
    r'test_[^/]+$',             # test_something.py
    r'[^/]+_test\.[^/]+$',      # something_test.go
    r'[^/]+\.test\.[^/]+$',     # something.test.js
    r'[^/]+\.spec\.[^/]+$',     # something.spec.ts
    r'[^/]+\.mock\.[^/]+$',     # something.mock.js
]
 
def is_test_file(path: str) -> bool:
    """Return True if the file is a test/mock/fixture — skip to reduce false positives."""
    path_lower = path.lower()
    return any(re.search(p, path_lower) for p in TEST_FILE_PATTERNS)
 
# ─── Models ──────────────────────────────────────────────────────────────────
 
class ScanRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None
 
class TriageRequest(BaseModel):
    secret_type: str
    severity: str
    file: str
    line: int
    match: str
    context: str
 
# ─── Helpers ─────────────────────────────────────────────────────────────────
 
def parse_repo_url(url: str) -> tuple[str, str]:
    url = url.rstrip("/")
    m = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', url)
    if m:
        return m.group(1), m.group(2).replace(".git", "")
    raise ValueError("Invalid GitHub repository URL")
 
 
def scan_content(content: str, file_path: str) -> list[dict]:
    findings = []
    for line_num, line in enumerate(content.split("\n"), 1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, line):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "secret_type": secret_type,
                    "severity": SEVERITY_MAP.get(secret_type, "info"),
                    "file": file_path,
                    "line": line_num,
                    "match": match.group(0)[:80] + ("..." if len(match.group(0)) > 80 else ""),
                    "context": line.strip()[:120],
                })
    return findings
 
 
async def fetch_tree(owner: str, repo: str, headers: dict, client: httpx.AsyncClient) -> list:
    """
    Fetch full repo file tree.
    ✅ Fix 1: 403 without token = friendly message, not a crash.
              Public repos don't need a token — 403 only happens when
              rate limit is actually hit (60 req/hr for unauthenticated).
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    r = await client.get(url, headers=headers)
 
    if r.status_code == 404:
        raise HTTPException(404, "Repository not found or is private.")
    if r.status_code == 403:
        await asyncio.sleep(5)  # wait and retry
        r = await client.get(url, headers=headers)

    if r.status_code == 403:
        raise HTTPException(
            403,
            "GitHub rate limit exceeded even after retry. Use a valid token."
        )

    r.raise_for_status()
    return [item for item in r.json().get("tree", []) if item["type"] == "blob"]
 
async def fetch_file_raw(owner: str, repo: str, path: str, branch: str, client: httpx.AsyncClient) -> str:
    """
    ✅ Uses raw.githubusercontent.com — no rate limit, no auth needed.
    """
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    try:
        r = await client.get(url, timeout=15)
        return r.text if r.status_code == 200 else ""
    except Exception as e:
        print(f"[WARN] Failed to fetch {path}: {e}")
        return ""
 
 
# ─── Background Scanner ───────────────────────────────────────────────────────
 
async def run_scan(scan_id: str, repo_url: str, token: Optional[str]):
    scan_results[scan_id]["status"] = "running"
 
    # ✅ Fix 2: Cache hit — copy findings into NEW scan_id, don't overwrite with old one
    if repo_url in repo_cache:
        cached = repo_cache[repo_url]
        scan_results[scan_id].update({
            "status": "completed",
            "progress": 100,
            "findings": cached["findings"],
            "completed_at": datetime.utcnow().isoformat(),
            "from_cache": True,   # frontend can show ⚡ Cached badge
            "stats": cached["stats"],
        })
        return
 
    findings = []
    scanned = 0
    skipped = 0
 
    try:
        owner, repo = parse_repo_url(repo_url)
 
        # ✅ Fix 1: Only add Authorization header if token is actually provided
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token or GITHUB_DEFAULT_TOKEN}"}

        async with httpx.AsyncClient(timeout=30) as client:
 
            # Repo info (best-effort, don't fail if this 403s)
            repo_r = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}", headers=headers
            )
            repo_info = repo_r.json() if repo_r.status_code == 200 else {}
            branch = repo_info.get("default_branch", "main")
 
            # File tree (uses GitHub API — needs auth header if token provided)
            all_files = await fetch_tree(owner, repo, headers, client)
 
            scannable = [
                f for f in all_files
                if any(f["path"].endswith(ext) for ext in EXTENSIONS_TO_SCAN)
                and f.get("size", 0) < 500_000
                and not is_test_file(f["path"])   # ✅ skip test/mock/fixture files
            ][:300]  # cap at 300 files
 
            test_files_skipped = sum(1 for f in all_files if is_test_file(f["path"]))
            scan_results[scan_id]["stats"] = {
                "total_files": len(all_files),
                "scannable_files": len(scannable),
                "test_files_skipped": test_files_skipped,
                "repo_info": {
                    "name":           repo_info.get("full_name", f"{owner}/{repo}"),
                    "description":    repo_info.get("description", ""),
                    "stars":          repo_info.get("stargazers_count", 0),
                    "language":       repo_info.get("language", "Unknown"),
                    "default_branch": branch,
                },
            }
 
            # ✅ Batch fetch via raw URL (no rate limit hit)
            batch_size = 10
            for i in range(0, len(scannable), batch_size):
                batch = scannable[i:i + batch_size]
                tasks = [
                    fetch_file_raw(owner, repo, f["path"], branch, client)
                    for f in batch
                ]
                contents = await asyncio.gather(*tasks, return_exceptions=True)
 
                for file_item, content in zip(batch, contents):
                    if isinstance(content, Exception) or not content:
                        skipped += 1
                        continue
                    findings.extend(scan_content(content, file_item["path"]))
                    scanned += 1
 
                scan_results[scan_id]["progress"] = min(
                    int(((i + batch_size) / max(len(scannable), 1)) * 100), 95
                )
                scan_results[scan_id]["findings"] = findings
 
        # Severity + type breakdown
        sev_count  = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_count = {}
        for f in findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
            type_count[f["secret_type"]] = type_count.get(f["secret_type"], 0) + 1
 
        final_stats = {
            **scan_results[scan_id]["stats"],
            "scanned_files":     scanned,
            "skipped_files":     skipped,
            "total_findings":    len(findings),
            "severity_breakdown": sev_count,
            "type_breakdown":    type_count,
        }
 
        scan_results[scan_id].update({
            "status":       "completed",
            "progress":     100,
            "findings":     findings,
            "completed_at": datetime.utcnow().isoformat(),
            "from_cache":   False,
            "stats":        final_stats,
        })
 
        # ✅ Save to cache — only findings + stats, NOT scan_id
        repo_cache[repo_url] = {
            "findings": findings,
            "stats":    final_stats,
        }
 
    except HTTPException as e:
        scan_results[scan_id].update({"status": "error", "error": e.detail, "progress": 0})
    except Exception as e:
        scan_results[scan_id].update({"status": "error", "error": str(e), "progress": 0})
 
 
# ─── Routes ──────────────────────────────────────────────────────────────────
 
@app.get("/")
def root():
    return {"message": "GitHub Secret Scanner API", "docs": "/docs"}
 
 
@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    try:
        parse_repo_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(400, str(e))
 
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "scan_id":      scan_id,
        "status":       "queued",
        "progress":     0,
        "repo_url":     req.repo_url,
        "started_at":   datetime.utcnow().isoformat(),
        "completed_at": None,
        "findings":     [],
        "stats":        {},
        "error":        None,
        "from_cache":   False,
    }
    background_tasks.add_task(run_scan, scan_id, req.repo_url, req.github_token)
    return {"scan_id": scan_id, "status": "queued"}
 
 
@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan not found")
    return scan_results[scan_id]
 
 
@app.get("/api/scan/{scan_id}/download")
def download_findings(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(
        content=scan_results[scan_id],
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"}
    )
 
 
@app.get("/api/scans")
def list_scans():
    return [
        {
            "scan_id":        v["scan_id"],
            "repo_url":       v["repo_url"],
            "status":         v["status"],
            "started_at":     v["started_at"],
            "from_cache":     v.get("from_cache", False),
            "total_findings": v["stats"].get("total_findings", len(v["findings"])),
        }
        for v in scan_results.values()
    ]
 
 
# # ✅ Paste your Gemini API key here
# GEMINI_API_KEY = "paste-your-gemini-key-here"
 
# @app.post("/api/triage")
# async def triage_finding(req: TriageRequest):
#     """
#     Proxy to Gemini API (free) — avoids CORS block from browser.
#     """
#     if not GEMINI_API_KEY or GEMINI_API_KEY == "paste-your-gemini-key-here":
#         raise HTTPException(400, "Gemini API key not configured. Set GEMINI_API_KEY in main.py")
 
#     prompt = f"""You are a security expert reviewing potential hardcoded secrets in source code.
 
# Finding details:
# - Secret Type: {req.secret_type}
# - Severity: {req.severity}
# - File: {req.file}
# - Line: {req.line}
# - Matched value: {req.match}
# - Code context: {req.context}
 
# Is this a REAL secret/credential that poses a security risk, or a FALSE POSITIVE (e.g. placeholder, example value, test data, env variable reference, comment)?
 
# Reply in this exact JSON format only, no markdown, no extra text:
# {{"verdict": "REAL or FALSE_POSITIVE or UNSURE", "confidence": "high or medium or low", "reason": "one sentence explanation"}}"""
 
#     try:
#         async with httpx.AsyncClient(timeout=30) as client:
#             r = await client.post(
#                 f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}",
#                 headers={"Content-Type": "application/json"},
#                 json={
#                     "contents": [{"parts": [{"text": prompt}]}],
#                     "generationConfig": {
#                         "temperature": 0.1,
#                         "maxOutputTokens": 200,
#                     }
#                 }
#             )
 
#             if r.status_code != 200:
#                 raise HTTPException(500, f"Gemini API error: {r.text}")
 
#             data = r.json()
#             raw = data["candidates"][0]["content"]["parts"][0]["text"].strip()
 
#             import json as _json
#             try:
#                 # Strip markdown fences if Gemini adds them
#                 clean = raw.replace("```json", "").replace("```", "").strip()
#                 parsed = _json.loads(clean)
#             except Exception:
#                 parsed = {"verdict": "UNSURE", "confidence": "low", "reason": raw[:120]}
 
#             return parsed
 
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(500, f"Triage failed: {str(e)}")
 
 
@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan not found")
    del scan_results[scan_id]
    return {"message": "Scan deleted"}
 
 
@app.delete("/api/cache")
def clear_cache():
    """Force a fresh scan next time by clearing the repo cache."""
    repo_cache.clear()
    return {"message": f"Cache cleared"}
 
 
# ─── Org / User Scanner ──────────────────────────────────────────────────────
 
# In-memory org scan store
org_scans: dict = {}
 
class OrgScanRequest(BaseModel):
    query: str                      # username, org name, or keyword
    github_token: Optional[str] = None
    max_repos: int = 10             # cap to avoid rate limit
 
 
@app.get("/api/search-repos")
async def search_repos(query: str, token: Optional[str] = None):
    """
    Search GitHub for repositories matching a query (user/org/keyword).
    Returns repo list with metadata — frontend shows this before scanning.
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
 
    async with httpx.AsyncClient(timeout=20) as client:
        # Try as exact user/org first
        user_r = await client.get(
            f"https://api.github.com/users/{query}/repos?per_page=30&sort=updated",
            headers=headers
        )
        if user_r.status_code == 200:
            repos = user_r.json()
            source = "user_org"
        else:
            # Fallback: GitHub search API
            search_r = await client.get(
                f"https://api.github.com/search/repositories?q={query}&sort=updated&per_page=30",
                headers=headers
            )
            if search_r.status_code != 200:
                raise HTTPException(search_r.status_code, "GitHub search failed")
            repos = search_r.json().get("items", [])
            source = "search"
 
    return {
        "query": query,
        "source": source,
        "total": len(repos),
        "repos": [
            {
                "full_name":    r.get("full_name", ""),
                "html_url":     r.get("html_url", ""),
                "description":  r.get("description") or "",
                "language":     r.get("language") or "Unknown",
                "stars":        r.get("stargazers_count", 0),
                "updated_at":   r.get("updated_at", ""),
                "default_branch": r.get("default_branch", "main"),
                "private":      r.get("private", False),
            }
            for r in repos
        ]
    }
 
 
async def scan_single_repo_for_org(repo_url: str, token: Optional[str], org_scan_id: str, repo_index: int):
    """Scan one repo as part of an org scan — updates org_scans entry."""
    findings = []
    try:
        owner, repo = parse_repo_url(repo_url)
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
 
        async with httpx.AsyncClient(timeout=30) as client:
            repo_r = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
            repo_info = repo_r.json() if repo_r.status_code == 200 else {}
            branch = repo_info.get("default_branch", "main")
 
            all_files = await fetch_tree(owner, repo, headers, client)
            scannable = [
                f for f in all_files
                if any(f["path"].endswith(ext) for ext in EXTENSIONS_TO_SCAN)
                and f.get("size", 0) < 500_000
                and not is_test_file(f["path"])
            ][:100]  # 100 files per repo in org scan
 
            batch_size = 8
            for i in range(0, len(scannable), batch_size):
                batch = scannable[i:i + batch_size]
                tasks = [fetch_file_raw(owner, repo, f["path"], branch, client) for f in batch]
                contents = await asyncio.gather(*tasks, return_exceptions=True)
                for file_item, content in zip(batch, contents):
                    if isinstance(content, Exception) or not content:
                        continue
                    findings.extend(scan_content(content, file_item["path"]))
 
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
 
        org_scans[org_scan_id]["repo_results"][repo_index].update({
            "status":           "completed",
            "findings":         findings,
            "total_findings":   len(findings),
            "severity_breakdown": sev,
        })
 
    except Exception as e:
        org_scans[org_scan_id]["repo_results"][repo_index].update({
            "status": "error",
            "error":  str(e),
            "findings": [],
            "total_findings": 0,
        })
 
    # Update overall progress
    done = sum(1 for r in org_scans[org_scan_id]["repo_results"] if r["status"] in ("completed", "error"))
    total = len(org_scans[org_scan_id]["repo_results"])
    org_scans[org_scan_id]["progress"] = int((done / max(total, 1)) * 100)
 
    if done == total:
        all_findings = [f for r in org_scans[org_scan_id]["repo_results"] for f in r.get("findings", [])]
        sev_total = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev_total[f["severity"]] = sev_total.get(f["severity"], 0) + 1
        org_scans[org_scan_id].update({
            "status":            "completed",
            "completed_at":      datetime.utcnow().isoformat(),
            "total_findings":    len(all_findings),
            "severity_breakdown": sev_total,
        })
 
 
async def run_org_scan(org_scan_id: str, repos: list, token: Optional[str]):
    """Run scans for all repos concurrently (max 5 at a time)."""
    org_scans[org_scan_id]["status"] = "running"
    semaphore = asyncio.Semaphore(5)  # max 5 concurrent repo scans
 
    async def bounded_scan(repo_url, idx):
        async with semaphore:
            await scan_single_repo_for_org(repo_url, token, org_scan_id, idx)
 
    tasks = [bounded_scan(r["html_url"], i) for i, r in enumerate(repos)]
    await asyncio.gather(*tasks, return_exceptions=True)
 
 
@app.post("/api/scan-org")
async def start_org_scan(req: OrgScanRequest, background_tasks: BackgroundTasks):
    """Start scanning multiple repos for a user/org/keyword."""
    # First fetch the repo list
    headers = {"Accept": "application/vnd.github.v3+json"}
    if req.github_token:
        headers["Authorization"] = f"token {req.github_token}"
 
    async with httpx.AsyncClient(timeout=20) as client:
        user_r = await client.get(
            f"https://api.github.com/users/{req.query}/repos?per_page=30&sort=updated",
            headers=headers
        )
        if user_r.status_code == 200:
            repos = user_r.json()[:req.max_repos]
        else:
            search_r = await client.get(
                f"https://api.github.com/search/repositories?q={req.query}&sort=updated&per_page=30",
                headers=headers
            )
            if search_r.status_code != 200:
                raise HTTPException(400, "Could not fetch repositories")
            repos = search_r.json().get("items", [])[:req.max_repos]
 
    if not repos:
        raise HTTPException(404, f"No public repositories found for '{req.query}'")
 
    org_scan_id = str(uuid.uuid4())
    repo_results = [
        {
            "repo":           r.get("full_name", ""),
            "html_url":       r.get("html_url", ""),
            "language":       r.get("language") or "Unknown",
            "stars":          r.get("stargazers_count", 0),
            "description":    r.get("description") or "",
            "status":         "queued",
            "findings":       [],
            "total_findings": 0,
            "severity_breakdown": {},
            "error":          None,
        }
        for r in repos
    ]
 
    org_scans[org_scan_id] = {
        "org_scan_id":  org_scan_id,
        "query":        req.query,
        "status":       "queued",
        "progress":     0,
        "started_at":   datetime.utcnow().isoformat(),
        "completed_at": None,
        "total_repos":  len(repos),
        "repo_results": repo_results,
        "total_findings": 0,
        "severity_breakdown": {},
    }
 
    background_tasks.add_task(run_org_scan, org_scan_id, repos, req.github_token)
    return {"org_scan_id": org_scan_id, "total_repos": len(repos)}
 
 
@app.get("/api/scan-org/{org_scan_id}")
def get_org_scan(org_scan_id: str):
    if org_scan_id not in org_scans:
        raise HTTPException(404, "Org scan not found")
    return org_scans[org_scan_id]
 