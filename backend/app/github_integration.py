"""Secure GitHub pull-request SQL change analysis helpers.

No SQL is executed. Network access is opt-in and credentials are read only
from environment variables. Tests use the pure functions and mocked transport.
"""
from __future__ import annotations
import hashlib, hmac, os, re, time
from collections import deque
from typing import Any

_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_BRANCH = re.compile(r"^[A-Za-z0-9_./-]{1,240}$")
_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_./ -]{1,500}\.sql$", re.I)
_seen_deliveries: dict[str, float] = {}

def validate_repo(repo: str) -> str:
    if not isinstance(repo, str) or not _REPO.fullmatch(repo) or '..' in repo:
        raise ValueError('repository must use owner/repository format')
    return repo

def validate_branch(branch: str) -> str:
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch) or '..' in branch or branch.startswith('/'):
        raise ValueError('invalid branch name')
    return branch

def validate_pr_number(number: Any) -> int:
    if isinstance(number, bool) or not isinstance(number, int) or number < 1 or number > 2_147_483_647:
        raise ValueError('pull_request_number must be a positive integer')
    return number

def validate_sql_path(path: str) -> str:
    if not isinstance(path, str) or not _PATH.fullmatch(path) or '\\' in path:
        raise ValueError('only safe relative .sql paths are accepted')
    return path

def classify_file_changes(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(files, list) or len(files) > 500:
        raise ValueError('files must be a list containing at most 500 entries')
    result=[]
    for item in files:
        if not isinstance(item, dict): raise ValueError('each file must be an object')
        status=item.get('status'); filename=validate_sql_path(item.get('filename'))
        if status not in {'added','modified','removed','renamed'}: raise ValueError('unsupported file status')
        previous=item.get('previous_filename')
        if status=='renamed': validate_sql_path(previous)
        patch=item.get('patch','')
        if patch is not None and (not isinstance(patch,str) or len(patch)>200_000): raise ValueError('invalid patch')
        result.append({'filename':filename,'status':status,'previous_filename':previous if status=='renamed' else None,
                       'additions':max(0,int(item.get('additions',0) or 0)),'deletions':max(0,int(item.get('deletions',0) or 0)),
                       'patch_available':bool(patch)})
    return result

def compare_sql_file(old_sql: str | None, new_sql: str | None, filename: str) -> dict[str, Any]:
    validate_sql_path(filename)
    if old_sql is not None and (not isinstance(old_sql,str) or len(old_sql)>2*1024*1024): raise ValueError('base SQL content exceeds limit')
    if new_sql is not None and (not isinstance(new_sql,str) or len(new_sql)>2*1024*1024): raise ValueError('head SQL content exceeds limit')
    status='added' if old_sql is None else 'deleted' if new_sql is None else 'modified'
    old_tables=set(re.findall(r"(?i)\b(?:from|join|update|into|table|view)\s+([\w.\"`]+)",old_sql or ''))
    new_tables=set(re.findall(r"(?i)\b(?:from|join|update|into|table|view)\s+([\w.\"`]+)",new_sql or ''))
    # This is lexical evidence only; parser-backed lineage below supplies verified findings.
    return {'filename':filename,'status':status,'added_table_references':sorted(new_tables-old_tables),
            'removed_table_references':sorted(old_tables-new_tables),'text_changed':(old_sql or '')!=(new_sql or ''),
            'old_content':old_sql,'new_content':new_sql}

def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    if not isinstance(body,bytes) or not isinstance(signature,str) or not secret: return False
    expected='sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,signature)

def accept_webhook_delivery(delivery_id: str, timestamp: str, now: float | None=None) -> bool:
    if not isinstance(delivery_id,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,100}',delivery_id): return False
    try: stamp=int(timestamp)
    except (TypeError,ValueError): return False
    current=time.time() if now is None else now
    if abs(current-stamp)>300: return False
    # Bounded in-memory replay guard; use shared persistent storage in multi-worker production.
    for key, seen in list(_seen_deliveries.items()):
        if current-seen>600: _seen_deliveries.pop(key,None)
    if delivery_id in _seen_deliveries: return False
    if len(_seen_deliveries)>=10000: _seen_deliveries.pop(next(iter(_seen_deliveries)))
    _seen_deliveries[delivery_id]=current
    return True

def verify_ci_bearer(header: str | None) -> bool:
    expected=os.getenv('DATALINEAGE_GITHUB_CI_TOKEN','').strip()
    if not expected or not isinstance(header,str) or not header.startswith('Bearer '): return False
    supplied=header[7:].strip()
    return bool(supplied) and hmac.compare_digest(supplied,expected)

def github_configuration(token_override: str | None = None) -> dict[str, Any]:
    token=(token_override if token_override is not None else os.getenv('DATALINEAGE_GITHUB_TOKEN','')).strip()
    base=os.getenv('DATALINEAGE_GITHUB_API_URL','https://api.github.com').strip().rstrip('/')
    from urllib.parse import urlparse
    parsed = urlparse(base)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.port not in (None, 443):
        raise ValueError('GitHub API URL must use the official https://api.github.com host')
    return {'configured':bool(token),'api_url':base,'token':token}

async def github_get(path: str) -> dict[str, Any]:
    """Fetch only fixed GitHub API paths; arbitrary URLs are never accepted."""
    import httpx
    cfg=github_configuration()
    if not cfg['configured']: raise RuntimeError('GitHub credentials are not configured')
    if not path.startswith('/repos/') or path.startswith('//') or '..' in path or '?' in path:
        raise ValueError('unsupported GitHub API path')
    url=cfg['api_url']+path
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0,connect=5.0),follow_redirects=False) as client:
        response=await client.get(url,headers={'Authorization':'Bearer '+cfg['token'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        response.raise_for_status()
        data=response.json()
        if not isinstance(data,dict): raise RuntimeError('Unexpected GitHub API response')
        return data

def build_pr_impact(files: list[dict[str,Any]], analyses: list[dict[str,Any]]) -> dict[str,Any]:
    changed=classify_file_changes(files)
    unresolved=[]; findings=[]; deps=set(); direct=set(); transitive=set()
    for analysis in analyses:
        if not isinstance(analysis,dict): continue
        for name in analysis.get('unresolved_references',[]) or []: unresolved.append(str(name))
        graph=analysis.get('graph') or {}
        for edge in graph.get('edges',[]) if isinstance(graph,dict) else []:
            if isinstance(edge,dict):
                src=edge.get('source'); dst=edge.get('target')
                if src and dst: deps.add((str(src),str(dst)))
        for item in analysis.get('column_lineage',[]) or []:
            if isinstance(item,dict):
                direct.add(str(item.get('target_table') or item.get('target') or 'unknown'))
                findings.append({'type':'column_lineage','confidence':item.get('confidence','probable'),
                                 'severity':'review','source_table':item.get('source_table'),
                                 'source_column':item.get('source_column'),'target_table':item.get('target_table'),
                                 'target_column':item.get('target_column'),'evidence':item.get('expression_sql') or item.get('reason')})
    status='neutral' if unresolved else 'success'
    return {'status':status,'changed_sql_files':len(changed),'changed_files':changed,'dependency_count':len(deps),
            'directly_affected_objects':len(direct),'direct_objects':sorted(direct),'transitive_affected_objects':len(transitive),
            'transitive_objects':[],'potential_breaking_changes':0,'unresolved_lineage_warnings':sorted(set(unresolved)),
            'findings':findings,'limitations':['A missing finding does not prove the pull request is safe.','Textual reference differences are hints; parser-backed lineage is required for confirmation.','Transitive impacts are reported only when supported by the supplied lineage graph.'],
            'enforcement_enabled':os.getenv('DATALINEAGE_GITHUB_ENFORCE','false').lower() in {'1','true','yes','on'}}


# Milestone 18: bounded, official GitHub REST API operations.
async def github_api_request(method: str, path: str, payload: dict[str, Any] | None = None, token_override: str | None = None) -> Any:
    """Call a fixed-path GitHub REST endpoint; never follow redirects or arbitrary URLs."""
    import httpx
    cfg = github_configuration(token_override)
    if not cfg["configured"]:
        raise RuntimeError("GitHub credentials are not configured")
    if (method not in {"GET", "POST", "PATCH"} or not path.startswith("/repos/")
            or path.startswith("//") or ".." in path or "://" in path
            or len(path) > 1000):
        raise ValueError("unsupported GitHub API request")
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False
    ) as client:
        response = await client.request(
            method, cfg["api_url"] + path,
            headers={"Authorization": "Bearer " + cfg["token"],
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
            json=payload,
        )
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()


async def github_api_pages(path: str, max_pages: int = 10, token_override: str | None = None) -> list[dict[str, Any]]:
    """Fetch bounded paginated list endpoints without accepting caller URLs."""
    import httpx
    cfg = github_configuration(token_override)
    if not cfg["configured"]:
        raise RuntimeError("GitHub credentials are not configured")
    if not (path.startswith("/repos/") or path.startswith("/user/repos")) or ".." in path or "://" in path or path.startswith("//"):
        raise ValueError("unsupported GitHub API path")
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0),
                                 follow_redirects=False) as client:
        for page in range(1, max_pages + 1):
            response = await client.get(cfg["api_url"] + path,
                params={"per_page": 100, "page": page},
                headers={"Authorization": "Bearer " + cfg["token"],
                         "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28"})
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list):
                raise RuntimeError("Unexpected GitHub list response")
            results.extend(x for x in batch if isinstance(x, dict))
            if len(batch) < 100:
                break
        return results


def decode_github_content(data: dict[str, Any]) -> str:
    """Decode GitHub Contents API base64 text with strict size and encoding checks."""
    import base64
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        raise ValueError("GitHub file content is unavailable or uses an unsupported encoding")
    raw = data.get("content")
    if not isinstance(raw, str) or len(raw) > 3 * 1024 * 1024:
        raise ValueError("GitHub file content exceeds the supported size")
    try:
        decoded = base64.b64decode(raw, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("GitHub file content is not valid UTF-8") from exc
    if len(decoded.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("GitHub SQL file exceeds the 2 MiB limit")
    return decoded
