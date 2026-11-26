from __future__ import annotations

import io
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath

from fastapi import HTTPException, UploadFile

from .config import settings


@dataclass(frozen=True)
class SQLFile:
    path: str
    content: str


def _safe_name(name: str) -> str:
    # ZIP paths use forward slashes even on Windows. We never write uploads to
    # disk, but normalize/reject unsafe paths before exposing names in reports.
    normalized = (name or "").replace("\\", "/")
    if not normalized or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise HTTPException(status_code=400, detail="Uploaded filename is invalid")
    path = PurePosixPath(normalized)
    parts = path.parts
    if (path.is_absolute() or not parts or ".." in parts
            or (parts and ":" in parts[0]) or normalized.startswith("//")):
        raise HTTPException(status_code=400, detail="Uploaded filename contains an unsafe path")
    clean = "/".join(part for part in parts if part not in {"", "."})
    if not clean:
        raise HTTPException(status_code=400, detail="Uploaded filename is invalid")
    return clean


def _decode_sql(name: str, raw: bytes) -> SQLFile:
    name = _safe_name(name)
    if not name.lower().endswith(".sql"):
        raise HTTPException(status_code=400, detail=f"Only .sql files are supported: {name}")
    if len(raw) > settings.max_sql_file_bytes:
        raise HTTPException(status_code=413, detail=f"SQL file exceeds size limit: {name}")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"SQL file must be UTF-8 encoded: {name}") from exc
    return SQLFile(path=name, content=content)


async def read_uploads(files: list[UploadFile]) -> list[SQLFile]:
    results: list[SQLFile] = []
    total_bytes = 0
    total_sql_bytes = 0
    for upload in files:
        name = upload.filename or ""
        raw = await upload.read(settings.max_upload_bytes + 1)
        total_bytes += len(raw)
        if total_bytes > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="Total upload exceeds 10 MB limit")
        if name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    entries = [entry for entry in archive.infolist() if not entry.is_dir()]
                    if len(entries) > settings.max_zip_files:
                        raise HTTPException(status_code=413, detail="ZIP contains too many files")
                    for entry in entries:
                        safe_name = _safe_name(entry.filename)
                        if not safe_name.lower().endswith(".sql"):
                            continue
                        if entry.flag_bits & 0x1:
                            raise HTTPException(status_code=400, detail=f"Encrypted SQL entries are not supported: {safe_name}")
                        if entry.file_size > settings.max_sql_file_bytes:
                            raise HTTPException(status_code=413, detail=f"SQL file exceeds size limit: {safe_name}")
                        total_sql_bytes += entry.file_size
                        if total_sql_bytes > settings.max_total_sql_bytes:
                            raise HTTPException(status_code=413, detail="Total uncompressed SQL content exceeds the configured limit")
                        results.append(_decode_sql(safe_name, archive.read(entry)))
            except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as exc:
                raise HTTPException(status_code=400, detail="Uploaded ZIP file is invalid or cannot be decompressed") from exc
        else:
            total_sql_bytes += len(raw)
            if total_sql_bytes > settings.max_total_sql_bytes:
                raise HTTPException(status_code=413, detail="Total SQL content exceeds the configured limit")
            results.append(_decode_sql(name, raw))
    if not results:
        raise HTTPException(status_code=400, detail="No .sql files found in the upload")
    return results
