import asyncio
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse

APP_NAME = "FrameGuard AI Video Scanner"
API_TOKEN = os.getenv("API_TOKEN", "")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() in {"1", "true", "yes"}
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_UPLOAD_UNKNOWN = os.getenv("VIRUSTOTAL_UPLOAD_UNKNOWN", "true").lower() in {"1", "true", "yes"}
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm",
    ".mpeg", ".mpg", ".3gp", ".ts", ".ogv"
}

app = FastAPI(
    title=APP_NAME,
    version="2.0.0",
    description=(
        "Authenticated inspection of AI-generated video files from untrusted sources. "
        "This service inspects files; it does not determine AI provenance or download videos from websites."
    ),
)
scan_semaphore = asyncio.Semaphore(1)


def require_auth(provided: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if not provided or not hmac.compare_digest(provided, API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid API key")


async def run_command(*args: str, timeout: int = SCAN_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run a fixed executable with an argument list; never invoke a shell."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8", "replace")[-12000:],
            "stderr": stderr.decode("utf-8", "replace")[-12000:],
            "timed_out": False,
        }
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return {"returncode": None, "stdout": "", "stderr": "Command timed out", "timed_out": True}
    except FileNotFoundError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": False}


async def vt_request(method: str, url: str, *, files=None, timeout: float = 60.0, authenticated: bool = True):
    headers = {"accept": "application/json"}
    if authenticated:
        headers["x-apikey"] = VIRUSTOTAL_API_KEY
    # Do not forward the VirusTotal API key to the one-time upload host.
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=15.0), follow_redirects=False) as client:
        return await client.request(method, url, headers=headers, files=files)


def vt_summary(attributes: dict[str, Any], sha256: str) -> dict[str, Any]:
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    if malicious:
        status = "malicious"
    elif suspicious:
        status = "suspicious"
    elif stats:
        status = "no_detections"
    else:
        status = "report_available_no_stats"
    return {
        "provider": "virustotal",
        "status": status,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}/detection",
    }


async def scan_virustotal(path: str, filename: str, sha256: str, size_bytes: int) -> dict[str, Any]:
    if not VIRUSTOTAL_ENABLED:
        return {"provider": "virustotal", "status": "not_configured", "reason": "Set VIRUSTOTAL_ENABLED=true and provide VIRUSTOTAL_API_KEY to enable VirusTotal."}
    if not VIRUSTOTAL_API_KEY:
        return {"provider": "virustotal", "status": "configuration_error", "reason": "VirusTotal is enabled but VIRUSTOTAL_API_KEY is missing."}

    try:
        # Reuse an existing public report when available; avoid unnecessary resubmissions.
        lookup = await vt_request("GET", f"{VT_BASE_URL}/files/{sha256}", timeout=25)
        if lookup.status_code == 200:
            payload = lookup.json().get("data", {}).get("attributes", {})
            return vt_summary(payload, sha256)
        if lookup.status_code == 429:
            return {"provider": "virustotal", "status": "rate_limited", "reason": "VirusTotal API quota/rate limit reached. Try again later."}
        if lookup.status_code not in (404,):
            return {"provider": "virustotal", "status": "error", "http_status": lookup.status_code, "reason": "VirusTotal hash lookup failed."}

        if not VIRUSTOTAL_UPLOAD_UNKNOWN:
            return {"provider": "virustotal", "status": "not_found", "reason": "No existing VirusTotal report; automatic upload is disabled."}

        if size_bytes > VT_DIRECT_UPLOAD_LIMIT:
            url_response = await vt_request("GET", f"{VT_BASE_URL}/files/upload_url", timeout=25)
            if url_response.status_code == 429:
                return {"provider": "virustotal", "status": "rate_limited", "reason": "VirusTotal API quota/rate limit reached while requesting a large-file upload URL."}
            url_response.raise_for_status()
            upload_url = url_response.json().get("data")
            if not upload_url:
                return {"provider": "virustotal", "status": "error", "reason": "VirusTotal did not return a large-file upload URL."}
        else:
            upload_url = f"{VT_BASE_URL}/files"

        with open(path, "rb") as video_file:
            upload_response = await vt_request(
                "POST",
                upload_url,
                files={"file": (filename, video_file, "application/octet-stream")},
                timeout=SCAN_TIMEOUT_SECONDS,
                authenticated=(upload_url == f"{VT_BASE_URL}/files"),
            )
        if upload_response.status_code == 429:
            return {"provider": "virustotal", "status": "rate_limited", "reason": "VirusTotal API quota/rate limit reached during upload."}
        upload_response.raise_for_status()
        analysis_id = upload_response.json().get("data", {}).get("id")
        if not analysis_id:
            return {"provider": "virustotal", "status": "error", "reason": "VirusTotal upload response did not include an analysis ID."}
        return {
            "provider": "virustotal",
            "status": "submitted",
            "analysis_id": analysis_id,
            "analysis_endpoint": f"/virustotal/analyses/{quote(analysis_id, safe='')}",
            "message": "File submitted to VirusTotal. Retrieve the analysis endpoint for the verdict when processing completes.",
            "privacy_notice": "Standard VirusTotal submissions are added to its dataset and may be shared with the security community and partners.",
        }
    except httpx.HTTPStatusError as exc:
        return {"provider": "virustotal", "status": "error", "http_status": exc.response.status_code, "reason": "VirusTotal returned an unsuccessful response."}
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return {"provider": "virustotal", "status": "error", "reason": f"VirusTotal request failed: {type(exc).__name__}."}


async def get_virustotal_analysis(analysis_id: str) -> dict[str, Any]:
    if not VIRUSTOTAL_ENABLED or not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=503, detail="VirusTotal is not configured")
    try:
        response = await vt_request("GET", f"{VT_BASE_URL}/analyses/{quote(analysis_id, safe='')}", timeout=25)
        if response.status_code == 429:
            raise HTTPException(status_code=429, detail="VirusTotal API rate limit reached; retry later")
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="VirusTotal analysis ID was not found")
        response.raise_for_status()
        data = response.json().get("data", {})
        attrs = data.get("attributes", {})
        status = attrs.get("status", "queued")
        result = {"provider": "virustotal", "analysis_id": analysis_id, "analysis_status": status}
        if status == "completed":
            stats = attrs.get("stats", {})
            result["status"] = "malicious" if (stats.get("malicious", 0) or 0) else ("suspicious" if (stats.get("suspicious", 0) or 0) else "no_detections")
            result["stats"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        else:
            result["status"] = "pending"
        return result
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"VirusTotal returned HTTP {exc.response.status_code}")
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Could not contact VirusTotal")


async def scan_ffprobe(path: str) -> dict[str, Any]:
    result = await run_command(
        "ffprobe", "-v", "error", "-probesize", "10M", "-analyzeduration", "10M",
        "-show_format", "-show_streams", "-of", "json", path, timeout=30,
    )
    if result["timed_out"]:
        return {"status": "error", "reason": "FFprobe timed out."}
    if result["returncode"] != 0:
        return {"status": "invalid_or_unreadable", "details": result["stderr"][-3000:]}
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"status": "error", "reason": "FFprobe returned invalid JSON."}
    streams = [{
        "index": s.get("index"), "codec_type": s.get("codec_type"), "codec_name": s.get("codec_name"),
        "width": s.get("width"), "height": s.get("height"), "sample_rate": s.get("sample_rate"),
        "channels": s.get("channels"), "duration": s.get("duration"),
    } for s in data.get("streams", [])]
    fmt = data.get("format", {})
    return {"status": "valid", "format_name": fmt.get("format_name"), "duration_seconds": fmt.get("duration"),
            "size_bytes": fmt.get("size"), "bit_rate": fmt.get("bit_rate"), "streams": streams}


async def scan_ffmpeg(path: str, has_av_streams: bool) -> dict[str, Any]:
    if not has_av_streams:
        return {"status": "not_run", "reason": "No audio or video streams were found."}
    result = await run_command(
        "ffmpeg", "-nostdin", "-hide_banner", "-v", "error", "-threads", "1", "-i", path,
        "-map", "0:v?", "-map", "0:a?", "-f", "null", "-", timeout=SCAN_TIMEOUT_SECONDS,
    )
    if result["timed_out"]:
        return {"status": "timeout", "details": "FFmpeg decoding exceeded the time limit."}
    if result["returncode"] == 0:
        return {"status": "no_decode_errors"}
    return {"status": "decode_errors", "details": result["stderr"][-4000:] or "FFmpeg exited with an error."}


async def scan_exiftool(path: str) -> dict[str, Any]:
    fields = ["-FileType", "-MIMEType", "-FileSize", "-Duration", "-CreateDate", "-ModifyDate", "-Software",
              "-ImageWidth", "-ImageHeight", "-VideoFrameRate", "-VideoCodecID", "-AudioCodecID", "-CompressorID"]
    result = await run_command("exiftool", "-json", "-n", *fields, path, timeout=20)
    if result["timed_out"]:
        return {"status": "error", "reason": "ExifTool timed out."}
    if result["returncode"] != 0:
        return {"status": "error", "details": result["stderr"][-2000:]}
    try:
        items = json.loads(result["stdout"])
        metadata = items[0] if items else {}
        metadata.pop("SourceFile", None)
        return {"status": "completed", "metadata": metadata}
    except (json.JSONDecodeError, IndexError, TypeError):
        return {"status": "error", "reason": "Could not parse ExifTool output."}


def determine_overall(report: dict[str, Any]) -> str:
    vt = report["virustotal"].get("status")
    if vt == "malicious":
        return "malware_detected"
    if vt == "suspicious":
        return "suspicious_detections"
    if report["ffprobe"].get("status") != "valid":
        return "invalid_or_unreadable_media"
    if vt == "no_detections":
        return "no_known_threat_detected"
    if vt == "submitted":
        return "malware_analysis_pending"
    return "incomplete_malware_scan"


@app.get("/")
async def root():
    return {"name": APP_NAME, "version": app.version,
            "purpose": "Security inspection of AI-generated video files obtained from untrusted websites.",
            "message": "Upload an authorized video file to /scan with the X-API-Key header. This API does not download videos from URLs.",
            "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "ok", "purpose": "AI-generated video file security inspection",
            "tools": {"ffprobe": bool(shutil.which("ffprobe")), "ffmpeg": bool(shutil.which("ffmpeg")),
                      "exiftool": bool(shutil.which("exiftool")), "virustotal_enabled": VIRUSTOTAL_ENABLED,
                      "virustotal_api_key_configured": bool(VIRUSTOTAL_API_KEY)}}


@app.get("/virustotal/analyses/{analysis_id}")
async def virustotal_analysis(analysis_id: str, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_auth(x_api_key)
    return await get_virustotal_analysis(analysis_id)


@app.post("/scan")
async def scan_video(file: UploadFile = File(...),
                     x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_auth(x_api_key)
    original_name = Path(file.filename or "upload.bin").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported extension. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    async with scan_semaphore:
        temp_path = None
        digest = hashlib.sha256()
        total = 0
        started = time.time()
        try:
            with tempfile.NamedTemporaryFile(prefix="frameguard-video-", suffix=suffix, delete=False) as tmp:
                temp_path = tmp.name
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail=f"Maximum upload size is {MAX_UPLOAD_MB} MiB")
                    digest.update(chunk)
                    tmp.write(chunk)
            if total == 0:
                raise HTTPException(status_code=400, detail="The uploaded file is empty.")

            sha256 = digest.hexdigest()
            ffprobe_result = await scan_ffprobe(temp_path)
            streams = ffprobe_result.get("streams", []) if ffprobe_result.get("status") == "valid" else []
            has_av = any(s.get("codec_type") in {"video", "audio"} for s in streams)

            # Sequential execution limits CPU and memory pressure on Render Free.
            vt_result = await scan_virustotal(temp_path, original_name, sha256, total)
            ffmpeg_result = await scan_ffmpeg(temp_path, has_av)
            exiftool_result = await scan_exiftool(temp_path)

            report = {"purpose": "AI-generated video file security inspection",
                      "filename": original_name, "size_bytes": total, "sha256": sha256,
                      "virustotal": vt_result, "ffprobe": ffprobe_result,
                      "ffmpeg": ffmpeg_result, "exiftool": exiftool_result}
            report["overall"] = determine_overall(report)
            report["duration_seconds"] = round(time.time() - started, 2)
            return JSONResponse(report, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        finally:
            await file.close()
            if temp_path:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass
