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

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse

APP_NAME = "Personal Video Scanner"
API_TOKEN = os.getenv("API_TOKEN", "")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
CLAMAV_ENABLED = os.getenv("CLAMAV_ENABLED", "false").lower() in {"1", "true", "yes"}
ALLOWED_EXTENSIONS = {
    ".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm",
    ".mpeg", ".mpg", ".3gp", ".ts", ".ogv"
}
CLAMAV_DB_DIRS = [Path("/var/lib/clamav"), Path("/usr/local/share/clamav")]

app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    description="Authenticated, temporary-file video inspection API."
)
scan_semaphore = asyncio.Semaphore(1)


def require_auth(provided: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if not provided or not hmac.compare_digest(provided, API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid API key")


async def run_command(*args: str, timeout: int = SCAN_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run a fixed executable with an argument list; never invoke a shell."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        # Bound the amount of diagnostic text returned to the API caller.
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8", "replace")[-12000:],
            "stderr": stderr.decode("utf-8", "replace")[-12000:],
            "timed_out": False,
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return {"returncode": None, "stdout": "", "stderr": "Command timed out", "timed_out": True}
    except FileNotFoundError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": False}


def clamav_database_present() -> bool:
    for directory in CLAMAV_DB_DIRS:
        if directory.exists() and any(
            any(directory.glob(pattern)) for pattern in ("*.cvd", "*.cld")
        ):
            return True
    return False


async def scan_clamav(path: str) -> dict[str, Any]:
    if not CLAMAV_ENABLED:
        return {
            "status": "not_run",
            "reason": "ClamAV is disabled by configuration (recommended on Render Free)."
        }
    if not shutil.which("clamscan"):
        return {"status": "unavailable", "reason": "clamscan executable is not installed."}
    if not clamav_database_present():
        return {"status": "unavailable", "reason": "No ClamAV signature database is installed."}

    result = await run_command("clamscan", "--no-summary", path, timeout=SCAN_TIMEOUT_SECONDS)
    output = (result["stdout"] + "\n" + result["stderr"]).strip()
    if result["timed_out"]:
        return {"status": "error", "reason": "ClamAV scan timed out."}
    if result["returncode"] == 0:
        return {"status": "clean", "details": output[-2000:]}
    if result["returncode"] == 1:
        return {"status": "infected", "details": output[-2000:]}
    return {"status": "error", "details": output[-2000:] or "ClamAV returned an error."}


async def scan_ffprobe(path: str) -> dict[str, Any]:
    result = await run_command(
        "ffprobe", "-v", "error",
        "-probesize", "10M", "-analyzeduration", "10M",
        "-show_format", "-show_streams", "-of", "json", path,
        timeout=30,
    )
    if result["timed_out"]:
        return {"status": "error", "reason": "FFprobe timed out."}
    if result["returncode"] != 0:
        return {"status": "invalid_or_unreadable", "details": result["stderr"][-3000:]}
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"status": "error", "reason": "FFprobe returned invalid JSON."}

    streams = []
    for stream in data.get("streams", []):
        streams.append({
            "index": stream.get("index"),
            "codec_type": stream.get("codec_type"),
            "codec_name": stream.get("codec_name"),
            "width": stream.get("width"),
            "height": stream.get("height"),
            "sample_rate": stream.get("sample_rate"),
            "channels": stream.get("channels"),
            "duration": stream.get("duration"),
        })
    fmt = data.get("format", {})
    return {
        "status": "valid",
        "format_name": fmt.get("format_name"),
        "duration_seconds": fmt.get("duration"),
        "size_bytes": fmt.get("size"),
        "bit_rate": fmt.get("bit_rate"),
        "streams": streams,
    }


async def scan_ffmpeg(path: str, has_av_streams: bool) -> dict[str, Any]:
    if not has_av_streams:
        return {"status": "not_run", "reason": "No audio or video streams were found."}
    result = await run_command(
        "ffmpeg", "-nostdin", "-hide_banner", "-v", "error",
        "-threads", "1", "-i", path,
        "-map", "0:v?", "-map", "0:a?",
        "-f", "null", "-",
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    if result["timed_out"]:
        return {"status": "timeout", "details": "FFmpeg decoding exceeded the time limit."}
    if result["returncode"] == 0:
        return {"status": "no_decode_errors"}
    return {
        "status": "decode_errors",
        "details": result["stderr"][-4000:] or "FFmpeg exited with an error."
    }


async def scan_exiftool(path: str) -> dict[str, Any]:
    fields = [
        "-FileType", "-MIMEType", "-FileSize", "-Duration",
        "-CreateDate", "-ModifyDate", "-Software",
        "-ImageWidth", "-ImageHeight", "-VideoFrameRate",
        "-VideoCodecID", "-AudioCodecID", "-CompressorID"
    ]
    result = await run_command(
        "exiftool", "-json", "-n", *fields, path, timeout=20
    )
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
    clam = report["clamav"]["status"]
    probe = report["ffprobe"]["status"]
    if clam == "infected":
        return "malware_detected"
    if probe != "valid":
        return "invalid_or_unreadable_media"
    if clam == "clean":
        return "no_known_threat_detected"
    return "incomplete_clamav_not_run"


@app.get("/")
async def root():
    return {
        "name": APP_NAME,
        "version": app.version,
        "message": "POST a video to /scan with the X-API-Key header.",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "tools": {
            "ffprobe": bool(shutil.which("ffprobe")),
            "ffmpeg": bool(shutil.which("ffmpeg")),
            "exiftool": bool(shutil.which("exiftool")),
            "clamscan": bool(shutil.which("clamscan")),
            "clamav_enabled": CLAMAV_ENABLED,
        },
    }


@app.post("/scan")
async def scan_video(
    file: UploadFile = File(...),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    require_auth(x_api_key)

    original_name = Path(file.filename or "upload.bin").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported extension. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    content_length = None
    # Content-Length includes multipart framing, so this is only an early rejection.
    # The streamed byte counter below is authoritative.
    async with scan_semaphore:
        temp_path = None
        digest = hashlib.sha256()
        total = 0
        started = time.time()
        try:
            with tempfile.NamedTemporaryFile(prefix="video-scan-", suffix=suffix, delete=False) as tmp:
                temp_path = tmp.name
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail=f"Maximum upload size is {MAX_UPLOAD_MB} MB")
                    digest.update(chunk)
                    tmp.write(chunk)

            if total == 0:
                raise HTTPException(status_code=400, detail="The uploaded file is empty.")

            ffprobe_result = await scan_ffprobe(temp_path)
            streams = ffprobe_result.get("streams", []) if ffprobe_result.get("status") == "valid" else []
            has_av = any(s.get("codec_type") in {"video", "audio"} for s in streams)

            # The four tools are run serially to keep peak memory and CPU usage down.
            clamav_result = await scan_clamav(temp_path)
            ffmpeg_result = await scan_ffmpeg(temp_path, has_av)
            exiftool_result = await scan_exiftool(temp_path)

            report = {
                "filename": original_name,
                "size_bytes": total,
                "sha256": digest.hexdigest(),
                "clamav": clamav_result,
                "ffprobe": ffprobe_result,
                "ffmpeg": ffmpeg_result,
                "exiftool": exiftool_result,
            }
            report["overall"] = determine_overall(report)
            report["duration_seconds"] = round(time.time() - started, 2)
            return JSONResponse(
                report,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
            )
        finally:
            await file.close()
            if temp_path:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass
