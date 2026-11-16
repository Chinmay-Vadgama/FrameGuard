# Personal Video Scanner API

A small authenticated FastAPI service for inspecting uploaded video files using FFprobe, FFmpeg, ExifTool and an optional ClamAV integration.

## Important Render Free limitation

Render Free web services have 512 MB RAM, ephemeral local storage, spin down after 15 minutes without inbound traffic, and do not support persistent disks or one-off jobs. ClamAV's official Docker documentation recommends at least 3 GiB RAM and notes that loading signatures alone can use over 1.2 GiB. Therefore this project **ships with ClamAV disabled by default** (`CLAMAV_ENABLED=false`). The API reports that ClamAV was not run; it does not falsely label the file clean.

The ClamAV code path is included for a later machine with sufficient memory. On a suitable Linux host, install/update signatures (`sudo freshclam`) and set `CLAMAV_ENABLED=true`. Allow at least 3–4 GiB RAM, preferably more.

## What it does

- `POST /scan`: accepts one video upload, up to 100 MiB by default.
- Requires `X-API-Key`.
- Computes SHA-256.
- Runs FFprobe, FFmpeg decode validation and ExifTool serially.
- Runs ClamAV only when explicitly enabled and a signature database exists.
- Deletes the temporary upload after the scan, including on errors.
- `GET /health`: reports tool availability.
- `GET /docs`: interactive API documentation.

Supported filename extensions: MP4, M4V, MOV, MKV, AVI, WEBM, MPEG, MPG, 3GP, TS and OGV. An extension is not proof of file type; FFprobe performs a content-level parse.

## Deploy to Render Free

1. Create a GitHub repository and upload the contents of this folder.
2. In Render, choose **New + → Blueprint** and connect the repository.
3. Render detects `render.yaml`. Confirm the service uses the **Free** plan and deploy.
4. In the Render dashboard, open the service's **Environment** page. Copy the generated `API_TOKEN` value and keep it private.
5. Wait for deployment, then visit `https://YOUR-SERVICE.onrender.com/health`.
6. The first request after inactivity may take about a minute while Render wakes the service.

Do not commit `.env` or your API token to GitHub.

## Test the API

Set your service URL and token locally:

```bash
export SCANNER_URL="https://YOUR-SERVICE.onrender.com"
export SCANNER_TOKEN="paste-your-render-API_TOKEN-here"
```

Health check:

```bash
curl "$SCANNER_URL/health"
```

Scan a file:

```bash
curl --fail-with-body \
  -H "X-API-Key: $SCANNER_TOKEN" \
  -F "file=@/path/to/video.mp4" \
  "$SCANNER_URL/scan"
```

Pretty-print the JSON response:

```bash
curl -s \
  -H "X-API-Key: $SCANNER_TOKEN" \
  -F "file=@/path/to/video.mp4" \
  "$SCANNER_URL/scan" | python3 -m json.tool
```

## Run locally with Docker

```bash
cp .env.example .env
# Edit .env and set a long random API_TOKEN.
docker build -t personal-video-scanner .
docker run --rm --env-file .env -p 10000:10000 personal-video-scanner
```

Then:

```bash
curl http://localhost:10000/health
curl -H "X-API-Key: replace-with-a-long-random-secret" \
  -F "file=@video.mp4" \
  http://localhost:10000/scan
```

## Enable ClamAV on a larger machine

The Docker image includes the ClamAV command-line tools, but it does not download signatures during build or startup. On a host with adequate RAM:

```bash
docker run --rm -it \
  --entrypoint sh personal-video-scanner
```

For a normal Linux installation outside the container, install and update ClamAV:

```bash
sudo apt update
sudo apt install clamav clamav-freshclam
sudo freshclam
clamscan --version
clamscan --no-summary video.mp4
```

Then set `CLAMAV_ENABLED=true` for the API. For container use, mount a populated ClamAV database directory at `/var/lib/clamav` and ensure the service user can read it. Do not attempt this on Render Free: it is likely to exceed its memory limit and be killed.

## Interpreting results

- `malware_detected`: ClamAV identified a signature.
- `no_known_threat_detected`: ClamAV returned clean and FFprobe parsed the media. This is not a guarantee of safety.
- `incomplete_clamav_not_run`: media parsing ran, but ClamAV did not complete.
- `invalid_or_unreadable_media`: FFprobe could not parse the file.

FFmpeg's `no_decode_errors` means the selected audio/video streams decoded without reported errors. It does not mean the file is benign. ExifTool is a metadata inspector, not an antivirus engine.

## Security notes and limitations

This is a **preliminary file-inspection API, not a malware sandbox**. FFmpeg, FFprobe, ExifTool and ClamAV all parse attacker-controlled input and may themselves contain vulnerabilities.

- Use a long random API token and never expose it in browser-side JavaScript.
- This API has a single-process concurrency limit of one scan.
- Uploads are held in the container's temporary directory and deleted after processing. Render's filesystem is ephemeral; no file archive is kept.
- Do not use this service to execute files, extract/run embedded attachments, or open files in a desktop session.
- A compromised media parser can potentially access its container's available resources. For higher-risk samples, use a disposable VM with networking disabled, no shared folders and snapshots.
- Render Free is for hobby/testing use, not a production malware-analysis service.
- Keep the service updated and review logs. Do not return or store uploaded content longer than needed.
- The 120-second timeout is configurable. Large, high-resolution, or damaged videos may time out; a timeout means incomplete analysis, not a clean result.
- The 100 MB limit is enforced while copying the upload to a temporary file. The service also relies on the hosting platform's request limits.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `API_TOKEN` | required | API authentication secret |
| `MAX_UPLOAD_MB` | `100` | Maximum upload size in MiB |
| `SCAN_TIMEOUT_SECONDS` | `120` | ClamAV/FFmpeg scan timeout |
| `CLAMAV_ENABLED` | `false` | Enable ClamAV only on a sufficiently provisioned host |
