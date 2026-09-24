# Mazzi Lab — Solid Render Build

## Deploy

Use Render **Web Service**, not Static Site.

This repository includes a Dockerfile. Render should detect it automatically.

The service installs 7-Zip inside the container and uses it only to extract/read
archives. Uploaded contents are never executed.

## Supported

ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ.

## Upload behavior

The frontend uses XMLHttpRequest so upload progress is visible. It never blindly
calls `response.json()`: empty, HTML, or non-JSON server responses become useful
error messages instead of `Unexpected end of JSON input`.

The backend always returns JSON for application errors and has explicit 413/404/500
handlers.

## Limits

100 MB upload
250 MB expanded archive
25 MB per extracted file
5,000 files per archive
5-minute extraction timeout
10 MB maximum browser preview

No archive contents are executed.

## Important

The static heuristics are indicators, not an antivirus verdict. For serious
malware research, use an isolated disposable environment with restricted
networking and no credentials.
