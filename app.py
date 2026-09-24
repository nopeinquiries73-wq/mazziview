import base64
import hashlib
import math
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

BASE = Path(__file__).resolve().parent
RUNTIME = BASE / "runtime"
RUNTIME.mkdir(exist_ok=True)

MAX_FILES = 5000
MAX_EXPANDED = 250 * 1024 * 1024
MAX_ENTRY = 25 * 1024 * 1024
ALLOWED = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}

PATTERNS = [
    ("PowerShell", r"\bpowershell(?:\.exe)?\b"),
    ("CMD", r"\bcmd(?:\.exe)?\b"),
    ("WScript", r"\bwscript(?:\.exe)?\b"),
    ("CScript", r"\bcscript(?:\.exe)?\b"),
    ("Rundll32", r"\brundll32(?:\.exe)?\b"),
    ("Regsvr32", r"\bregsvr32(?:\.exe)?\b"),
    ("Scheduled task", r"\bschtasks(?:\.exe)?\b"),
    ("Run key", r"currentversion[\\/]+run"),
    ("DownloadString", r"\bdownloadstring\b"),
    ("Base64 decode", r"frombase64string"),
    ("CreateRemoteThread", r"CreateRemoteThread"),
    ("VirtualAlloc", r"VirtualAlloc"),
    ("WriteProcessMemory", r"WriteProcessMemory"),
]

TEXT_EXTS = {
    ".txt", ".log", ".json", ".xml", ".html", ".htm", ".css", ".js", ".ts",
    ".jsx", ".tsx", ".py", ".ps1", ".bat", ".cmd", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".cs", ".java", ".php", ".rb", ".go", ".rs", ".sql",
    ".yaml", ".yml", ".ini", ".cfg", ".md"
}

sessions = {}


def json_error(message, status=400):
    return jsonify({"ok": False, "error": str(message)}), status


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts if count
    )


def safe_relative(path):
    """Return a safe relative path or None."""
    normalized = str(path).replace("\\", "/")
    p = Path(normalized)

    if p.is_absolute() or any(part == ".." for part in p.parts):
        return None

    clean = "/".join(part for part in p.parts if part not in ("", "."))
    return clean or None


def scan_data(data):
    sample = data[:2_000_000].decode("utf-8", "ignore")
    return [
        label for label, pattern in PATTERNS
        if re.search(pattern, sample, re.IGNORECASE)
    ]


def find_7zip():
    for command in ("7zz", "7z"):
        found = shutil.which(command)
        if found:
            return found
    return None


def extract_archive(archive_path, destination):
    tool = find_7zip()
    if not tool:
        raise RuntimeError(
            "Archive engine is unavailable on this server. "
            "The Render service must be deployed from the included Dockerfile."
        )

    command = [
        tool,
        "x",
        "-y",
        "-bd",
        f"-o{destination}",
        str(archive_path),
    ]

    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Archive extraction timed out after 5 minutes.")

    if result.returncode != 0:
        error = result.stderr.decode("utf-8", "replace").strip()
        if len(error) > 1200:
            error = error[-1200:]
        raise RuntimeError(error or "The archive could not be extracted.")


def build_index(root):
    result = []
    total_size = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        try:
            relative = path.relative_to(root).as_posix()
            safe_name = safe_relative(relative)
            if not safe_name:
                continue

            size = path.stat().st_size

            if size > MAX_ENTRY:
                continue

            total_size += size
            if total_size > MAX_EXPANDED:
                raise RuntimeError(
                    "Expanded archive is larger than the 250 MB safety limit."
                )

            data = path.read_bytes()

            result.append({
                "id": len(result),
                "name": safe_name,
                "size": size,
                "sha256": sha256(data),
                "entropy": round(entropy(data), 3),
                "hits": scan_data(data),
                "text": Path(safe_name).suffix.lower() in TEXT_EXTS,
            })

            if len(result) >= MAX_FILES:
                raise RuntimeError(
                    "Archive contains more than the 5,000 file safety limit."
                )

        except (OSError, ValueError):
            continue

    return result


@app.errorhandler(413)
def too_large(_error):
    return json_error(
        "Archive is too large. The maximum upload size is 100 MB.",
        413,
    )


@app.errorhandler(404)
def not_found(_error):
    return json_error("Endpoint not found.", 404)


@app.errorhandler(500)
def internal_error(error):
    app.logger.exception("Mazzi Lab internal error: %s", error)
    return json_error("Server error. Check the Render service logs.", 500)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy"})


@app.post("/api/upload")
def upload():
    file = request.files.get("file")

    if file is None or not file.filename:
        return json_error("No archive was selected.")

    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED:
        return json_error(
            "Unsupported archive. Use ZIP, RAR, 7Z, TAR, GZ, BZ2 or XZ.",
            415,
        )

    session_id = uuid.uuid4().hex
    work = RUNTIME / session_id
    source = work / ("sample" + extension)
    extracted = work / "extracted"

    try:
        work.mkdir(parents=True, exist_ok=False)
        extracted.mkdir()

        file.save(source)

        if not source.exists() or source.stat().st_size == 0:
            raise RuntimeError("The uploaded archive was empty.")

        extract_archive(source, extracted)

        indexed = build_index(extracted)

        if not indexed:
            raise RuntimeError(
                "The archive was opened, but no readable files were found."
            )

        sessions[session_id] = {
            "root": extracted,
            "files": indexed,
            "archive_name": file.filename,
        }

        source.unlink(missing_ok=True)

        return jsonify({
            "ok": True,
            "session": session_id,
            "name": file.filename,
            "files": indexed,
        })

    except Exception as exc:
        shutil.rmtree(work, ignore_errors=True)
        app.logger.exception("Archive upload failed")
        return json_error(str(exc), 400)


@app.get("/api/file/<session_id>/<int:file_id>")
def get_file(session_id, file_id):
    session = sessions.get(session_id)

    if not session:
        return json_error("Analysis session expired.", 404)

    files = session["files"]

    if file_id < 0 or file_id >= len(files):
        return json_error("File not found.", 404)

    metadata = files[file_id]
    root = session["root"]
    path = root / metadata["name"]

    try:
        resolved = path.resolve()
        if root.resolve() not in resolved.parents:
            return json_error("Unsafe file path.", 400)

        if not resolved.is_file():
            return json_error("File not found.", 404)

        data = resolved.read_bytes()
    except OSError:
        return json_error("Could not read the selected file.", 500)

    # Limit what is sent to the browser.
    browser_data = data[:10 * 1024 * 1024]

    return jsonify({
        "ok": True,
        "name": metadata["name"],
        "size": len(data),
        "sha256": metadata["sha256"],
        "entropy": metadata["entropy"],
        "hits": metadata["hits"],
        "truncated": len(data) > len(browser_data),
        "data": base64.b64encode(browser_data).decode("ascii"),
    })


@app.post("/api/cleanup/<session_id>")
def cleanup(session_id):
    sessions.pop(session_id, None)
    shutil.rmtree(RUNTIME / session_id, ignore_errors=True)
    return jsonify({"ok": True})


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
