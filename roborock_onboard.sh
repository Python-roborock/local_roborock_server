#!/usr/bin/env bash

# Strict error handling: fail on unhandled errors, missing variables and failed
# pipeline members. Expected failures are checked explicitly below.
set -euo pipefail
# Restrict new config, state, logs and inherited mitmproxy captures to this user.
umask 077

# Keep paths anchored to this file, including when its directory contains spaces.
# Run from a local trusted checkout; configuration and capture data stay beside it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CONFIG_FILE="$SCRIPT_DIR/.roborock_onboard.conf"
PID_FILE="$SCRIPT_DIR/.roborock_mitm.pid"
LOG_FILE="$SCRIPT_DIR/roborock_mitm.log"
MITM_SCRIPT="$SCRIPT_DIR/mitm_redirect.py"
SESSION_ROOT="$SCRIPT_DIR/.roborock_sessions"
WIZARD_LOCK_DIR="$SCRIPT_DIR/.roborock_onboard.lock"
WIZARD_LOCK_HELD=0
CERT_LOG_FILE="$SCRIPT_DIR/.roborock_certificate.log"
# Python is resolved lazily by ensure_python, before any managed server starts.
PYTHON_BIN=''
SESSION_DIR=''
NEW_SESSION_DIR=''
CERT_SESSION_DIR=''
STARTUP_TIMEOUT=90
PHONE_PREPARED=0

MITM_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"

# These flags distinguish a session this run owns from one it only discovered.
# The normal-completion flag suppresses the aborted-onboarding reminder on exit.
MITM_ACTIVE=0
NORMAL_CLEANUP=0


# Styling is enabled only for an interactive, color-capable terminal.
UI_COLOR=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    UI_COLOR=1
fi
if (( UI_COLOR )); then
    C_RESET=$'\033[0m'
    C_CYAN=$'\033[1;36m'
    C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'
    C_DIM=$'\033[2m'
else
    C_RESET='' C_CYAN='' C_GREEN='' C_YELLOW='' C_RED='' C_DIM=''
fi

# Numbered steps show progress in the box and the step title underneath.
# Other screens use one title inside the box, avoiding a generic onboarding
# label followed by a second heading that repeats the same context.
# Empty color variables retain the same readable layout in noninteractive output.
header() {
    local title="$1" step=0 label progress='' i
    if [[ "$title" =~ ^STEP[[:space:]]([1-9]):[[:space:]](.*)$ ]]; then
        step="${BASH_REMATCH[1]}"
        title="${BASH_REMATCH[2]}"
        label="STEP ${step} / 9"
    else
        label="$title"
    fi
    printf '\n%s╭──────────────────────────────────────────────────────────╮%s\n' "$C_CYAN" "$C_RESET"
    printf '%s│ %-56.56s │%s\n' "$C_CYAN" "$label" "$C_RESET"
    if (( step > 0 )); then
        for ((i=1; i<=9; i++)); do
            if ((i<=step)); then progress+='●'; else progress+='○'; fi
        done
        # Nine Unicode circles occupy nine terminal cells, but more bytes.
        # Use a separate ASCII-space field so printf never measures their bytes.
        printf '%s│ %s%*s │%s\n' "$C_CYAN" "$progress" 47 '' "$C_RESET"
    fi
    printf '%s╰──────────────────────────────────────────────────────────╯%s\n' "$C_CYAN" "$C_RESET"
    if (( step > 0 )); then
        printf '\n%s  %s%s\n\n' "$C_CYAN" "$title" "$C_RESET"
    else
        printf '\n'
    fi
}

# Display colored status markers without changing the actual workflow.
ui_success() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
ui_error() { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET"; }
ui_warning() { printf '%s! %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
# Every pause is a human confirmation, not an automated check of iPhone state.
# EOF or Ctrl+C aborts through the exit handler rather than advancing the wizard.
ui_pause() {
    printf '\n%s────────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
    printf '%s  [ENTER] %s    [Ctrl+C] Cancel%s ' "$C_CYAN" "$1" "$C_RESET"
    read -r
}


# Validate a host[:port] authority before it reaches either a config file or uv.
# Schemes pasted from a browser are accepted as input conveniences only: the
# launcher always uses HTTPS. A bare host deliberately retains no explicit port,
# letting mitm_redirect.py apply its own default (555). Reverse proxies on the
# standard HTTPS port must be entered as host:443.
normalize_endpoint() {
    local value="$1" host port label octet
    local authority_re='^[A-Za-z0-9.-]+(:[0-9]+)?$'
    case "$value" in
        https://*) value="${value#https://}" ;;
        http://*) value="${value#http://}" ;;
    esac
    if [[ ! "$value" =~ $authority_re ]]; then
        echo "Enter a hostname or IPv4 address with an optional port, for example host:555." >&2
        return 1
    fi
    host="${value%%:*}"
    # A port entered on its own looks like a numeric hostname to a permissive
    # parser. Reject it here so "443" cannot be saved as the server address.
    if [[ "$host" != *[!0-9]* ]]; then
        echo "Enter the server hostname or IP address, not just a port such as 443 or 555." >&2
        return 1
    fi
    if (( ${#host} > 253 )); then
        echo "The hostname is too long." >&2
        return 1
    fi
    # DNS labels cannot be empty or start/end with a hyphen. No underscores,
    # credentials, paths, shell punctuation, or IPv6 literals are accepted here.
    local label_re='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$'
    local remaining="$host"
    while :; do
        label="${remaining%%.*}"
        if (( ${#label} > 63 )) || [[ ! "$label" =~ $label_re ]]; then
            echo "Invalid hostname label." >&2
            return 1
        fi
        [[ "$remaining" == *.* ]] || break
        remaining="${remaining#*.}"
    done
    # Reject an invalid numeric IPv4 address instead of treating it as DNS.
    if [[ "$host" == *.* && "$host" != *[!0-9.]* ]]; then
        local count=0
        remaining="$host"
        while :; do
            octet="${remaining%%.*}"
            if (( ${#octet} > 3 )) || (( 10#$octet > 255 )); then
                echo "Invalid IPv4 address." >&2
                return 1
            fi
            count=$((count + 1))
            [[ "$remaining" == *.* ]] || break
            remaining="${remaining#*.}"
        done
        [[ "$count" -eq 4 ]] || { echo "IPv4 addresses need four octets." >&2; return 1; }
    fi
    if [[ "$value" == *:* ]]; then
        port="${value##*:}"
        if (( ${#port} > 5 )) || (( 10#$port < 1 || 10#$port > 65535 )); then
            echo "The port must be between 1 and 65535." >&2
            return 1
        fi
        # Decimal normalization prevents a zero-prefixed port being interpreted
        # inconsistently by downstream tools; it does not change the port number.
        value="$host:$((10#$port))"
    fi
    printf '%s\n' "$value"
}

# Validate a credential without printing, trimming, or executing any of it.
# The launcher uses Python's strip() before deciding whether sync is enabled.
# Match that exact definition, including Unicode/control whitespace regardless
# of the terminal locale; Bash's [[:space:]] alone has different edge cases.
# Pass the value on stdin, never in process arguments, and keep the original
# meaningful value byte-for-byte rather than silently trimming saved settings.
sync_secret_has_content() {
    local value="${1:-}"
    ensure_python || return 2
    printf '%s' "$value" | "$PYTHON_BIN" -c '
import sys
value = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
sys.exit(0 if value.strip() else 1)
'
}

# Configuration v2 is DATA, not a shell program. The first line identifies the
# format; the following lines hold literal values after the first '='. Quotes,
# dollar signs and backticks have no special meaning and are never executed.
# Values are single lines because prompts use read; reject embedded newlines
# rather than allow extra records to be injected. Write atomically with 0600 mode.
save_config() {
    local temporary
    if ! sync_secret_has_content "${SYNC_SECRET:-}"; then
        ui_error "A Protocol Sync Secret containing more than whitespace is required. Configuration was not saved." >&2
        return 1
    fi
    if [[ "${ROBOROCK_DOMAIN:-}" == *$'\n'* || "${SYNC_SECRET:-}" == *$'\n'* ||
          "${ROBOROCK_DOMAIN:-}" == *$'\r'* || "${SYNC_SECRET:-}" == *$'\r'* ||
          -L "$CONFIG_FILE" ]]; then
        ui_error "Cannot save multiline values or a symlinked configuration." >&2
        return 1
    fi
    temporary="$(mktemp "$SCRIPT_DIR/.roborock_config.XXXXXXXX")" || return 1
    chmod 600 "$temporary"
    {
        printf '%s\n' '# roborock-onboard-config-v2: literal values, not shell code'
        printf 'ROBOROCK_DOMAIN=%s\n' "$ROBOROCK_DOMAIN"
        printf 'SYNC_SECRET=%s\n' "$SYNC_SECRET"
    } > "$temporary"
    mv -f "$temporary" "$CONFIG_FILE"
}

# Read only recognized keys. For migration, accept the old exact KEY='value'
# format ONLY when its single-quoted value contains no inner quote. Even a
# string such as '$(touch file)' remains data. Malformed legacy files get an
# actionable error; never source or eval a configuration to recover its values.
read_config() {
    local first line key value version=1 domain_seen=0 secret_seen=0
    local legacy_re="^(ROBOROCK_DOMAIN|SYNC_SECRET)='([^']*)'$"
    [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || {
        ui_error "Configuration is missing or is a symbolic link. Run '$0 config'." >&2
        return 1
    }
    IFS= read -r first < "$CONFIG_FILE" || return 1
    [[ "$first" != '# roborock-onboard-config-v2: literal values, not shell code' ]] || version=2
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$version" -eq 2 && "$line" == "$first" ]]; then
            continue
        fi
        [[ -n "$line" ]] || continue
        if [[ "$version" -eq 1 ]]; then
            if [[ "$line" =~ $legacy_re ]]; then
                key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
            else
                ui_error "Invalid legacy configuration. Run '$0 config' to replace it." >&2
                return 1
            fi
        else
            [[ "$line" == *=* && "$line" != *$'\r'* ]] || return 1
            key="${line%%=*}" value="${line#*=}"
        fi
        case "$key" in
            ROBOROCK_DOMAIN)
                [[ "$domain_seen" -eq 0 ]] || return 1
                ROBOROCK_DOMAIN="$value"; domain_seen=1 ;;
            SYNC_SECRET)
                [[ "$secret_seen" -eq 0 ]] || return 1
                SYNC_SECRET="$value"; secret_seen=1 ;;
            *) ui_error "Unknown configuration key. Run '$0 config'." >&2; return 1 ;;
        esac
    done < "$CONFIG_FILE"
    [[ "$domain_seen" -eq 1 && "$secret_seen" -eq 1 ]] || {
        ui_error "Incomplete configuration. Run '$0 config'." >&2
        return 1
    }
}

# Ask only for missing values. Explain the two common connection arrangements
# with complete examples before requesting an address; users should not need to
# understand host[:port] notation. Invalid interactive input is retried before
# asking for a secret. A bad saved address instead points to the config command.
# The Protocol Sync Secret is found in the server Web UI, not in the admin login
# password field. Explain hidden terminal input so pasting does not look broken.
# Repair an empty/whitespace-only saved secret by prompting before any launch;
# the save and launch boundaries also validate it as defense against a bypass.
load_config() {
    local entered_address normalized_address
    ensure_python || return 1
    if [[ -e "$CONFIG_FILE" || -L "$CONFIG_FILE" ]]; then
        read_config || return 1
    fi
    if [[ -z "${ROBOROCK_DOMAIN:-}" ]]; then
        echo "How do you connect to Roborock Local Server?"
        echo
        echo "  No reverse proxy / default installation:"
        echo "    Enter the server's IP address or hostname."
        echo "    Example: 192.168.1.50"
        echo "    The wizard will use HTTPS port 555 automatically."
        echo
        echo "  Through a reverse proxy:"
        echo "    Enter the proxy hostname followed by its HTTPS port."
        echo "    Example: roborock.example.com:443"
        echo "    If your proxy uses a different port, use that port instead."
        echo
        echo "If you changed the default server port, include it after the address."
        echo "Enter the full hostname or IP address, not just 443 or 555."
        echo
        while :; do
            read -rp "Roborock server address: " entered_address || return 1
            if normalized_address="$(normalize_endpoint "$entered_address")"; then
                ROBOROCK_DOMAIN="$normalized_address"
                break
            fi
            echo "Please try again using one of the examples above."
            echo
        done
    else
        if ! normalized_address="$(normalize_endpoint "$ROBOROCK_DOMAIN")"; then
            ui_error "The saved server address is invalid. Run './roborock_onboard.sh config' to replace it." >&2
            return 1
        fi
        ROBOROCK_DOMAIN="$normalized_address"
    fi
    if ! sync_secret_has_content "${SYNC_SECRET:-}"; then
        if [[ -n "${SYNC_SECRET:-}" ]]; then
            ui_warning "The saved Protocol Sync Secret contains only whitespace. Please copy it again."
        fi
        echo
        echo "Find your Protocol Sync Secret:"
        echo
        echo "  1. Open Home Assistant (HA)."
        echo "  2. Go to Apps → Roborock Local Server."
        echo "  3. Press the Open Web UI button."
        echo "  4. Log in with your admin password."
        echo "  5. Copy the Protocol Sync Secret and paste it into this terminal."
        echo
        echo "Paste the Protocol Sync Secret, not your admin password."
        echo "Your paste will be hidden; press Enter afterward."
        echo
        while ! sync_secret_has_content "${SYNC_SECRET:-}"; do
            IFS= read -rsp "Protocol Sync Secret: " SYNC_SECRET || { echo; return 1; }
            echo
            if ! sync_secret_has_content "$SYNC_SECRET"; then
                ui_warning "A Protocol Sync Secret is required; blank input or whitespace alone is not valid. Copy it from the Web UI and try again."
            fi
        done
    fi
    save_config
}

# Present the effective connection once, beneath the relevant screen heading.
# Do not print from load_config: that previously produced a Server line before
# the main heading followed by a redundant Domain line after it.
display_server() {
    case "$ROBOROCK_DOMAIN" in
        *:*) printf 'Configured server: https://%s\n' "$ROBOROCK_DOMAIN" ;;
        *) printf 'Configured server: https://%s:555 (default port)\n' "$ROBOROCK_DOMAIN" ;;
    esac
}

# The small embedded supervisor needs Python 3. Prefer a Python already on PATH;
# otherwise ask uv for its existing managed interpreter. No sudo or keychain
# access is used. Python isolates a process group on macOS without a setsid CLI.
ensure_python() {
    [[ -z "${PYTHON_BIN:-}" ]] || return 0
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    elif command -v uv >/dev/null 2>&1; then
        PYTHON_BIN="$(uv python find 2>/dev/null)" || {
            ui_error "Python 3 is required. Install it with uv, then retry." >&2
            return 1
        }
    else
        ui_error "Python 3 and uv are required." >&2
        return 1
    fi
}

# Pointer files contain a private session-directory path, never executable code.
# Numeric PID files from older wizard versions are deliberately not trusted:
# that PID could now belong to an unrelated application.
read_session_pointer() {
    local pointer scan_status=0
    [[ -f "$PID_FILE" && ! -L "$PID_FILE" ]] || return 1
    IFS= read -r pointer < "$PID_FILE" || return 1
    if [[ "$pointer" != "$SESSION_ROOT"/mitm.* || ! -d "$pointer" || -L "$pointer" ]]; then
        # A legacy PID is never signalled. A complete exact-argv scan can prove
        # there is no matching launcher left; only then discard the stale pointer.
        process_helper scan "$SESSION_ROOT" "$MITM_SCRIPT" || scan_status=$?
        if [[ "$scan_status" -eq 1 ]]; then
            ui_warning "Discarding an old server-state pointer; no process was signalled." >&2
            rm -f "$PID_FILE"
            return 1
        fi
        ui_warning "Old or invalid server state; no process will be signalled." >&2
        echo "Stop the listed MITM process(es) from the original launcher, then retry." >&2
        echo "If inspection is unavailable, confirm the server is stopped before removing only: $PID_FILE" >&2
        return 2
    fi
    SESSION_DIR="$pointer"
}

# A checkout-wide lock serializes complete wizard runs, including the long
# human checkpoints. mkdir is atomic, unlike a check-then-create PID file.
# Utility stop/status commands remain available while the wizard is paused.
# After a power failure/SIGKILL the directory can remain: fail safely and tell
# the user to confirm no wizard is running before removing only this empty lock.
acquire_wizard_lock() {
    if ! mkdir -m 700 "$WIZARD_LOCK_DIR" 2>/dev/null; then
        ui_error "Another wizard is active, or an interrupted run left its lock."
        echo "Close any other onboarding wizard first."
        echo "If none is running, remove this empty lock directory in Finder, then retry:"
        printf '  %s\n' "$WIZARD_LOCK_DIR"
        return 1
    fi
    WIZARD_LOCK_HELD=1
}

release_wizard_lock() {
    if [[ "$WIZARD_LOCK_HELD" -eq 1 ]]; then
        rmdir "$WIZARD_LOCK_DIR" 2>/dev/null || return 1
        WIZARD_LOCK_HELD=0
    fi
}

# Make one private state directory per launch. Never overwrite an uncertain live
# session or reuse another launch's token/log. Refusing reuse also avoids silently
# retaining a previous endpoint or sync secret which cannot be checked via /flows.
prepare_session() {
    local kind="$1"
    if [[ -L "$SESSION_ROOT" ]]; then
        ui_error "Refusing a symbolic link at the session-state directory." >&2
        return 1
    fi
    mkdir -p "$SESSION_ROOT"
    chmod 700 "$SESSION_ROOT"
    NEW_SESSION_DIR="$(mktemp -d "$SESSION_ROOT/$kind.XXXXXXXX")"
}

# Run the small Python process supervisor embedded here. Python supplies the
# native session/argument APIs that Bash 3.2 cannot express reliably on macOS.
# The parent passes secrets in the environment, never in these arguments.
process_helper() {
    "$PYTHON_BIN" - "$@" <<'PY_PROCESS_HELPER'
import ctypes
import errno
import json
import os
import re
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ACTION, DIRECTORY, ADDON, *COMMAND = sys.argv[1:]
DIRECTORY = os.path.realpath(DIRECTORY)
ADDON = os.path.realpath(ADDON)
STATE = Path(DIRECTORY) / "state.json"
STOP_REQUEST = Path(DIRECTORY) / "stop-request"
GRACE = 4.0


def process_rows():
    """Read only PID/group/state columns: never expose command environments."""
    observer = subprocess.Popen(
        ["ps", "-axo", "pid=,pgid=,stat=,uid="], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True
    )
    output, errors = observer.communicate()
    if observer.returncode:
        raise RuntimeError("Cannot inspect process ownership; no process was stopped.")
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and int(parts[0]) != observer.pid:
            rows.append((int(parts[0]), int(parts[1]), parts[2], int(parts[3])))
    return rows


def arguments(pid):
    """Get real argv boundaries, including paths with spaces or regex symbols."""
    if sys.platform == "darwin":
        # KERN_PROCARGS2 returns argc, executable path, padding, then argv.
        # Unlike `ps command`, it does not flatten distinct arguments together.
        libc = ctypes.CDLL(None, use_errno=True)
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t(1024 * 1024)
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0):
            raise OSError(ctypes.get_errno(), "Cannot inspect process arguments")
        raw = buffer.raw[:size.value]
        argc = int.from_bytes(raw[:4], sys.byteorder)
        position = raw.index(b"\0", 4) + 1
        while position < len(raw) and raw[position] == 0:
            position += 1
        # Stop at argc so environment values, including secrets, are not read.
        return [os.fsdecode(value) for value in raw[position:].split(b"\0")[:argc]]
    return [os.fsdecode(value) for value in
            Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if value]


def birth(pid):
    """Pair a process start identity with the unique supervisor argv marker."""
    if sys.platform != "darwin":
        # Field 22 of Linux proc stat is the monotonic start tick count.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19]
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True
    )
    if result.returncode or not result.stdout.strip():
        raise ProcessLookupError(pid)
    return result.stdout.strip()


def members(group):
    # Zombies cannot receive signals and are already stopped; their parent
    # will reap them. The supervisor deliberately stays until live members exit.
    return [pid for pid, pgid, state, uid in process_rows()
            if pgid == group and not state.startswith("Z")]


def validate_directory():
    directory_stat = os.stat(DIRECTORY, follow_symlinks=False)
    if (not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.getuid()
            or directory_stat.st_mode & 0o077):
        raise RuntimeError("Session directory ownership or permissions are unsafe.")


def read_state():
    validate_directory()
    fd = os.open(STATE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd) as stream:
        metadata = os.fstat(stream.fileno())
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise RuntimeError("Session state ownership or permissions are unsafe.")
        data = json.load(stream)
    if data.get("directory") != DIRECTORY or data.get("addon") != ADDON:
        raise RuntimeError("Session state belongs to a different checkout.")
    if type(data.get("pid")) is not int or data["pid"] <= 1:
        raise RuntimeError("Session state has an invalid process identity.")
    if data.get("pgid") != data["pid"]:
        raise RuntimeError("Session does not own an isolated process group.")
    return data


def verified(data):
    """A stale numeric PID must never be sufficient authority to send signals."""
    pid = data["pid"]
    try:
        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
            return False
        if birth(pid) != data["birth"]:
            return False
        argv = arguments(pid)
        return (len(argv) >= 5 and argv[1:3] == ["-", "supervise"]
                and os.path.realpath(argv[3]) == DIRECTORY
                and os.path.realpath(argv[4]) == ADDON)
    except (OSError, ValueError, KeyError):
        return False


def safe_group_signal(data, sig):
    if data["pgid"] == os.getpgrp() or not verified(data):
        raise RuntimeError("Session ownership changed; refusing to signal its group.")
    os.killpg(data["pgid"], sig)


def write_state(data):
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=DIRECTORY)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream)
        os.replace(temporary, STATE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def supervise():
    if not COMMAND:
        raise RuntimeError("No supervised command was supplied.")
    os.umask(0o077)
    validate_directory()
    # A stop command can arrive before state.json exists. Its persistent marker
    # prevents this delayed supervisor from ever launching a new child afterward.
    if STOP_REQUEST.exists():
        return 0
    os.setsid()
    pid = os.getpid()
    stopping = [False]

    def request_stop(signum, frame):
        # Keep the group leader alive while every child is being terminated.
        stopping[0] = True

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, request_stop)
    data = {"pid": pid, "pgid": pid, "birth": birth(pid),
            "directory": DIRECTORY, "addon": ADDON}
    # Prove process inspection works before starting anything that needs cleanup.
    process_rows()
    write_state(data)
    child = None
    launch_failed = False
    try:
        if not stopping[0] and not STOP_REQUEST.exists():
            # uv selects the project from cwd, not merely from the addon filename.
            # Anchor both server and certificate runs to the addon checkout.
            child = subprocess.Popen(COMMAND, stdin=subprocess.DEVNULL,
                                     cwd=os.path.dirname(ADDON))
        while child is not None and child.poll() is None and not stopping[0]:
            time.sleep(0.1)
    except OSError:
        launch_failed = True
        print("Could not launch the temporary server; verify the required commands.",
              file=sys.stderr)
    finally:
        # The supervisor is the session/group leader, so this group is owned.
        # Its TERM handler only sets a flag; it does not exit ahead of children.
        os.killpg(pid, signal.SIGTERM)
        deadline = time.monotonic() + GRACE
        while time.monotonic() < deadline:
            if child is not None:
                child.poll()
            remaining = [member for member in members(pid) if member != pid]
            if not remaining:
                STATE.unlink(missing_ok=True)
                return (1 if launch_failed else 0) if child is None else (child.returncode or 0)
            time.sleep(0.1)
        # An exact group KILL includes this supervisor. Keep its state record so
        # the external stop command can verify that the entire group disappeared.
        os.killpg(pid, signal.SIGKILL)
    return 1


def status():
    try:
        data = read_state()
    except FileNotFoundError:
        return 1
    if verified(data):
        print(data["pid"])
        return 0
    if members(data["pgid"]):
        raise RuntimeError("A session group remains but its supervisor cannot be verified.")
    return 1


def stop():
    try:
        validate_directory()
    except FileNotFoundError:
        return 0
    marker_fd = os.open(STOP_REQUEST, os.O_WRONLY | os.O_CREAT
                        | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(marker_fd)
    # Cover startup before the supervisor publishes state. The marker remains,
    # so even a later launch must see the stop request before creating children.
    deadline = time.monotonic() + 1.0
    while not STATE.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        data = read_state()
    except FileNotFoundError:
        return 0
    if not verified(data):
        if members(data["pgid"]):
            raise RuntimeError("Unverified session remains; it was left running.")
        STATE.unlink(missing_ok=True)
        return 0
    try:
        safe_group_signal(data, signal.SIGTERM)
    except (ProcessLookupError, RuntimeError):
        if not members(data["pgid"]):
            STATE.unlink(missing_ok=True)
            return 0
        raise
    deadline = time.monotonic() + GRACE + 1.0
    while time.monotonic() < deadline:
        if not members(data["pgid"]):
            STATE.unlink(missing_ok=True)
            return 0
        time.sleep(0.1)
    # The leader remains until descendants stop. Revalidate immediately before
    # escalation, rather than treating a saved PID as permanent authorization.
    if verified(data):
        safe_group_signal(data, signal.SIGKILL)
    elif members(data["pgid"]):
        raise RuntimeError("Supervisor identity disappeared; remaining group was left untouched.")
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not members(data["pgid"]):
            STATE.unlink(missing_ok=True)
            return 0
        time.sleep(0.1)
    raise RuntimeError("Some session processes remain; inspect the session manually.")


def addon_command(argv):
    """Recognize launcher/mitmweb command shapes, not arbitrary path mentions."""
    if not argv:
        return False
    executable = os.path.basename(argv[0])
    if executable == "uv" and argv[1:3] == ["run", ADDON]:
        return True
    addon_option = any(argv[index:index + 2] == ["-s", ADDON]
                       for index in range(1, len(argv) - 1))
    if executable == "mitmweb":
        return addon_option
    if executable == "uvx" and "mitmweb" in argv[1:]:
        return addon_option
    if not re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?", executable):
        return False
    # Find Python's script argument, respecting options that consume a value.
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument in ("-", "-c", "-m"):
            return False
        if argument == "--":
            index += 1
            break
        if argument in ("-W", "-X"):
            index += 2
        elif argument.startswith("-"):
            index += 1
        else:
            break
    if index >= len(argv):
        return False
    return (argv[index] == ADDON
            or (os.path.basename(argv[index]) == "mitmweb" and addon_option))


def scan():
    """Best-effort discovery; never use its results to authorize a signal.

    macOS can deny argv reads for unrelated processes, including ones owned by
    this user. That is not a fault in our session permissions and must not stop
    an otherwise valid launch. Status 3 means the scan was incomplete; only 1
    proves a complete scan with no matching addon processes. That distinction
    matters when deciding whether an old numeric PID pointer can be discarded.
    """
    found = False
    incomplete = False
    try:
        rows = process_rows()
    except (OSError, RuntimeError, ValueError):
        rows = []
        incomplete = True
    for pid, group, state, uid in rows:
        if pid == os.getpid() or state.startswith("Z") or uid != os.getuid():
            continue
        try:
            if addon_command(arguments(pid)):
                print(pid)
                found = True
        except OSError as exc:
            # Vanished processes are normal. Permission denials and other
            # inspection failures make this advisory scan incomplete, not fatal.
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                incomplete = True
        except ValueError:
            incomplete = True
    if incomplete:
        print("Note: macOS could not inspect some other processes. "
              "They will not be reused or stopped by this wizard.", file=sys.stderr)
    return 0 if found else (3 if incomplete else 1)


def web_port_is_free():
    """Probe loopback without credentials or claiming ownership of a listener.

    This is an early diagnostic, not a port reservation; mitmweb still handles a
    bind conflict if another listener starts between the probe and its launch.
    An occupied port is left untouched, and the old shared log is preserved.
    """
    try:
        with socket.create_connection(("127.0.0.1", 8081), timeout=0.5):
            pass
    except ConnectionRefusedError:
        return 0
    except OSError:
        raise RuntimeError("Cannot check the local MITM web port. No server was started.")
    print("Port 8081 is already in use. No existing server was stopped.", file=sys.stderr)
    print("For a previous wizard session, run './roborock_onboard.sh stop'. "
          "Otherwise close that server from its original launcher, then retry.",
          file=sys.stderr)
    return 1


try:
    if ACTION == "supervise":
        code = supervise()
    elif ACTION == "status":
        code = status()
    elif ACTION == "stop":
        code = stop()
    elif ACTION == "scan":
        code = scan()
    elif ACTION == "port-free":
        code = web_port_is_free()
    else:
        raise RuntimeError("Unknown process helper action.")
    sys.exit(code if isinstance(code, int) and 0 <= code <= 255 else 1)
except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
    # RuntimeError messages above are fixed, non-sensitive explanations. Other
    # exceptions may contain paths or data, so report only a safe error category.
    if isinstance(exc, RuntimeError):
        detail = str(exc)
    elif isinstance(exc, OSError):
        category = errno.errorcode.get(exc.errno, "OS_ERROR")
        detail = "The operating system refused a process or state operation (" + category + ")."
    else:
        detail = "Session state or process information could not be decoded."
    print("MITM process check: " + detail, file=sys.stderr)
    sys.exit(2)
PY_PROCESS_HELPER
}

mitm_is_running() {
    process_helper status "$SESSION_DIR" "$MITM_SCRIPT" >/dev/null
}

# Only stop groups whose identity can be verified by the embedded helper.
# The supervisor keeps the group leader alive while TERM reaches uv's children;
# a bounded KILL fallback therefore cannot accidentally hit the wizard's group.
kill_mitm_quietly() {
    [[ -n "$SESSION_DIR" ]] || return 0
    if process_helper stop "$SESSION_DIR" "$MITM_SCRIPT"; then
        MITM_ACTIVE=0
        if [[ -f "$PID_FILE" ]] && [[ "$(cat "$PID_FILE")" == "$SESSION_DIR" ]]; then
            rm -f "$PID_FILE"
        fi
        return 0
    fi
    ui_error "Could not safely stop this MITM session. See the server state and stop it manually." >&2
    return 1
}

# Give each signal a defined nonzero status. The EXIT handler receives that
# explicit status rather than the status of whichever command ran before Ctrl+C.
install_traps() {
    trap 'emergency_cleanup "$?"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
}

emergency_cleanup() {
    local exit_code="$1"
    trap - EXIT INT TERM HUP
    set +e
    if [[ -n "$CERT_SESSION_DIR" ]]; then
        process_helper stop "$CERT_SESSION_DIR" "$MITM_SCRIPT"
    fi
    if [[ "$NORMAL_CLEANUP" -eq 0 && "$MITM_ACTIVE" -eq 1 ]]; then
        header "ONBOARDING ABORTED"
        echo "Stopping temporary MITM server..."
        if kill_mitm_quietly; then
            ui_success "MITM server stopped."
        else
            [[ "$exit_code" -ne 0 ]] || exit_code=1
        fi
    fi
    if [[ "$NORMAL_CLEANUP" -eq 0 && "$PHONE_PREPARED" -eq 1 ]]; then
        echo
        ui_warning "On the iPhone: turn WireGuard OFF and disable Full Trust for the mitmproxy certificate."
        echo "Settings → General → About → Certificate Trust Settings."
        capture_cleanup_guidance
    fi
    release_wizard_lock || {
        ui_warning "The wizard lock could not be removed; inspect it before retrying."
        [[ "$exit_code" -ne 0 ]] || exit_code=1
    }
    exit "$exit_code"
}

stop_mitm() {
    local pointer_status=0 scan_status=0
    header "STOP MITM SERVER"
    read_session_pointer || pointer_status=$?
    if [[ "$pointer_status" -eq 2 ]]; then return 1; fi
    if [[ "$pointer_status" -eq 0 ]]; then
        kill_mitm_quietly || return 1
        ui_success "This wizard's MITM session is stopped."
    else
        echo "No managed MITM session was recorded for this directory."
    fi
    # Legacy servers have no verified group identity. Report all exact-addon
    # matches, but do not adopt or terminate them on the basis of a stale PID.
    process_helper scan "$SESSION_ROOT" "$MITM_SCRIPT" || scan_status=$?
    if [[ "$scan_status" -eq 0 ]]; then
        ui_warning "An unmanaged MITM process for this addon is still running. Stop it from its original launcher."
        return 1
    elif [[ "$scan_status" -eq 3 ]]; then
        # Optional discovery may be incomplete, but shutdown of this wizard's
        # recorded group was already verified above. Never claim other groups.
        return 0
    elif [[ "$scan_status" -ne 1 ]]; then
        ui_error "Could not verify that all MITM processes stopped." >&2
        return 1
    fi
}

status_mitm() {
    local pointer_status=0 status=0
    header "MITM SERVER STATUS"
    read_session_pointer || pointer_status=$?
    [[ "$pointer_status" -ne 2 ]] || return 1
    if [[ "$pointer_status" -eq 0 ]]; then
        mitm_is_running || status=$?
        case "$status" in
            0) ui_success "A verified MITM session is running for this directory." ;;
            1) echo "The recorded MITM session is no longer running." ;;
            *) ui_warning "The recorded process identity could not be verified."; return 1 ;;
        esac
    else
        echo "No managed MITM session is recorded for this directory."
    fi
    echo "Log: $LOG_FILE"
    echo "Unmanaged matching processes (if any):"
    process_helper scan "$SESSION_ROOT" "$MITM_SCRIPT" || {
        status=$?
        [[ "$status" -eq 1 || "$status" -eq 3 ]] || return 1
    }
}

# Wait for a NEW, owned session, not a token from an old log. Only a real HTTP
# 200 from the authenticated /flows endpoint permits opening the Capture page.
# curl reads its URL from stdin so even its token stays out of process arguments.
# Ignore user curl config/proxies: this is strictly a local loopback probe.
wait_for_mitm() {
    local deadline=$((SECONDS + STARTUP_TIMEOUT)) candidate token http_status
    MITM_AUTH_URL=''
    echo "Waiting for the authenticated MITM page (up to $STARTUP_TIMEOUT seconds)..."
    while (( SECONDS < deadline )); do
        if ! mitm_is_running; then
            echo
            ui_error "MITM exited or its identity could not be verified during startup."
            return 1
        fi
        candidate="$(
            grep 'Web server listening at ' "$LOG_FILE" 2>/dev/null |
                grep -Eo 'http://127\.0\.0\.1:8081/\?token=[A-Za-z0-9._~%+-]+' |
                tail -n 1 || true
        )"
        if [[ -n "$candidate" ]]; then
            token="${candidate##*token=}"
            http_status="$(
                printf 'url = "http://127.0.0.1:8081/flows?token=%s"\n' "$token" |
                    curl -q --config - --noproxy '*' --connect-timeout 1 --max-time 2 \
                        -s -o /dev/null -w '%{http_code}' 2>/dev/null || true
            )"
            if [[ "$http_status" == 200 ]]; then
                MITM_AUTH_URL="$candidate"
                echo
                return 0
            fi
        fi
        printf '.'
        sleep 1
    done
    echo
    ui_error "Timed out waiting for the authenticated MITM Capture page."
    return 1
}

# Capture directories contain entire Roborock requests/responses, including login
# tokens and rriot keys. Identify this session from the addon's [LOG] announcement,
# not by guessing that the newest directory is ours. Cleanup is manual and narrow:
# this script never recursively deletes captures or other sessions automatically.
capture_cleanup_guidance() {
    local stamp current_capture=''
    stamp="$(grep -F '[LOG] Rewritten' "$LOG_FILE" 2>/dev/null |
        grep -Eo '[0-9]{8}_[0-9]{6}/rewritten' | tail -n 1 || true)"
    if [[ -n "$stamp" ]]; then
        current_capture="$SCRIPT_DIR/mitm_logs/${stamp%/rewritten}"
    fi
    echo
    ui_warning "Sensitive captures may contain your Roborock login token and rriot keys."
    if [[ -n "$current_capture" && -d "$current_capture" && ! -L "$current_capture" ]]; then
        echo "After successful onboarding, delete this session directory in Finder:"
        printf '  %s\n' "$current_capture"
    else
        echo "After successful onboarding, identify and delete this session under:"
        printf '  %s/mitm_logs/\n' "$SCRIPT_DIR"
        echo "The [LOG] entries in the MITM startup log identify its session directory."
    fi
    echo "Keep other sessions only if needed; do not post raw captures or startup logs."
    echo "The separate startup log contains the web authentication URL:"
    printf '  %s\n' "$LOG_FILE"
    echo "Delete that startup log after you have finished any troubleshooting."
}


# Reset saved values only for the explicit config command; never execute old data.
configure() {
    rm -f "$CONFIG_FILE"
    unset ROBOROCK_DOMAIN SYNC_SECRET

    header "ROBOROCK CONFIGURATION"

    load_config

    echo
    display_server
    ui_success "Configuration saved."
    echo
    echo "File:"
    echo "$CONFIG_FILE"
    echo
    echo "Permissions are restricted to your user."
}


# Generate the public CA by briefly running mitmdump in a private supervised
# group. A fresh uvx tool environment provides mitmproxy when it is not a project
# dependency. Bind only loopback and request an ephemeral port; no phone tunnel,
# sudo, macOS keychain edit, or Mac trust change is needed for CA generation.
generate_mitm_certificate() {
    local deadline ready=0 cert_job_pid
    local command=()
    echo "The mitmproxy CA certificate was not found."
    echo "Generating the mitmproxy CA on this Mac (up to 90 seconds)..."
    mkdir -p "$HOME/.mitmproxy"
    if command -v mitmdump >/dev/null 2>&1; then
        command=(mitmdump)
    elif command -v uvx >/dev/null 2>&1; then
        command=(uvx --from mitmproxy mitmdump)
    else
        ui_error "FAILED: Install uv (which includes uvx), or install mitmdump."
        return 1
    fi
    ensure_python || return 1
    prepare_session cert || return 1
    CERT_SESSION_DIR="$NEW_SESSION_DIR"
    [[ ! -L "$CERT_LOG_FILE" ]] || { ui_error "Refusing a symbolic link at the certificate log."; return 1; }
    : > "$CERT_LOG_FILE"
    chmod 600 "$CERT_LOG_FILE"
    process_helper supervise "$CERT_SESSION_DIR" "$MITM_SCRIPT" \
        "${command[@]}" --set "confdir=$HOME/.mitmproxy" \
        --listen-host 127.0.0.1 --listen-port 0 \
        > "$CERT_LOG_FILE" 2>&1 < /dev/null &
    cert_job_pid=$!
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
        if [[ -s "$MITM_CERT" ]]; then ready=1; break; fi
        # Checking our shell job for existence cannot signal an unrelated PID.
        # All actual shutdown signals still require the verified group helper.
        kill -0 "$cert_job_pid" 2>/dev/null || break
        if [[ -f "$CERT_SESSION_DIR/state.json" ]]; then
            process_helper status "$CERT_SESSION_DIR" "$MITM_SCRIPT" >/dev/null || break
        fi
        printf '.'
        sleep 1
    done
    echo
    process_helper stop "$CERT_SESSION_DIR" "$MITM_SCRIPT" || return 1
    CERT_SESSION_DIR=''
    wait "$cert_job_pid" 2>/dev/null || true
    if [[ "$ready" -ne 1 ]]; then
        ui_error "FAILED: mitmproxy did not create its CA certificate."
        echo "Check network/tool installation and the private certificate-generation log:"
        printf '  %s\n' "$CERT_LOG_FILE"
        return 1
    fi
    ui_success "SUCCESS: mitmproxy CA generated."
}

# Verify dependencies before enabling certificate trust or requesting a code.
# A launcher file is required in the same project directory as this wizard.
# The early wizard probe matches the launcher's defaults and expected response.
# The launcher also performs its own fresh preflight when MITM actually starts.
check_requirements() {
    local tool
    for tool in uv uvx curl; do
        command -v "$tool" >/dev/null 2>&1 || {
            ui_error "Missing required command: $tool. Install uv/uvx and curl, then retry."
            return 1
        }
    done
    ensure_python || return 1
    "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || {
        ui_error "Python 3.8 or newer is required for the process supervisor."
        return 1
    }
    [[ -f "$MITM_SCRIPT" ]] || {
        ui_error "Cannot find $MITM_SCRIPT"
        echo "Keep roborock_onboard.sh beside the repository's mitm_redirect.py."
        return 1
    }
}

# Check the real HTTPS sync endpoint before asking the user to change iPhone
# trust or obtain a time-sensitive code. This matches mitm_redirect.py's probe:
# an intentionally incomplete payload must return HTTP 400 with the structured
# missing_user_data reason. An ordinary website/redirect/2xx response is NOT a
# successful check. The launcher checks again later, since phone steps take time.
#
# curl provides a total request deadline (including connection establishment).
# Python normalizes the secret and parses JSON without depending on spacing or
# key order. Credentials go only through a temporary environment and curl stdin;
# neither the credential nor response bodies appear in process arguments/output.
verify_server_connection() {
    local authority request_authority secret_header response curl_status=0
    local http_code response_body
    ensure_python || return 1
    authority="$(normalize_endpoint "$ROBOROCK_DOMAIN")" || return 1
    if ! sync_secret_has_content "${SYNC_SECRET:-}"; then
        ui_error "A valid Protocol Sync Secret is required before checking the server."
        echo "Run: ./roborock_onboard.sh config"
        return 1
    fi
    # Match the launcher's HTTPS default and its omission of an explicit :443
    # in direct HTTP requests (some reverse proxies inspect the Host header).
    case "$authority" in
        *:443) request_authority="${authority%:443}" ;;
        *:*) request_authority="$authority" ;;
        *) request_authority="$authority:555" ;;
    esac
    # Header injection must be rejected even for direct calls that bypass the
    # config writer's single-line constraint. Strip only after this check.
    secret_header="$(MITM_LOCAL_SYNC_SECRET="$SYNC_SECRET" "$PYTHON_BIN" -c '
import os, sys
value = os.environ.get("MITM_LOCAL_SYNC_SECRET", "")
if "\r" in value or "\n" in value or not value.strip():
    sys.exit(1)
sys.stdout.write("X-Local-Sync-Secret: " + value.strip())
')" || {
        ui_error "The Protocol Sync Secret is invalid. Copy it again as a single line."
        echo "Run: ./roborock_onboard.sh config"
        return 1
    }
    echo "Checking the server connection and Protocol Sync Secret (up to 10 seconds)..."
    # Do not add --fail: HTTP 400 is the expected probe response. Do not follow
    # redirects: the configured address itself must be the intended endpoint.
    # Disable user curl configuration and bound response size and total runtime.
    response="$(
        printf '%s\n' "$secret_header" |
            curl -q --http1.1 --connect-timeout 5 --max-time 10 --max-filesize 65536 \
                -s --header @- --header 'Content-Type: application/json' \
                --data-binary '{"source":"mitm_preflight"}' \
                -w $'\n%{http_code}' \
                "https://$request_authority/internal/protocol/user-data" 2>/dev/null
    )" || curl_status=$?
    if [[ "$curl_status" -ne 0 ]]; then
        case "$curl_status" in
            5|6) ui_error "Could not resolve the configured hostname or network proxy. Check the address and DNS." ;;
            7) ui_error "Could not connect to the server. Check its address, HTTPS port, and whether it is running." ;;
            28) ui_error "The server connection timed out. Check the network and HTTPS port." ;;
            35|51|58|60) ui_error "HTTPS certificate or TLS verification failed. Check the hostname and server certificate." ;;
            63) ui_error "The server returned an unexpectedly large response. Check that this is the correct server address." ;;
            *) ui_error "The server connection check failed (connection error $curl_status)." ;;
        esac
        echo "To correct the server or Protocol Sync Secret, run: ./roborock_onboard.sh config"
        return 1
    fi
    http_code="${response##*$'\n'}"
    response_body="${response%$'\n'*}"
    if [[ "$http_code" == 400 ]] &&
        printf '%s' "$response_body" | "$PYTHON_BIN" -c '
import json, sys
try:
    result = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
    data = result.get("data") if isinstance(result, dict) else None
    valid = isinstance(data, dict) and str(data.get("reason") or "").strip() == "missing_user_data"
except (ValueError, TypeError, RecursionError):
    valid = False
sys.exit(0 if valid else 1)
'; then
        ui_success "Server connection verified."
        return 0
    fi
    case "$http_code" in
        401|403) ui_error "The server rejected access. Check the Protocol Sync Secret and any reverse-proxy login requirements." ;;
        3[0-9][0-9]) ui_error "The server redirected the request. Configure the direct HTTPS address of Roborock Local Server." ;;
        *) ui_error "The address did not return the expected Roborock sync response (HTTP $http_code). Check the server, port, and proxy routing." ;;
    esac
    echo "To correct the server or Protocol Sync Secret, run: ./roborock_onboard.sh config"
    return 1
}

# A prior session is never silently adopted: its endpoint/secret cannot be
# proved by web authentication. Stop it first, then launch with the saved inputs.
# Legacy or externally launched matching processes are informational only and
# require manual shutdown; a stale numeric PID never grants authority to kill.
check_existing_session() {
    local pointer_status=0 state_status=0 scan_status=0
    read_session_pointer || pointer_status=$?
    [[ "$pointer_status" -ne 2 ]] || return 1
    if [[ "$pointer_status" -eq 0 ]]; then
        mitm_is_running || state_status=$?
        if [[ "$state_status" -eq 0 ]]; then
            ui_warning "A verified MITM server from this wizard is already running."
            echo "Stop it before starting with the current endpoint and session secret:"
            echo "  ./roborock_onboard.sh stop"
            return 1
        elif [[ "$state_status" -ne 1 ]]; then
            ui_error "Existing server ownership is uncertain; it was left untouched."
            return 1
        fi
        rm -f "$PID_FILE"
        SESSION_DIR=''
    fi
    process_helper scan "$SESSION_ROOT" "$MITM_SCRIPT" || scan_status=$?
    if [[ "$scan_status" -eq 0 ]]; then
        ui_warning "An unmanaged server for this exact addon is running (PID(s) above)."
        echo "Stop it from its original launcher, then retry. It has been left untouched."
        return 1
    elif [[ "$scan_status" -eq 3 ]]; then
        # Discovery is advisory. A known managed session still requires strict
        # identity checks above; an unreadable unrelated process does not.
        return 0
    elif [[ "$scan_status" -ne 1 ]]; then
        ui_error "The existing-server discovery check failed unexpectedly."
        return 1
    fi
}

# Before changing the shared log or PID pointer, check the local web port. Even
# an unreadable/unmanaged listener must be left untouched. The actual server's
# bind and authenticated readiness checks remain authoritative after launch.
web_port_is_available() {
    process_helper port-free "$SESSION_ROOT" "$MITM_SCRIPT"
}

# Launch in an isolated group managed by the embedded Python supervisor. The
# environment supplies the secret; neither uv nor Python gets a --sync-secret
# argument. Environment transport avoids argv exposure; it does not hide a secret
# from privileged or same-user processes able to inspect another environment.
# umask 077 propagates to mitmweb and its sensitive capture files.
# The log is freshly truncated ONLY after all previous-session checks pass.
launch_mitm() {
    local pointer_temp startup_deadline
    # Never let the launcher receive a blank credential: it would skip the
    # protocol-sync preflight and start with authentication sync disabled.
    # This final guard also protects direct calls that bypass load_config.
    if ! sync_secret_has_content "${SYNC_SECRET:-}"; then
        ui_error "A valid Protocol Sync Secret is required before starting MITM. Run './roborock_onboard.sh config'." >&2
        return 1
    fi
    # Recheck after the phone/code checkpoints: an external launcher might have
    # started since the initial check. Preserve its log and leave it untouched.
    check_existing_session || return 1
    web_port_is_available || return 1
    prepare_session mitm || return 1
    SESSION_DIR="$NEW_SESSION_DIR"
    [[ ! -L "$LOG_FILE" ]] || { ui_error "Refusing a symbolic link at the MITM log."; return 1; }
    : > "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    pointer_temp="$(mktemp "$SCRIPT_DIR/.roborock_pid.XXXXXXXX")" || return 1
    printf '%s\n' "$SESSION_DIR" > "$pointer_temp"
    mv -f "$pointer_temp" "$PID_FILE"
    MITM_ACTIVE=1
    MITM_LOCAL_SYNC_SECRET="$SYNC_SECRET" PYTHONUNBUFFERED=1 \
        process_helper supervise "$SESSION_DIR" "$MITM_SCRIPT" \
            uv run "$MITM_SCRIPT" --local-api "$ROBOROCK_DOMAIN" \
            --set web_open_browser=false \
            > "$LOG_FILE" 2>&1 < /dev/null &
    # The supervisor proves process inspection works before publishing state.
    # Waiting for publication avoids treating a normal launch race as a crash.
    startup_deadline=$((SECONDS + 5))
    while [[ ! -f "$SESSION_DIR/state.json" ]] && (( SECONDS < startup_deadline )); do
        sleep 0.1
    done
    if ! wait_for_mitm; then
        echo "The launcher may have rejected the endpoint/secret or encountered a port conflict."
        echo "Its preflight requires the expected missing_user_data response; a generic 2xx is not accepted."
        echo "Inspect the private startup log locally; it may contain authentication data:"
        printf '  %s\n' "$LOG_FILE"
        return 1
    fi
    ui_success "SUCCESS: MITM server and authenticated web interface are ready."
    echo "Log: $LOG_FILE"
    echo
    echo "Opening the authenticated MITM capture page..."
    # macOS open returns after dispatching the URL. mitmweb's own browser opener
    # is disabled above, so the wizard requests only this one Capture tab.
    if ! open "${MITM_AUTH_URL}#/capture" 2>/dev/null; then
        ui_warning "Could not open the browser automatically."
        echo "Open the authenticated URL from the private log, then select Capture."
        ui_pause "after the authenticated capture page is open"
    fi
}

# Keep WireGuard OFF until the official app has requested its verification code.
# Installing a certificate profile and enabling Full Trust are separate actions.
prepare_iphone_certificate() {
    header "STEP 1: PREPARE THE IPHONE"
    # From here onward an abort must remind the user to undo iPhone trust,
    # even if the wizard fails before the MITM process has been launched.
    PHONE_PREPARED=1

    ui_warning "IMPORTANT: Leave WireGuard OFF for now."
    echo
    echo "To check whether the mitmproxy CA certificate is already installed,"
    echo "go to this screen on the iPhone:"
    echo
    echo "  Settings"
    echo "    → General"
    echo "    → About (scroll to bottom)"
    echo "    → Certificate Trust Settings"
    echo

    while true; do
        read -rp "Is the mitmproxy CA certificate already installed on this iPhone? [y/N]: " CERT_INSTALLED

        case "${CERT_INSTALLED:-n}" in

            y|Y|yes|YES|Yes)

                echo
                echo "The certificate is already installed."
                echo
                echo "On this Certificate Trust Settings screen,"
                echo "under 'Enable Full Trust for Root Certificates':"
                echo
                echo "  Turn ON the mitmproxy certificate."
                echo
                ui_warning "IMPORTANT: Keep WireGuard OFF."
                echo
                ui_pause "after Full Trust is ON"
                break
                ;;


            n|N|no|NO|No|"")

                echo
                echo "The certificate needs to be transferred from this Mac."
                echo

                if [[ -f "$MITM_CERT" ]]; then
                    ui_success "Found the mitmproxy CA certificate:"
                    echo
                    echo "  $MITM_CERT"
                else
                    generate_mitm_certificate
                fi

                echo
                echo "Opening Finder with the certificate selected..."

                open -R "$MITM_CERT" 2>/dev/null || true

                echo
                echo "On the Mac:"
                echo
                echo "  1. Finder should now show:"
                echo
                echo "       mitmproxy-ca-cert.cer"
                echo
                echo "  2. AirDrop that file to the iPhone."
                echo
                echo "On the iPhone:"
                echo
                echo "  3. Accept the AirDrop."
                echo
                echo "  4. Go to:"
                echo
                echo "       Settings"
                echo "         → General"
                echo "         → VPN & Device Management"
                echo
                echo "  5. Select the mitmproxy profile and install it."
                echo
                echo "  6. Then go to:"
                echo
                echo "       Settings"
                echo "         → General"
                echo "         → About"
                echo "         → Certificate Trust Settings"
                echo
                echo "  7. Under 'Enable Full Trust for Root Certificates',"
                echo "     turn ON the mitmproxy certificate."
                echo
                echo "IMPORTANT:"
                echo "Installing the certificate profile is not enough."
                echo "Full Trust must also be enabled."
                echo
                echo "Keep WireGuard OFF."
                echo
                ui_pause "after the certificate is installed and Full Trust is ON"
                break
                ;;


            *)
                echo "Please answer y or n."
                ;;
        esac
    done
}


# Nine-step flow: request code with the tunnel OFF, submit with it ON, then
# prove the normal app works with the tunnel OFF before stopping MITM.
start() {
    acquire_wizard_lock
    check_requirements

    header "ROBOROCK iOS ONBOARDING"

    echo "To change the saved server or Protocol Sync Secret, run:"
    echo "  ./roborock_onboard.sh config"
    echo

    load_config
    display_server
    verify_server_connection
    check_existing_session

    prepare_iphone_certificate


    # Obtain the cloud code before intercepting the phone network connection.
    header "STEP 2: GET THE ROBOROCK VERIFICATION CODE"

    echo "With WireGuard STILL OFF:"
    echo
    echo "  1. Open the official Roborock iOS app."
    echo "  2. Enter the Roborock account email address."
    echo "  3. Agree to the terms and conditions."
    echo "  4. Request a fresh email verification code."
    echo "  5. Wait for the verification code to arrive in your email."
    echo "  6. Save the verification code somewhere you can easily reference."
    ui_warning "DO NOT ENTER IT YET."
    echo
    echo "     The Roborock app does not allow pasting verification codes,"
    echo "     so you will need to type the code manually later."
    echo "  7. Leave the Roborock app at the code-entry screen."
    echo
    echo "DO NOT submit the verification code yet."
    echo
    ui_pause "after you have the code and have NOT submitted it"


    # The initial screen already verified the endpoint before iPhone changes.
    # The launcher repeats its own preflight at startup to catch a server or
    # credential change during the manual phone/code checkpoints.
    header "STEP 3: PREPARE MITM CONNECTION"
    echo "The configured server passed the initial connection check."
    echo "The launcher will check it again before starting mitmweb."
    echo "If that check fails, onboarding stops before you enable WireGuard."

    header "STEP 4: START MITM SERVER"
    launch_mitm

    # The new WireGuard tunnel must belong to this particular MITM instance.
    header "STEP 5: CONNECT WIREGUARD AND SUBMIT LOGIN"

    echo "On the iPhone:"
    echo
    echo "  1. Delete any pre-existing Roborock MITM WireGuard tunnel."
    echo "     Then create a NEW Roborock WireGuard tunnel."
    echo "     Scan the QR code on the MITM capture page."
    echo "     A new tunnel must be created each time."
    echo
    echo "  2. Turn ON the newly created WireGuard tunnel."
    echo
    echo "  3. Return to the Roborock app."
    echo "     It should still be waiting at the verification-code screen."
    echo
    echo "  4. Enter the verification code you obtained while"
    echo "     WireGuard was OFF."
    echo
    echo "  5. Submit the login."
    echo
    echo "The verification-code submission MUST occur with WireGuard ON."
    echo
    ui_pause "after the Roborock login succeeds"


    # Wait for both live device state and the map to work through interception.
    header "STEP 6: VERIFY ROBOT THROUGH MITM"

    echo "Keep WireGuard ON."
    echo "Keep the MITM server running."
    echo
    echo "In the Roborock app:"
    echo
    echo "  1. Confirm your robot(s) appear."
    echo "  2. Open the robot's device screen."
    echo "  3. Confirm its status loads."
    echo "  4. Confirm the MAP loads."
    echo
    echo "This can take approximately 1.5 minutes."
    echo "Do not continue until the robot status and map are working."
    echo
    ui_pause "after the robot status and map have loaded successfully"


    # Restart the app without the tunnel to verify the authentication handoff.
    header "STEP 7: TEST WITHOUT THE MITM TUNNEL"

    echo "Leave the MITM server running on this Mac for now."
    echo
    echo "On the iPhone:"
    echo
    echo "  1. FORCE-QUIT the Roborock app."
    echo "  2. Turn WireGuard OFF."
    echo "  3. Reopen the Roborock app normally."
    echo "  4. Confirm your robot(s) appear."
    echo "  5. Open the robot's device screen."
    echo "  6. Confirm its status loads."
    echo "  7. Confirm the map loads."
    echo "  8. Confirm normal controls work."
    echo
    echo "This verifies that the authentication handoff succeeded."
    echo
    echo "DO NOT continue if the app fails this test."
    echo
    ui_pause "only after the app works normally with WireGuard OFF"


    # Do not stop interception until the user confirms the normal app works.
    header "STEP 8: SHUT DOWN MITM"

    echo "Authentication handoff confirmed."
    echo
    echo "Stopping the temporary MITM server..."
    echo

    stop_mitm


    # The Mac cannot verify iPhone VPN/trust settings; these remain manual steps.
    header "STEP 9: CERTIFICATE CLEANUP"

    echo "On the iPhone:"
    echo
    echo "  1. Confirm WireGuard is OFF."
    echo
    echo "  2. Go to:"
    echo
    echo "       Settings"
    echo "         → General"
    echo "         → About"
    echo "         → Certificate Trust Settings"
    echo
    echo "  3. Turn OFF 'Enable Full Trust' for the mitmproxy certificate."
    echo
    echo "You may leave the certificate/profile installed."
    echo "That makes future recovery easier if the Roborock session expires."
    echo
    ui_pause "after Full Trust is OFF"

    # No broad deletion: the user identifies and removes only this session's
    # sensitive captures after confirming the handoff worked.
    capture_cleanup_guidance
    NORMAL_CLEANUP=1

    header "ONBOARDING COMPLETE"

    ui_success "Roborock authentication handoff confirmed by you."
    ui_warning "Reminder: leave WireGuard OFF on the iPhone."
    ui_success "MITM server is stopped."
    ui_warning "Reminder: leave mitmproxy Full Trust OFF on the iPhone."
    echo
    echo "The Roborock app should now operate normally through"
    echo "local_roborock_server without the temporary MITM tunnel."
}


# Utility commands also need the supervisor runtime, but never prompt for a
# session secret. SIGINT/SIGTERM/SIGHUP always exit through the same cleanup.
install_traps

case "${1:-start}" in

    start)
        start
        ;;

    stop)
        ensure_python
        stop_mitm
        NORMAL_CLEANUP=1
        ;;

    status)
        ensure_python
        status_mitm
        NORMAL_CLEANUP=1
        ;;

    config)
        configure
        NORMAL_CLEANUP=1
        ;;

    *)
        echo "Usage: $0 {start|stop|status|config}"
        NORMAL_CLEANUP=1
        exit 1
        ;;
esac
