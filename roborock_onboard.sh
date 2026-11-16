#!/usr/bin/env bash

# Stop on an unhandled command failure (-e), an unset variable (-u), or a
# failed command inside a pipeline (pipefail). Expected failures are handled
# explicitly with conditionals or `|| true` throughout the wizard.
set -euo pipefail

# Keep all wizard files beside this script, regardless of the directory from
# which it is launched. BASH_SOURCE identifies this file; quoting preserves
# paths containing spaces. The hidden configuration contains the session secret;
# the PID file records the temporary server process; the log records its output.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/.roborock_onboard.conf"
PID_FILE="$SCRIPT_DIR/.roborock_mitm.pid"
LOG_FILE="$SCRIPT_DIR/roborock_mitm.log"
MITM_SCRIPT="$SCRIPT_DIR/mitm_redirect.py"

# mitmproxy generates this public CA certificate in the current user's home.
# Installing it on the iPhone and enabling Full Trust are separate actions.
MITM_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"

# Cleanup state: active means the wizard has started or accepted responsibility
# for a server. Normal cleanup is set only after the intended workflow completes.
# These flags let the exit handler distinguish completion from interruption.
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

# Draw the shared heading. Titles of the form "STEP N: ..." receive a step
# counter and progress circles; other titles receive the general wizard label.
# All styling variables are empty when color is disabled, keeping output readable.
header() {
    local title="$1" step=0 label progress='' i
    if [[ "$title" =~ ^STEP[[:space:]]([1-9]):[[:space:]](.*)$ ]]; then
        step="${BASH_REMATCH[1]}"
        title="${BASH_REMATCH[2]}"
        label="STEP ${step} / 9"
    else
        label="ROBOROCK iOS ONBOARDING"
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
    printf '\n%s  %s%s\n\n' "$C_CYAN" "$title" "$C_RESET"
}

# Display colored status markers without changing the actual workflow.
ui_success() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
ui_error() { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET"; }
ui_warning() { printf '%s! %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
# Pause at a human checkpoint. Nothing proceeds until Enter is pressed.
# Ctrl+C invokes the cleanup handler registered below.
ui_pause() {
    printf '\n%s────────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
    printf '%s  [ENTER] %s    [Ctrl+C] Cancel%s ' "$C_CYAN" "$1" "$C_RESET"
    read -r
}


# Persist the domain and admin session secret so later runs need not ask again.
# umask 077 limits newly created files to this user; chmod also restricts an
# existing configuration file. This file is sourced as shell code on later runs,
# so treat it as a trusted local file and do not share it.
save_config() {
    umask 077
    cat > "$CONFIG_FILE" <<EOF
ROBOROCK_DOMAIN='$ROBOROCK_DOMAIN'
SYNC_SECRET='$SYNC_SECRET'
EOF
    chmod 600 "$CONFIG_FILE"
}


# Read saved values when available, ask only for missing values, and normalize
# the domain by removing a leading https:// and one trailing slash.
# Secret input is hidden on the terminal. Save the resulting settings afterward.
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    fi

    if [[ -z "${ROBOROCK_DOMAIN:-}" ]]; then
        read -rp "Roborock domain (example: api-roborock.example.com): " ROBOROCK_DOMAIN
    fi

    ROBOROCK_DOMAIN="${ROBOROCK_DOMAIN#https://}"
    ROBOROCK_DOMAIN="${ROBOROCK_DOMAIN%/}"

    if [[ -z "${SYNC_SECRET:-}" ]]; then
        read -rsp "Current admin session secret: " SYNC_SECRET
        echo
    fi

    save_config
}


# Locate the first process whose command line matches this onboarding addon.
# This is a command-line match, not a check of which directory launched it.
# No match is normal: return empty output without triggering strict-mode exit.
find_existing_mitm() {
    pgrep -f 'mitmweb.*mitm_redirect.py' 2>/dev/null | head -n 1 || true
}


# Best-effort shutdown for emergency cleanup: first use the recorded PID,
# then look for a matching mitmweb process. Give each process a short chance
# to stop normally before forcing termination. Remove the PID marker afterward.
kill_mitm_quietly() {
    if [[ -f "$PID_FILE" ]]; then
        PID="$(cat "$PID_FILE" 2>/dev/null || true)"

        if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            sleep 1

            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null || true
            fi
        fi

        rm -f "$PID_FILE"
    fi

    EXISTING_PID="$(find_existing_mitm)"

    if [[ -n "$EXISTING_PID" ]]; then
        kill "$EXISTING_PID" 2>/dev/null || true
        sleep 1

        if kill -0 "$EXISTING_PID" 2>/dev/null; then
            kill -9 "$EXISTING_PID" 2>/dev/null || true
        fi
    fi

    MITM_ACTIVE=0
}


# Preserve the triggering exit status, then disable traps to avoid recursion.
# If the wizard owns an active server and has not completed normally, stop it
# and show the manual iPhone safety steps. The Mac cannot switch off the
# iPhone's WireGuard tunnel or its certificate trust setting for the user.
emergency_cleanup() {
    EXIT_CODE=$?

    trap - EXIT INT TERM HUP

    if [[ "$NORMAL_CLEANUP" -eq 0 && "$MITM_ACTIVE" -eq 1 ]]; then
        header "ONBOARDING ABORTED"

        echo "Stopping temporary MITM server..."
        echo

        kill_mitm_quietly

        ui_success "MITM server stopped."
        echo
        ui_warning "IMPORTANT: On the iPhone:"
        echo
        echo "  1. Turn WireGuard OFF."
        echo "  2. Go to:"
        echo
        echo "       Settings"
        echo "         → General"
        echo "         → About"
        echo "         → Certificate Trust Settings"
        echo
        echo "  3. Turn OFF Enable Full Trust for the mitmproxy certificate."
        echo
    fi

    exit "$EXIT_CODE"
}


# Run cleanup on normal shell exit as well as common interruption signals.
# The state flags prevent a completed run or a status/config command from
# performing the aborted-onboarding cleanup.
trap emergency_cleanup EXIT INT TERM HUP


# User-facing shutdown, also used by step 8. Try the PID file and then the
# process-name lookup so an orphaned server can still be found. Report whether
# a server was stopped, and clear the active flag to prevent duplicate cleanup.
stop_mitm() {
    header "STOP MITM SERVER"

    STOPPED=0

    if [[ -f "$PID_FILE" ]]; then
        PID="$(cat "$PID_FILE" 2>/dev/null || true)"

        if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            sleep 2

            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null || true
            fi

            ui_success "MITM server stopped (PID $PID)."
            STOPPED=1
        fi

        rm -f "$PID_FILE"
    fi

    EXISTING_PID="$(find_existing_mitm)"

    if [[ -n "$EXISTING_PID" ]]; then
        kill "$EXISTING_PID" 2>/dev/null || true
        sleep 2

        if kill -0 "$EXISTING_PID" 2>/dev/null; then
            kill -9 "$EXISTING_PID" 2>/dev/null || true
        fi

        ui_success "Existing MITM server stopped (PID $EXISTING_PID)."
        STOPPED=1
    fi

    MITM_ACTIVE=0

    if [[ "$STOPPED" -eq 0 ]]; then
        echo "MITM server is not running."
    fi
}


# Report the matching process and log location without starting onboarding.
# A running process alone does not prove that its authenticated web UI is ready;
# the start workflow performs that additional check.
status_mitm() {
    header "MITM SERVER STATUS"

    EXISTING_PID="$(find_existing_mitm)"

    if [[ -n "$EXISTING_PID" ]]; then
        ui_success "MITM server is running."
        echo "PID: $EXISTING_PID"
        echo "Log: $LOG_FILE"
    else
        echo "MITM server is not running."
    fi
}


# Explicit configuration reset: discard saved settings and ask for new values.
# Unsetting variables ensures values from this shell are not silently reused.
configure() {
    rm -f "$CONFIG_FILE"
    unset ROBOROCK_DOMAIN SYNC_SECRET

    header "ROBOROCK CONFIGURATION"

    load_config

    echo
    ui_success "Configuration saved."
    echo
    echo "File:"
    echo "$CONFIG_FILE"
    echo
    echo "Permissions are restricted to your user."
}


# Briefly launch mitmdump to generate its CA files, then stop that process.
# Prefer an installed mitmdump, otherwise try it through the project's uv setup.
# The uv branch runs in a subshell so its directory change stays local.
# Finally check that the certificate exists before asking the user to install it.
generate_mitm_certificate() {
    echo "The mitmproxy CA certificate was not found."
    echo
    echo "Generating the mitmproxy CA on this Mac..."
    echo

    mkdir -p "$HOME/.mitmproxy"

    if command -v mitmdump >/dev/null 2>&1; then

        mitmdump --set confdir="$HOME/.mitmproxy" >/dev/null 2>&1 &
        GEN_PID=$!

        sleep 3

        kill "$GEN_PID" 2>/dev/null || true
        wait "$GEN_PID" 2>/dev/null || true

    elif command -v uv >/dev/null 2>&1; then

        (
            cd "$SCRIPT_DIR"

            uv run mitmdump \
                --set confdir="$HOME/.mitmproxy" \
                >/dev/null 2>&1 &

            GEN_PID=$!

            sleep 3

            kill "$GEN_PID" 2>/dev/null || true
            wait "$GEN_PID" 2>/dev/null || true
        )

    else
        ui_error "FAILED: Neither mitmdump nor uv was found."
        echo
        echo "The script cannot generate the mitmproxy CA."
        exit 1
    fi

    if [[ ! -f "$MITM_CERT" ]]; then
        ui_error "FAILED: mitmproxy did not create:"
        echo
        echo "  $MITM_CERT"
        echo
        exit 1
    fi

    ui_success "SUCCESS: mitmproxy CA generated."
}


# Step 1 branches on whether the iPhone already has the CA profile installed.
# An existing profile needs Full Trust enabled; a missing profile also needs
# transfer and installation. Both branches pause with WireGuard still OFF.
prepare_iphone_certificate() {
    header "STEP 1: PREPARE THE IPHONE"

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


# Main nine-step onboarding flow. The ordering matters: obtain the cloud login
# code with WireGuard OFF, submit it through MITM with WireGuard ON, then prove
# the normal app works without the tunnel before stopping MITM and removing trust.
start() {
    load_config

    if [[ ! -f "$MITM_SCRIPT" ]]; then
        echo "ERROR: Cannot find:"
        echo
        echo "  $MITM_SCRIPT"
        echo
        echo "roborock_onboard.sh and mitm_redirect.py should be"
        echo "in the same project directory."
        exit 1
    fi

    header "ROBOROCK LOCAL SERVER ONBOARDING"

    echo "Domain: $ROBOROCK_DOMAIN"

    prepare_iphone_certificate


    # Obtain the email code before routing the phone through the temporary MITM.
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


    # Verify the destination server before altering the phone network path.
    header "STEP 3: VERIFY LOCAL SERVER ENDPOINT"

    # Send a deliberately incomplete sync payload to test reachability and the
    # server's sync endpoint. Append the HTTP status on its own final line so
    # the response body and status can be inspected separately.
    PREFLIGHT_RESPONSE="$(
        curl --http1.1 -sS \
          -w $'\n%{http_code}' \
          "https://${ROBOROCK_DOMAIN}/internal/protocol/user-data" \
          -H 'Content-Type: application/json' \
          -H "X-Local-Sync-Secret: ${SYNC_SECRET}" \
          --data-binary '{"source":"mitm_preflight"}'
    )" || {
        ui_error "FAILED: Could not connect to the local Roborock server."
        exit 1
    }

    # Split at the last newline: the final line is curl's HTTP status, and all
    # preceding text is the server response body.
    HTTP_CODE="${PREFLIGHT_RESPONSE##*$'\n'}"
    RESPONSE_BODY="${PREFLIGHT_RESPONSE%$'\n'*}"

    # The specific missing_user_data response confirms the intended endpoint
    # understood the probe. A 2xx response is also accepted; other responses
    # stop onboarding before the temporary MITM server is started.
    if [[ "$HTTP_CODE" == "400" ]] &&
       [[ "$RESPONSE_BODY" == *'"code":40041'* ]] &&
       [[ "$RESPONSE_BODY" == *'"reason":"missing_user_data"'* ]]; then

        ui_success "SUCCESS: Local Roborock server is reachable and ready."

    elif [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then

        ui_success "SUCCESS: Local Roborock server accepted the preflight request."

    else
        ui_error "FAILED: Local Roborock server preflight check failed."
        echo
        echo "HTTP status: $HTTP_CODE"
        echo "Response:"
        echo "$RESPONSE_BODY"
        exit 1
    fi


    # Start or verify MITM, then open its authenticated Capture interface.
    header "STEP 4: START MITM SERVER"

    EXISTING_PID="$(find_existing_mitm)"
    # Track whether this run launched the process or discovered an existing one.
    # SECONDS is Bash's elapsed-time counter, used below for a bounded wait.
    local reused_mitm=0 startup_deadline candidate_url http_status
    MITM_AUTH_URL=""

    if [[ -n "$EXISTING_PID" ]] &&
       kill -0 "$EXISTING_PID" 2>/dev/null; then

        ui_success "MITM server is already running."
        echo "  Reusing the existing server."
        echo "  PID: $EXISTING_PID"
        MITM_PID="$EXISTING_PID"
        reused_mitm=1
        # Do not take ownership until its authenticated interface is verified.
        # An old log may belong to another server; validate its token below.
    else
        rm -f "$PID_FILE"
        cd "$SCRIPT_DIR"

        # Truncate stale output only when starting a new server. Unbuffered
        # Python output makes the authentication URL visible when redirected.
        (umask 077; : > "$LOG_FILE")
        chmod 600 "$LOG_FILE"
        PYTHONUNBUFFERED=1 nohup uv run "$MITM_SCRIPT" \
          --local-api "https://${ROBOROCK_DOMAIN}:443" \
          --sync-secret "$SYNC_SECRET" \
          --set web_open_browser=false \
          >"$LOG_FILE" 2>&1 < /dev/null &

        MITM_PID=$!
        echo "$MITM_PID" > "$PID_FILE"
        MITM_ACTIVE=1
    fi

    echo
    echo "Waiting for the authenticated MITM capture page (up to 45 seconds)..."
    # Readiness requires both a logged token URL and a successful authenticated
    # API response. Print a dot on each retry so slow startup is visible.
    # Each HTTP probe has its own short timeout; the final probe/sleep can extend
    # the elapsed-time deadline slightly.
    startup_deadline=$((SECONDS + 45))
    while (( SECONDS < startup_deadline )); do
        if ! kill -0 "$MITM_PID" 2>/dev/null; then
            echo
            ui_error "FAILED: MITM server exited during startup."
            break
        fi

        # Only read the server announcement, and restrict the token to URL-safe
        # characters so terminal color escapes cannot become part of the URL.
        candidate_url="$(
            grep 'Web server listening at ' "$LOG_FILE" 2>/dev/null |
                grep -Eo 'http://127\.0\.0\.1:8081/\?token=[A-Za-z0-9._~%+-]+' |
                tail -n 1 || true
        )"
        if [[ -n "$candidate_url" ]]; then
            # An authenticated API request proves that a log token belongs to
            # the live web server. Never open an unverified stale log URL.
            http_status="$(
                curl --noproxy '*' --connect-timeout 1 --max-time 2 \
                    -s -o /dev/null -w '%{http_code}' \
                    "${candidate_url/\/?token=/\/flows?token=}" 2>/dev/null || true
            )"
            if [[ "$http_status" == "200" ]]; then
                MITM_AUTH_URL="$candidate_url"
                break
            fi
        fi
        printf '.'
        sleep 1
    done
    echo

    if [[ -z "$MITM_AUTH_URL" ]]; then
        ui_error "FAILED: The authenticated MITM capture page is not ready."
        echo "Log: $LOG_FILE"
        if (( reused_mitm )); then
            echo "The existing server's current authentication token could not be verified."
            echo "It has been left running. Run this wizard with 'stop', then retry."
        else
            echo "Startup timed out or the server exited. The temporary server will be stopped."
            echo "Check the log for startup errors or dependency downloads, then retry."
        fi
        exit 1
    fi

    # Only after verification do we adopt a reused process for normal cleanup.
    # Store its PID so the stop command can find it on a later invocation.
    MITM_ACTIVE=1
    echo "$MITM_PID" > "$PID_FILE"
    ui_success "SUCCESS: MITM server and authenticated web interface are ready."
    echo "PID: $MITM_PID"
    echo "Log: $LOG_FILE"
    echo
    echo "Opening the authenticated MITM capture page..."
    # The query token authenticates the browser; the fragment selects Capture.
    # Keep mitmweb's own browser launch disabled so it does not open a Flows tab.
    # If macOS cannot open the browser, require a manual checkpoint instead.
    if ! open "${MITM_AUTH_URL}#/capture" 2>/dev/null; then
        ui_warning "Could not open the browser automatically."
        echo "Open the authentication URL in $LOG_FILE and select Capture."
        ui_pause "after the authenticated capture page is open"
    fi

    # A newly generated tunnel carries the code submission through this server.
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


    # Confirm device data and maps work while the interception tunnel is active.
    header "STEP 6: VERIFY ROBOT THROUGH MITM"

    echo "Keep WireGuard ON."
    echo "Keep the MITM server running."
    echo
    echo "In the Roborock app:"
    echo
    echo "  1. Confirm the Saros 10R appears."
    echo "  2. Open the robot's device screen."
    echo "  3. Confirm its status loads."
    echo "  4. Confirm the MAP loads."
    echo
    echo "This can take approximately 1.5 minutes."
    echo "Do not continue until the robot status and map are working."
    echo
    ui_pause "after the robot status and map have loaded successfully"


    # Test the handoff independently: restart the app with the tunnel disabled.
    header "STEP 7: TEST WITHOUT THE MITM TUNNEL"

    echo "Leave the MITM server running on this Mac for now."
    echo
    echo "On the iPhone:"
    echo
    echo "  1. FORCE-QUIT the Roborock app."
    echo "  2. Turn WireGuard OFF."
    echo "  3. Reopen the Roborock app normally."
    echo "  4. Confirm the Saros 10R appears."
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


    # Shut down only after the user confirms operation without the tunnel.
    header "STEP 8: SHUT DOWN MITM"

    echo "Authentication handoff confirmed."
    echo
    echo "Stopping the temporary MITM server..."
    echo

    stop_mitm


    # Finish by disabling temporary CA trust on the phone; keep the profile if desired.
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

    # All required checkpoints have completed; suppress aborted-run cleanup.
    NORMAL_CLEANUP=1


    header "ONBOARDING COMPLETE"

    ui_success "Roborock authentication handoff completed."
    ui_success "WireGuard is OFF."
    ui_success "MITM server is stopped."
    ui_success "mitmproxy Full Trust is OFF."
    echo
    echo "The Roborock app should now operate normally through"
    echo "local_roborock_server without the temporary MITM tunnel."
}


# Command dispatcher. With no argument, run the full wizard. The other commands
# manage the temporary server or saved configuration without the nine-step flow.
# Mark successful utility commands as normal exits for the cleanup handler.
case "${1:-start}" in

    start)
        start
        ;;

    stop)
        stop_mitm
        NORMAL_CLEANUP=1
        ;;

    status)
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
