#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/.roborock_onboard.conf"
PID_FILE="$SCRIPT_DIR/.roborock_mitm.pid"
LOG_FILE="$SCRIPT_DIR/roborock_mitm.log"
MITM_SCRIPT="$SCRIPT_DIR/mitm_redirect.py"

MITM_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"

MITM_ACTIVE=0
NORMAL_CLEANUP=0


header() {
    echo
    echo "============================================================"
    echo " $1"
    echo "============================================================"
    echo
}


save_config() {
    umask 077
    cat > "$CONFIG_FILE" <<EOF
ROBOROCK_DOMAIN='$ROBOROCK_DOMAIN'
SYNC_SECRET='$SYNC_SECRET'
EOF
    chmod 600 "$CONFIG_FILE"
}


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


find_existing_mitm() {
    pgrep -f 'mitmweb.*mitm_redirect.py' 2>/dev/null | head -n 1 || true
}


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


emergency_cleanup() {
    EXIT_CODE=$?

    trap - EXIT INT TERM HUP

    if [[ "$NORMAL_CLEANUP" -eq 0 && "$MITM_ACTIVE" -eq 1 ]]; then
        header "ONBOARDING ABORTED"

        echo "Stopping temporary MITM server..."
        echo

        kill_mitm_quietly

        echo "✓ MITM server stopped."
        echo
        echo "IMPORTANT: On the iPhone:"
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


trap emergency_cleanup EXIT INT TERM HUP


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

            echo "✓ MITM server stopped (PID $PID)."
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

        echo "✓ Existing MITM server stopped (PID $EXISTING_PID)."
        STOPPED=1
    fi

    MITM_ACTIVE=0

    if [[ "$STOPPED" -eq 0 ]]; then
        echo "MITM server is not running."
    fi
}


status_mitm() {
    header "MITM SERVER STATUS"

    EXISTING_PID="$(find_existing_mitm)"

    if [[ -n "$EXISTING_PID" ]]; then
        echo "✓ MITM server is running."
        echo "PID: $EXISTING_PID"
        echo "Log: $LOG_FILE"
    else
        echo "MITM server is not running."
    fi
}


configure() {
    rm -f "$CONFIG_FILE"
    unset ROBOROCK_DOMAIN SYNC_SECRET

    header "ROBOROCK CONFIGURATION"

    load_config

    echo
    echo "✓ Configuration saved."
    echo
    echo "File:"
    echo "$CONFIG_FILE"
    echo
    echo "Permissions are restricted to your user."
}


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
        echo "✗ FAILED: Neither mitmdump nor uv was found."
        echo
        echo "The script cannot generate the mitmproxy CA."
        exit 1
    fi

    if [[ ! -f "$MITM_CERT" ]]; then
        echo "✗ FAILED: mitmproxy did not create:"
        echo
        echo "  $MITM_CERT"
        echo
        exit 1
    fi

    echo "✓ SUCCESS: mitmproxy CA generated."
}


prepare_iphone_certificate() {
    header "STEP 1: PREPARE THE IPHONE"

    echo "IMPORTANT: Leave WireGuard OFF for now."
    echo

    while true; do
        read -rp "Is the mitmproxy CA certificate already installed on this iPhone? [y/N]: " CERT_INSTALLED

        case "${CERT_INSTALLED:-n}" in

            y|Y|yes|YES|Yes)

                echo
                echo "The certificate is already installed."
                echo
                echo "On the iPhone go to:"
                echo
                echo "  Settings"
                echo "    → General"
                echo "    → About"
                echo "    → Certificate Trust Settings"
                echo
                echo "Under 'Enable Full Trust for Root Certificates':"
                echo
                echo "  Turn ON the mitmproxy certificate."
                echo
                echo "IMPORTANT: Keep WireGuard OFF."
                echo

                read -rp "Press ENTER after Full Trust is ON..."
                break
                ;;


            n|N|no|NO|No|"")

                echo
                echo "The certificate needs to be transferred from this Mac."
                echo

                if [[ -f "$MITM_CERT" ]]; then
                    echo "✓ Found the mitmproxy CA certificate:"
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

                read -rp "Press ENTER after the certificate is installed and Full Trust is ON..."
                break
                ;;


            *)
                echo "Please answer y or n."
                ;;
        esac
    done
}


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


    header "STEP 2: GET THE ROBOROCK VERIFICATION CODE"

    echo "With WireGuard STILL OFF:"
    echo
    echo "  1. Open the official Roborock iOS app."
    echo "  2. Enter the Roborock account email address."
    echo "  3. Request a fresh email verification code."
    echo "  4. Wait for the verification code to arrive."
    echo "  5. Leave the Roborock app at the code-entry screen."
    echo
    echo "DO NOT submit the verification code yet."
    echo

    read -rp "Press ENTER after you have the code and have NOT submitted it..."


    header "STEP 3: VERIFY LOCAL SERVER ENDPOINT"

    PREFLIGHT_RESPONSE="$(
        curl --http1.1 -sS \
          -w $'\n%{http_code}' \
          "https://${ROBOROCK_DOMAIN}/internal/protocol/user-data" \
          -H 'Content-Type: application/json' \
          -H "X-Local-Sync-Secret: ${SYNC_SECRET}" \
          --data-binary '{"source":"mitm_preflight"}'
    )" || {
        echo "✗ FAILED: Could not connect to the local Roborock server."
        exit 1
    }

    HTTP_CODE="${PREFLIGHT_RESPONSE##*$'\n'}"
    RESPONSE_BODY="${PREFLIGHT_RESPONSE%$'\n'*}"

    if [[ "$HTTP_CODE" == "400" ]] &&
       [[ "$RESPONSE_BODY" == *'"code":40041'* ]] &&
       [[ "$RESPONSE_BODY" == *'"reason":"missing_user_data"'* ]]; then

        echo "✓ SUCCESS: Local Roborock server is reachable and ready."

    elif [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then

        echo "✓ SUCCESS: Local Roborock server accepted the preflight request."

    else
        echo "✗ FAILED: Local Roborock server preflight check failed."
        echo
        echo "HTTP status: $HTTP_CODE"
        echo "Response:"
        echo "$RESPONSE_BODY"
        exit 1
    fi


    header "STEP 4: START MITM SERVER"

    EXISTING_PID="$(find_existing_mitm)"

    if [[ -n "$EXISTING_PID" ]] &&
       kill -0 "$EXISTING_PID" 2>/dev/null; then

        echo "✓ MITM server is already running."
        echo "  Reusing the existing server."
        echo "  PID: $EXISTING_PID"

        MITM_PID="$EXISTING_PID"
        MITM_ACTIVE=1

    else

        rm -f "$PID_FILE"

        cd "$SCRIPT_DIR"

        nohup uv run "$MITM_SCRIPT" \
          --local-api "https://${ROBOROCK_DOMAIN}:443" \
          --sync-secret "$SYNC_SECRET" \
          >"$LOG_FILE" 2>&1 &

        MITM_PID=$!
        echo "$MITM_PID" > "$PID_FILE"
        MITM_ACTIVE=1

        sleep 3

        if ! kill -0 "$MITM_PID" 2>/dev/null; then

            MITM_ACTIVE=0

            echo "✗ FAILED: MITM server exited during startup."
            echo

            if grep -q "Address already in use" "$LOG_FILE" 2>/dev/null; then
                echo "The MITM listening port is already in use."
                echo
                echo "Another MITM process may already be running."
                echo
                echo "Run:"
                echo
                echo "  $0 stop"
                echo
                echo "Then start onboarding again."
            else
                echo "MITM server output:"
                echo
                cat "$LOG_FILE"
            fi

            rm -f "$PID_FILE"
            exit 1
        fi

        echo "✓ SUCCESS: MITM server started."
        echo "PID: $MITM_PID"
        echo "Log: $LOG_FILE"
    fi


    header "STEP 5: CONNECT WIREGUARD AND SUBMIT LOGIN"

    echo "On the iPhone:"
    echo
    echo "  1. Create a NEW Roborock WireGuard tunnel."
    echo "     Scan the QR code on the MITM website."
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

    read -rp "Press ENTER after the Roborock login succeeds..."


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

    read -rp "Press ENTER after the robot status and map have loaded successfully..."


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

    read -rp "Press ENTER only after the app works normally with WireGuard OFF..."


    header "STEP 8: SHUT DOWN MITM"

    echo "Authentication handoff confirmed."
    echo
    echo "Stopping the temporary MITM server..."
    echo

    stop_mitm


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

    read -rp "Press ENTER after Full Trust is OFF..."

    NORMAL_CLEANUP=1


    header "ONBOARDING COMPLETE"

    echo "✓ Roborock authentication handoff completed."
    echo "✓ WireGuard is OFF."
    echo "✓ MITM server is stopped."
    echo "✓ mitmproxy Full Trust is OFF."
    echo
    echo "The Roborock app should now operate normally through"
    echo "local_roborock_server without the temporary MITM tunnel."
}


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
