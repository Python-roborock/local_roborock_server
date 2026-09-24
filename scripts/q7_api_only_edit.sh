#!/bin/sh
# Q7 recovery BusyBox editor. The OTA builder embeds this script in begin.sh.
set -eu

fail() { printf 'Q7 API edit refused: %s\n' "$1" >&2; exit 1; }
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail 'usage: <set|restore> <iot.json> [api-url]'
mode=$1
json_path=$2
bb=${Q7_BUSYBOX:-/bin/busybox}

[ -x "$bb" ] || fail 'BusyBox unavailable'
[ -f "$json_path" ] && [ ! -L "$json_path" ] || fail 'iot.json missing or linked'
case "$json_path" in */iot.json) ;; *) fail 'unexpected IoT filename' ;; esac
backup="${json_path}.before-q7-api-edit"

case "$mode" in
    set)
        [ "$#" -eq 3 ] || fail 'set requires an API URL'
        new_api=$3
        case "$new_api" in https://?*) ;; *) fail 'API URL must be HTTPS' ;; esac
        case "$new_api" in *[!A-Za-z0-9._:/+-]*) fail 'API URL has unsupported characters' ;; esac
        [ "${#new_api}" -le 240 ] || fail 'API URL is too long'
        [ ! -e "$backup" ] && [ ! -L "$backup" ] || fail 'rollback copy already exists'
        ;;
    restore)
        [ "$#" -eq 2 ] || fail 'restore takes no URL'
        [ -f "$backup" ] && [ ! -L "$backup" ] || fail 'rollback copy missing or linked'
        ;;
    *) fail 'unknown mode' ;;
esac

tmp=$("$bb" mktemp "${json_path}.new.XXXXXX") || fail 'could not stage replacement'
cleanup() { "$bb" rm -f -- "$tmp"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ "$mode" = restore ]; then
    "$bb" cp -p "$backup" "$tmp" || fail 'could not stage rollback'
    "$bb" cmp -s "$backup" "$tmp" || fail 'rollback stage differs'
else
    "$bb" cp -p "$json_path" "$tmp" || fail 'could not stage source metadata'
    "$bb" awk -v api="$new_api" '
    {
        line = $0
        if (index(line, "\"api_url\"") != 0) {
            if (line !~ /^[[:space:]]*"api_url"[[:space:]]*:[[:space:]]*"[^"]*"[[:space:]]*,?[[:space:]]*$/) exit 10
            seen++
            if (seen != 1) exit 11
            start = match(line, /"api_url"[[:space:]]*:[[:space:]]*"/)
            if (start == 0) exit 12
            prefix = substr(line, 1, RSTART + RLENGTH - 1)
            tail = substr(line, RSTART + RLENGTH)
            endquote = index(tail, "\"")
            if (endquote == 0) exit 13
            line = prefix api "\"" substr(tail, endquote + 1)
        }
        print line
    }
    END { if (seen != 1) exit 14 }
    ' "$json_path" > "$tmp" || fail 'expected one standalone API URL line'
    if "$bb" cmp -s "$json_path" "$tmp"; then
        printf 'Q7 API URL already matches; no edit\n'
        exit 0
    fi
    "$bb" cp -p "$json_path" "$backup" || fail 'could not save rollback copy'
    "$bb" cmp -s "$json_path" "$backup" || fail 'rollback copy differs'
fi

"$bb" sync || fail 'could not flush staged files'
"$bb" mv -f "$tmp" "$json_path" || fail 'atomic replacement failed'
"$bb" sync || fail 'replacement committed but sync failed'
printf 'Q7 API %s complete; rollback copy retained\n' "$mode"
