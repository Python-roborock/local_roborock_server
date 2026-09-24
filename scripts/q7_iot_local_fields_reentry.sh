#!/bin/sh
# Offline research fixture only. No OTA packaging or device access.
# Arguments: existing JSON, API URL, MQTT URL, MQTT client ID, user, password.
set -eu

if [ "$#" -ne 6 ]; then
    printf 'usage: %s <existing-iot.json> <api-url> <mqtt-url> <mqtt-clientid> <mqtt-user> <mqtt-password>\n' "$0" >&2
    exit 2
fi

json_path=$1
new_api=$2
new_mqtt=$3
new_clientid=$4
new_user=$5
new_password=$6
bb=${Q7_BUSYBOX:-/bin/busybox}

fail() { printf 'Q7 IoT local-field patch refused: %s\n' "$1" >&2; exit 1; }

[ -f "$json_path" ] || fail 'input is not a regular file'
[ ! -L "$json_path" ] || fail 'input is a symbolic link'
[ -x "$bb" ] || fail 'BusyBox command is unavailable'
case "$json_path" in */iot.json) ;; *) fail 'input name must be iot.json' ;; esac

# Q7's observed saved credential lengths are 16/16/32, and the recovered
# B01 derivation emits hexadecimal values of those lengths. This restriction
# also prevents JSON escaping and AWK -v escape interpretation.
for url in "$new_api" "$new_mqtt"; do
    case "$url" in *://?*) ;; *) fail 'URL must contain a scheme and nonempty suffix' ;; esac
    case "$url" in *[!A-Za-z0-9._:/+-]*) fail 'URL has unsupported characters' ;; esac
    [ "${#url}" -le 240 ] || fail 'URL exceeds conservative 240-byte limit'
done
[ "${#new_clientid}" -eq 16 ] || fail 'MQTT client ID must have 16 characters'
[ "${#new_user}" -eq 16 ] || fail 'MQTT user must have 16 characters'
[ "${#new_password}" -eq 32 ] || fail 'MQTT password must have 32 characters'
for credential in "$new_clientid" "$new_user" "$new_password"; do
    case "$credential" in *[!0-9a-fA-F]*) fail 'MQTT credentials must be hexadecimal' ;; esac
done

backup="${json_path}.before-q7-local-edit"
reuse_backup=0
if [ -e "$backup" ] || [ -L "$backup" ]; then
    [ -f "$backup" ] && [ ! -L "$backup" ] || fail 'rollback copy is not a regular file'
    "$bb" cmp -s "$json_path" "$backup" || fail 'rollback copy differs from restored source'
    reuse_backup=1
fi
tmp=$("$bb" mktemp "${json_path}.new.XXXXXX") || fail 'could not create same-directory temporary file'
cleanup() { "$bb" rm -f -- "$tmp"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

"$bb" cp -p "$json_path" "$tmp" || fail 'could not stage file metadata'

"$bb" awk -v api="$new_api" -v mqtt="$new_mqtt" \
    -v clientid="$new_clientid" -v username="$new_user" -v password="$new_password" '
function patch(key, value,       quoted, pattern, start, prefix, tail, endquote) {
    quoted = "\"" key "\""
    if (index(line, quoted) == 0) return
    pattern = "^[[:space:]]*" quoted "[[:space:]]*:[[:space:]]*\"[^\"]*\"[[:space:]]*,?[[:space:]]*$"
    if (line !~ pattern) exit 10
    seen[key]++
    if (seen[key] != 1) exit 11
    start = match(line, quoted "[[:space:]]*:[[:space:]]*\"")
    if (start == 0) exit 12
    prefix = substr(line, 1, RSTART + RLENGTH - 1)
    tail = substr(line, RSTART + RLENGTH)
    endquote = index(tail, "\"")
    if (endquote == 0) exit 13
    line = prefix value "\"" substr(tail, endquote + 1)
}
{
    line = $0
    patch("api_url", api)
    patch("mqtt_url", mqtt)
    patch("mqtt_clientid", clientid)
    patch("mqtt_usr", username)
    patch("mqtt_passwd", password)
    print line
}
END {
    if (seen["api_url"] != 1 || seen["mqtt_url"] != 1 ||
        seen["mqtt_clientid"] != 1 || seen["mqtt_usr"] != 1 ||
        seen["mqtt_passwd"] != 1) exit 14
}
' "$json_path" > "$tmp" || fail 'expected one standalone line for each of five fields'

if "$bb" cmp -s "$json_path" "$tmp"; then
    printf 'Fields already match; source unchanged\n'
    exit 0
fi

if [ "$reuse_backup" -eq 0 ]; then
    [ ! -e "$backup" ] && [ ! -L "$backup" ] || fail 'rollback copy appeared during edit'
    "$bb" cp -p "$json_path" "$backup" || fail 'could not create rollback copy'
    "$bb" cmp -s "$json_path" "$backup" || fail 'rollback copy does not match source'
fi
"$bb" sync || fail 'could not flush staged file and rollback copy'
"$bb" mv -f "$tmp" "$json_path" || fail 'atomic replacement failed'
"$bb" sync || fail 'replacement committed but sync failed; inspect source and backup'
printf 'Changed five IoT fields; rollback copy saved next to source\n'
