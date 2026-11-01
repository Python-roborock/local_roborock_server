#!/usr/bin/env bash
# Build the checked-out commit and update one existing Compose service in place.
# Reuses its configuration, mounts, certificates and credentials. No backups.
set -Eeuo pipefail

repo=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
runtime=${ROBOROCK_RUNTIME_DIR:-/opt/local_roborock_server}
container=${ROBOROCK_CONTAINER_NAME:-roborock-local-server}

fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
trap 'printf "\nUpdate stopped at line %s. Review the error above.\n" "$LINENO" >&2' ERR
for program in git docker python3 sudo; do
    command -v "$program" >/dev/null || fail "Missing command: $program"
done
revision=$(git -C "$repo" rev-parse --verify HEAD)
git -C "$repo" diff --quiet || fail 'Commit or resolve tracked local changes before updating.'
git -C "$repo" diff --cached --quiet || fail 'Commit or resolve staged changes before updating.'
sudo -v
sudo docker compose version >/dev/null
sudo docker inspect "$container" >/dev/null

label() {
    sudo docker inspect --format "{{ index .Config.Labels \"$1\" }}" "$container"
}
project=$(label com.docker.compose.project)
service=$(label com.docker.compose.service)
project_dir=$(label com.docker.compose.project.working_dir)
config_files=$(label com.docker.compose.project.config_files)
environment_files=$(label com.docker.compose.project.environment_file)
server_image=$(sudo docker inspect --format '{{.Config.Image}}' "$container")
for value in "$project" "$service" "$project_dir" "$config_files"; do
    [[ -n "$value" && "$value" != '<no value>' ]] || fail 'The running container does not identify its Compose configuration.'
done
[[ -d "$project_dir" ]] || fail "Compose working directory is missing: $project_dir"
[[ "$server_image" != *@sha256:* && "$server_image" != sha256:* ]] || fail 'The existing image needs a tag before it can be rebuilt.'

compose_args=(--project-name "$project" --project-directory "$project_dir")
if [[ -n "$environment_files" && "$environment_files" != '<no value>' ]]; then
    IFS=',' read -r -a env_paths <<< "$environment_files"
    for env_path in "${env_paths[@]}"; do
        [[ "$env_path" = /* ]] || env_path="$project_dir/$env_path"
        sudo test -r "$env_path" || fail "Missing Compose environment file: $env_path"
        compose_args+=(--env-file "$env_path")
    done
elif sudo test -r "$runtime/.env"; then
    compose_args+=(--env-file "$runtime/.env")
fi
IFS=',' read -r -a compose_paths <<< "$config_files"
for compose_path in "${compose_paths[@]}"; do
    [[ "$compose_path" = /* ]] || compose_path="$project_dir/$compose_path"
    sudo test -r "$compose_path" || fail "Missing Compose file: $compose_path"
    compose_args+=(-f "$compose_path")
done
configured_image=$(
    sudo docker compose "${compose_args[@]}" config --format json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["services"][sys.argv[1]].get("image", ""))' "$service"
)
[[ "$configured_image" = "$server_image" ]] || fail "Compose image ($configured_image) differs from the running image ($server_image). Nothing has been restarted."

printf '\nBuilding revision %s. Your current server keeps running during the build.\n' "$revision"
git -C "$repo" archive --format=tar "$revision" |
    sudo docker build --label "org.opencontainers.image.revision=$revision" -t "$server_image" -

printf '\nRestarting the server with the new image…\n'
sudo docker compose "${compose_args[@]}" up -d --no-deps --no-build --pull never --force-recreate "$service"

printf '\nWaiting for the server health check…\n'
for attempt in {1..75}; do
    state=$(sudo docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container")
    if [[ "$state" = healthy ]]; then
        printf '%s\n' "$revision" | sudo tee "$runtime/SOURCE_COMMIT" >/dev/null
        printf '\nUpdate complete: %s\nRefresh your server’s /admin page and open Schedules.\n' "$revision"
        exit 0
    fi
    if [[ "$state" = exited || "$state" = dead || "$state" = unhealthy ]]; then
        fail "Container state: $state. Inspect with: sudo docker logs --tail 80 $container"
    fi
    sleep 2
done
fail "The container did not become healthy in time. Inspect with: sudo docker logs --tail 80 $container"
