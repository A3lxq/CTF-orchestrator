#!/usr/bin/env bash
# Builds every CTF box image this orchestrator's specs expect
# (orchestrator/boxes/specs/*.yaml), plus pulls the two extra images
# Legendary's nested Docker daemon needs preloaded (see
# orchestrator/boxes/specs/legendary-ferrymans-relay.yaml's
# nested_docker.extra_preload_images -- that nested daemon has no
# internet egress, so alpine must already be present, not pulled live).
#
# Single-host boxes have boxes-src/<box_id>/docker/Dockerfile directly
# and build ONE image, ctf-boxes/<box_id>:latest. Multi-host boxes have
# boxes-src/<box_id>/docker/<service>/Dockerfile, one per service, and
# build one image per service, ctf-boxes/<box_id>-<service>:latest --
# matching exactly how each box's spec YAML names its own `image:` field.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

built=()
failed=()

for box_dir in boxes-src/*/; do
    box_id="$(basename "$box_dir")"

    if [[ -f "${box_dir}docker/Dockerfile" ]]; then
        tag="ctf-boxes/${box_id}:latest"
        echo "==> Building ${tag}"
        if docker build -f "${box_dir}docker/Dockerfile" -t "$tag" "$box_dir"; then
            built+=("$tag")
        else
            failed+=("$tag")
        fi
    else
        for dockerfile in "${box_dir}"docker/*/Dockerfile; do
            [[ -f "$dockerfile" ]] || continue
            service="$(basename "$(dirname "$dockerfile")")"
            tag="ctf-boxes/${box_id}-${service}:latest"
            echo "==> Building ${tag}"
            if docker build -f "$dockerfile" -t "$tag" "$box_dir"; then
                built+=("$tag")
            else
                failed+=("$tag")
            fi
        done
    fi
done

echo "==> Pulling ctf-boxes/legendary-ferrymans-relay's nested-daemon prerequisites"
for image in docker:27-dind alpine:latest; do
    echo "    pulling ${image}"
    if docker pull "$image" > /dev/null; then
        built+=("$image")
    else
        failed+=("$image")
    fi
done

echo
echo "==================== build_boxes.sh summary ===================="
printf 'Built/pulled (%d):\n' "${#built[@]}"
printf '  %s\n' "${built[@]}"
if ((${#failed[@]} > 0)); then
    printf 'FAILED (%d):\n' "${#failed[@]}"
    printf '  %s\n' "${failed[@]}"
    exit 1
fi
echo "All images built/pulled successfully."
