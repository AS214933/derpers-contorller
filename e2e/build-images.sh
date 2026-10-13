#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
source deploy/images.env
set +a
export IMAGE_TAG="${IMAGE_TAG:-test}"
revision="$(git rev-parse HEAD 2>/dev/null || printf local)"
labels=(--label org.opencontainers.image.source=https://github.com/AS214933/derpers-contorller --label "org.opencontainers.image.revision=$revision" --label "org.opencontainers.image.version=$IMAGE_TAG")
docker build -f Dockerfile --target controller "${labels[@]}" -t "derpers-controller:$IMAGE_TAG" .
docker build -f Dockerfile --target agent "${labels[@]}" -t "derpers-agent:$IMAGE_TAG" .
docker build -f Dockerfile.derper --target derper "${labels[@]}" -t "derpers-derper:$IMAGE_TAG" .
docker build -f Dockerfile.derper --target e2e-client "${labels[@]}" -t "derpers-e2e-client:$IMAGE_TAG" .
if [[ -n "${IMAGE_ARCHIVE:-}" ]]; then
  docker save -o "$IMAGE_ARCHIVE" "derpers-controller:$IMAGE_TAG" "derpers-agent:$IMAGE_TAG" "derpers-derper:$IMAGE_TAG" "derpers-e2e-client:$IMAGE_TAG"
fi
