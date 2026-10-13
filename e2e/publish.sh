#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_EVENT_NAME:-}" != pull_request ]]
[[ "$GITHUB_REF" == refs/heads/main || "$GITHUB_REF" == refs/tags/v* ]]
repository="${GITHUB_REPOSITORY,,}"
registry="ghcr.io/$repository"
components=(controller agent derper)
mkdir -p publication

# 0=exists, 3=absent. Authorization, TLS and network errors are never absence.
inspect_ref() {
  local reference="$1" destination="$2"
  if docker buildx imagetools inspect "$reference" --format '{{json .Manifest}}' >"$destination" 2>"$destination.error"; then return 0; fi
  if grep -Eqi 'not found|manifest unknown|name unknown' "$destination.error"; then return 3; fi
  cat "$destination.error" >&2
  return 2
}
alias_digest() {
  local component="$1" tag="$2" digest="$3" mutable="$4" old status
  local target="$registry-$component:$tag" metadata="publication/$component-$tag-descriptor.json"
  if inspect_ref "$target" "$metadata"; then
    old="$(jq -er .digest "$metadata")" || return 1
    if [[ "$old" == "$digest" ]]; then return 0; fi
    if [[ "$mutable" != true ]]; then echo "Refusing to replace immutable $target ($old != $digest)" >&2; return 1; fi
  else
    status=$?; [[ "$status" == 3 ]] || return 1
  fi
  docker buildx imagetools create --prefer-index=false --tag "$target" "$registry-$component@$digest" || return 1
  inspect_ref "$target" "$metadata" || return 1
  [[ "$(jq -er .digest "$metadata")" == "$digest" ]] || return 1
  printf 'Promoted %s -> %s\n' "$target" "$digest"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then printf '\n%s -> %s\n' "$target" "$digest" >>"$GITHUB_STEP_SUMMARY"; fi
}
validate_index() {
  jq -e '(.manifests|length)==2 and any(.manifests[]; .platform.os=="linux" and .platform.architecture=="amd64") and any(.manifests[]; .platform.os=="linux" and .platform.architecture=="arm64")' "$1" >/dev/null
}

case "$1" in
  upload)
    [[ "$GITHUB_REF" == refs/heads/main ]]
    result="publication/pushed-$IMAGE_ARCH.jsonl"
    : >"$result"
    docker load -i "images-$IMAGE_ARCH.tar"
    for component in "${components[@]}"; do
      image="derpers-$component:$GITHUB_SHA-$IMAGE_ARCH"
      [[ "$(docker image inspect "$image" --format '{{.Architecture}}')" == "$IMAGE_ARCH" ]]
      [[ "$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')" == "$GITHUB_SHA" ]]
      # Run-specific staging tags cannot replace the immutable commit manifest.
      target="$registry-$component:ci-$GITHUB_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$IMAGE_ARCH"
      docker tag "$image" "$target"
      docker push "$target"
      digest="$(docker buildx imagetools inspect "$target" --format '{{json .Manifest}}' | jq -er .digest)"
      [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
      source_id="$(docker image inspect "$image" --format '{{.Id}}')"
      remote_config="$(docker buildx imagetools inspect --raw "$registry-$component@$digest" | jq -er '.config.digest')"
      [[ "$remote_config" == "$source_id" ]]
      jq -nc --arg component "$component" --arg manifest "$digest" --arg config "$source_id" --arg revision "$GITHUB_SHA" --arg arch "$IMAGE_ARCH" '{component:$component,manifest:$manifest,config:$config,revision:$revision,arch:$arch}' >>"$result"
    done
    jq -s . "$result" >"publication/pushed-$IMAGE_ARCH.json"
    ;;
  manifests)
    [[ "$GITHUB_REF" == refs/heads/main ]]
    for component in "${components[@]}"; do
      amd64="$(jq -er --arg component "$component" --arg revision "$GITHUB_SHA" '.[] | select(.component==$component and .revision==$revision and .arch=="amd64") | .manifest' publication/pushed-amd64.json)"
      arm64="$(jq -er --arg component "$component" --arg revision "$GITHUB_SHA" '.[] | select(.component==$component and .revision==$revision and .arch=="arm64") | .manifest' publication/pushed-arm64.json)"
      [[ "$amd64" =~ ^sha256:[a-f0-9]{64}$ && "$arm64" =~ ^sha256:[a-f0-9]{64}$ ]]
      candidate="$registry-$component:ci-$GITHUB_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
      docker buildx imagetools create --tag "$candidate" "$registry-$component@$amd64" "$registry-$component@$arm64"
      docker buildx imagetools inspect "$candidate" --format '{{json .Manifest}}' >"publication/$component-index-descriptor.json"
      validate_index "publication/$component-index-descriptor.json"
      jq -e --arg amd64 "$amd64" --arg arm64 "$arm64" 'any(.manifests[]; .platform.architecture=="amd64" and .digest==$amd64) and any(.manifests[]; .platform.architecture=="arm64" and .digest==$arm64)' "publication/$component-index-descriptor.json" >/dev/null
      index_digest="$(jq -er .digest "publication/$component-index-descriptor.json")"
      alias_digest "$component" "sha-$GITHUB_SHA" "$index_digest" false
      # Older queued main runs may retain their sha tag, but must not move edge.
      current_main="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)"
      if [[ "$current_main" == "$GITHUB_SHA" ]]; then alias_digest "$component" edge "$index_digest" true; else printf 'Skip edge: main is now %s\n' "$current_main"; fi
    done
    ;;
  promote)
    [[ "$GITHUB_REF" == refs/tags/v* ]]
    version="${GITHUB_REF#refs/tags/}"
    node e2e/version.mjs validate "$version"
    [[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]
    git merge-base --is-ancestor HEAD origin/main
    gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs" -f head_sha="$GITHUB_SHA" -f branch=main -f event=push -f status=completed -f per_page=100 >publication/main-ci-runs.json
    jq -e --arg sha "$GITHUB_SHA" --arg repository "$GITHUB_REPOSITORY" 'any(.workflow_runs[]; .head_sha==$sha and .head_branch=="main" and .event=="push" and .conclusion=="success" and .head_repository.full_name==$repository)' publication/main-ci-runs.json >/dev/null
    # Every source must already be a successfully tested main commit manifest.
    for component in "${components[@]}"; do
      inspect_ref "$registry-$component:sha-$GITHUB_SHA" "publication/$component-release-source.json"
      validate_index "publication/$component-release-source.json"
      while IFS= read -r native_digest; do
        docker buildx imagetools inspect "$registry-$component@$native_digest" --format '{{json .Image}}' | jq -e --arg sha "$GITHUB_SHA" '.config.Labels["org.opencontainers.image.revision"]==$sha' >/dev/null
      done < <(jq -r '.manifests[].digest' "publication/$component-release-source.json")
    done
    # Resolve the current latest revision back to this repository's stable tags.
    # The publication mutex protects all latest writes; all three are checked first.
    update_latest=true
    if [[ "$version" == *-* ]]; then update_latest=false; else
      for component in "${components[@]}"; do
        if inspect_ref "$registry-$component:latest" "publication/$component-previous-latest.json"; then
          validate_index "publication/$component-previous-latest.json"
          native_digest="$(jq -er '.manifests[] | select(.platform.architecture=="amd64") | .digest' "publication/$component-previous-latest.json")"
          latest_revision="$(docker buildx imagetools inspect "$registry-$component@$native_digest" --format '{{json .Image}}' | jq -er '.config.Labels["org.opencontainers.image.revision"]')"
          [[ "$latest_revision" =~ ^[a-f0-9]{40}$ ]]
          mapfile -t current_tags < <(git tag --points-at "$latest_revision" | grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || true)
          if [[ "${#current_tags[@]}" == 0 ]]; then echo "Cannot determine previous latest SemVer; refusing promotion" >&2; exit 1; fi
          current_version="$(node e2e/version.mjs max "${current_tags[@]}")"
          if node e2e/version.mjs ge "$version" "$current_version"; then :; else
            status=$?; [[ "$status" == 1 ]]
            update_latest=false
            printf 'Keep latest at %s; requested release %s is older\n' "$current_version" "$version"
          fi
        else
          status=$?; [[ "$status" == 3 ]]
        fi
      done
    fi
    for component in "${components[@]}"; do
      digest="$(jq -er .digest "publication/$component-release-source.json")"
      alias_digest "$component" "$version" "$digest" false
      if [[ "$update_latest" == true ]]; then alias_digest "$component" latest "$digest" true; fi
    done
    ;;
  *) echo 'usage: publish.sh upload|manifests|promote' >&2; exit 2;;
esac
