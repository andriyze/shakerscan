# Layer cache for the pull-request smoke build (.github/workflows/e2e-pr.yml).
#
# This bake builds nothing the smoke check uses directly. It runs before `./scanner.sh build` on
# the same Docker daemon, importing every layer whose inputs are unchanged from the GitHub Actions
# cache that main's image build (.github/workflows/_build-images.yml) keeps warm, so the complete
# `./scanner.sh build` that follows finds those layers locally instead of rebuilding them. The
# compose targets reuse docker-compose.yml's exact build definitions and arguments; the two stage
# targets warm the toolchain stages the Model Intake and API overlays build on top of the runtime.
#
# Release and candidate builds never read this file and keep building from their exact source.

variable "SMOKE_CACHE_WRITE" {
  default = "false"
}

# Read main's per-image cache and this pull request's own smoke entries.
function "cache_from" {
  params = [image]
  result = [
    "type=gha,scope=${image}-linux-amd64",
    "type=gha,scope=smoke-${image}",
  ]
}

# One shard writes this pull request's entries, so a change to a heavy layer is built once per
# pull request rather than on every push.
function "cache_to" {
  params = [image]
  result = SMOKE_CACHE_WRITE == "true" ? ["type=gha,mode=max,scope=smoke-${image},ignore-error=true"] : []
}

group "smoke-cache" {
  targets = ["worker", "ui", "model-intake-signer", "model-intake-toolchain", "api-posture-engine"]
}

target "worker" {
  cache-from = cache_from("scanner")
  cache-to   = cache_to("scanner")
}

target "ui" {
  cache-from = cache_from("ui")
  cache-to   = cache_to("ui")
}

target "model-intake-signer" {
  cache-from = cache_from("signer")
  cache-to   = cache_to("signer")
}

target "model-intake-toolchain" {
  context    = "."
  dockerfile = "scanner/Dockerfile.model-intake"
  target     = "model-intake-go-tools"
  tags       = ["shakerscan-smoke-cache/model-intake-go-tools:local"]
  cache-from = cache_from("model-intake")
  cache-to   = cache_to("model-intake")
}

target "api-posture-engine" {
  context    = "."
  dockerfile = "scanner/Dockerfile.api"
  target     = "posture-engine"
  tags       = ["shakerscan-smoke-cache/api-posture-engine:local"]
  cache-from = cache_from("api")
  cache-to   = cache_to("api")
}
