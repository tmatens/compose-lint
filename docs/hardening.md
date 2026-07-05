# Running with full hardening

The compose-lint Docker image is safe-by-default (distroless, nonroot, read-only attack surface), so the simple `docker run --rm -v "$(pwd):/src" composelint/compose-lint` form is fine for most use.

If you want to dogfood compose-lint's own rules against the container that runs it, the fully-hardened invocation is:

```bash
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --network none \
  --user 65532:65532 \
  --pids-limit 256 \
  -v "$(pwd):/src:ro" \
  composelint/compose-lint:0.13.0
```

| Flag | Rule satisfied |
|---|---|
| `--security-opt no-new-privileges:true` | CL-0003 |
| `--cap-drop ALL` | CL-0006 |
| `--read-only` | CL-0007 |
| `--pids-limit 256` | CL-0012 (defense-in-depth; rule fires only on `0`/`-1`) |
| `--user 65532:65532` | CL-0018 (matches the image's existing default) |

`--network none` and `:ro` on the bind mount are extra hardening — compose-lint never reaches the network and only reads its inputs.

For full supply-chain reproducibility (and to satisfy CL-0004 / CL-0019), replace the `:0.13.0` tag with a digest pin: `composelint/compose-lint@sha256:<digest>`. Get the current digest from [Docker Hub](https://hub.docker.com/r/composelint/compose-lint/tags) or with `docker buildx imagetools inspect composelint/compose-lint:0.13.0 --format '{{json .Manifest}}' | jq -r '.digest'`.

A Compose-form equivalent that lints clean across every rule lives in [`tests/compose_files/safe_self_hosted.yml`](https://github.com/tmatens/compose-lint/blob/main/tests/compose_files/safe_self_hosted.yml).
