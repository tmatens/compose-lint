# syntax=docker/dockerfile:1
# Build: docker build -t composelint/compose-lint .
# Run:   docker run --rm -v "$(pwd):/src" composelint/compose-lint

# --- build stage: wheel only, no dev deps ---
FROM python:3.13-alpine@sha256:70dd89363f8665af9a8076ef505bfd8b8bf2fb0b3ab45860cd3494ab7197fe73 AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir build~=1.0 \
    && python -m build --wheel --outdir /dist

# --- runtime stage: minimal install ---
FROM python:3.13-alpine@sha256:70dd89363f8665af9a8076ef505bfd8b8bf2fb0b3ab45860cd3494ab7197fe73
LABEL org.opencontainers.image.title="compose-lint" \
      org.opencontainers.image.description="Security-focused linter for Docker Compose files" \
      org.opencontainers.image.url="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.source="https://github.com/tmatens/compose-lint" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /dist /dist
RUN pip install --no-cache-dir /dist/*.whl \
    && rm -rf /dist
# Non-root user; /src is the default working directory for mounted compose files
RUN adduser -D -h /src linter
USER linter
WORKDIR /src
ENTRYPOINT ["compose-lint"]
