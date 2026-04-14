# syntax=docker/dockerfile:1
# Build: docker build -t composelint/compose-lint .
# Run:   docker run --rm -v "$(pwd):/src" composelint/compose-lint

# --- build stage: wheel only, no dev deps ---
FROM python:3.14-alpine@sha256:01f125438100bb6b5770c0b1349e5200b23ca0ae20a976b5bd8628457af607ae AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir build~=1.0 \
    && python -m build --wheel --outdir /dist

# --- runtime stage: minimal install ---
FROM python:3.14-alpine@sha256:01f125438100bb6b5770c0b1349e5200b23ca0ae20a976b5bd8628457af607ae
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
