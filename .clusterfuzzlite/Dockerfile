# ClusterFuzzLite build image. Renovate manages the digest pin; the tag
# comment tracks which OSS-Fuzz base-builder-python release it maps to.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:8d46cb51bc42b45eeaa80b132a235f60a79154c788fe17012847a35304d8b804

COPY . $SRC/compose-lint
WORKDIR $SRC/compose-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
