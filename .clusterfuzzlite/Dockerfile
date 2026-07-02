# ClusterFuzzLite build image. Renovate manages the digest pin; the tag
# comment tracks which OSS-Fuzz base-builder-python release it maps to.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:53d5573ec78599bdb03dba1fea0b4d12855d126ffd0d02d1bc915da170675cf1

COPY . $SRC/compose-lint
WORKDIR $SRC/compose-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
