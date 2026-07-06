# ClusterFuzzLite build image. Renovate manages the digest pin; the tag
# comment tracks which OSS-Fuzz base-builder-python release it maps to.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:fce2290f3c86b52b2196a7f50bc9144d7de2182d7635b1c24bf2121289231dc6

COPY . $SRC/compose-lint
WORKDIR $SRC/compose-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
