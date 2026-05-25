# ClusterFuzzLite build image. Renovate manages the digest pin; the tag
# comment tracks which OSS-Fuzz base-builder-python release it maps to.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:3dbcb2fba5b92507146862ff7cd612908430137e60a112fd6425240163649a31

COPY . $SRC/compose-lint
WORKDIR $SRC/compose-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
