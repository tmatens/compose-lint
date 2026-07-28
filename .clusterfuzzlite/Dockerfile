# ClusterFuzzLite build image. Renovate manages the digest pin; the tag
# comment tracks which OSS-Fuzz base-builder-python release it maps to.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:093721649cdd0d15c1e97eb905ed94079c09ffc8b3341c5dc42957b92f1b388f

COPY . $SRC/compose-lint
WORKDIR $SRC/compose-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
