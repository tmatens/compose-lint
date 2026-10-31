# Compose Specification schema — licensing posture

`tests/data/compose-spec/compose-spec.json` is an unmodified copy of
`schema/compose-spec.json` from the
[Compose Specification](https://github.com/compose-spec/compose-spec), vendored
so that `tests/test_spec_round_trip.py` can hold `docs/compose-keys.md` to the
spec's key set without a network call. `tests/data/compose-spec/SOURCE` records
the upstream commit it was taken from; `compose-spec-bump.yml` refreshes it.

The Compose Specification is licensed under the Apache License, Version 2.0.
A copy of that license is at <https://www.apache.org/licenses/LICENSE-2.0>.
The file is redistributed here under that license, unchanged, with this notice.
It is test data only: it is not part of the `compose-lint` wheel and nothing
at runtime reads it. compose-lint itself remains MIT licensed (`LICENSE`).
