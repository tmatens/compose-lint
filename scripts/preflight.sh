#!/usr/bin/env bash
# Run every gate a pull request faces, from this checkout, in one command.
#
# CI grades a PR on eleven things — ruff, ruff format, mypy, the test suite,
# the statement-coverage floor, patch coverage, and five checks on the commits
# themselves (signature, DCO trailer, no AI attribution, subject length, no
# Conventional Commits prefix). CONTRIBUTING lists them across four sections,
# and the pre-push hook that catches the commit ones is opt-in. In practice a
# first PR here fails on one of the commit checks, not on code: of the last
# seven external PRs, three lost a round to a Signed-off-by trailer that was
# absent or carried a different email than the author (#675, #685, #726), and
# one to a subject prefix — every one a rule that was written down and still
# not caught until CI, hours later, after a maintainer approved the run.
#
# This script is what CI runs, in the order CI runs it, with the same
# commands, so a green preflight is a green PR. It runs every gate rather than
# stopping at the first failure, and prints one summary at the end, so one
# pass shows everything that needs fixing.
#
# Usage:
#   scripts/preflight.sh            # everything CI checks
#   scripts/preflight.sh --quick    # skip the test suite and coverage gates
#
# The commits checked are the ones on this branch that are not on the base.
# The base is upstream/main when an `upstream` remote exists, else
# origin/main: on a fork, `origin` is your copy and its `main` is frozen at
# whatever it held when you forked, so it is the wrong base (#685).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

quick=0
case "${1:-}" in
  --quick) quick=1 ;;
  "") ;;
  *) printf 'usage: %s [--quick]\n' "$0" >&2; exit 2 ;;
esac

# ---- tools ------------------------------------------------------------------

# CI installs the pinned dev environment and calls the tools bare; locally
# that means an activated venv. If the repo's .venv exists and is not already
# first on PATH, put it there — a machine-global mypy or a pytest without
# pytest-cov reports failures that have nothing to do with your change.
if [ -x .venv/bin/python ] && [ "$(command -v python || true)" != "${PWD}/.venv/bin/python" ]; then
  export PATH="${PWD}/.venv/bin:${PATH}"
fi
printf 'python: %s\n' "$(command -v python)"
for tool in ruff mypy pytest; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'missing %s: install the dev environment first (CONTRIBUTING.md "Development setup")\n' "${tool}" >&2
    exit 2
  fi
done

# ---- base -------------------------------------------------------------------

if git remote get-url upstream >/dev/null 2>&1; then
  base_remote=upstream
else
  base_remote=origin
fi
if ! git fetch -q "${base_remote}" main 2>/dev/null; then
  printf 'note: could not fetch %s; comparing against the last-known %s/main\n' \
    "${base_remote}" "${base_remote}"
fi
base="$(git merge-base HEAD "${base_remote}/main")"
range="${base}..HEAD"
printf 'base: %s/main (%s), %s commit(s) on this branch\n' \
  "${base_remote}" "$(git rev-parse --short "${base}")" "$(git rev-list --count "${range}")"

# ---- gate runner ------------------------------------------------------------

results=()
failed=0
gate() {
  local name="$1"; shift
  printf '\n== %s\n' "${name}"
  if "$@"; then
    results+=("PASS  ${name}")
  else
    results+=("FAIL  ${name}")
    failed=1
  fi
}

# ---- code gates (ci.yml: lint, type-check, test, coverage) ------------------

gate "ruff check"        ruff check src/ tests/
gate "ruff format"       ruff format --check src/ tests/
gate "mypy"              mypy src/ tests/

coverage_run() {
  # CI measures the subprocesses test_cli.py and test_integration.py spawn
  # by installing a .pth that calls coverage.process_startup() in every
  # interpreter. A sitecustomize on PYTHONPATH does the same without writing
  # into site-packages; pyproject's `parallel = true` merges the data files.
  local shim
  shim="$(mktemp -d)"
  printf 'import coverage\ncoverage.process_startup()\n' > "${shim}/sitecustomize.py"
  PYTHONPATH="${shim}${PYTHONPATH:+:${PYTHONPATH}}" \
  COVERAGE_PROCESS_START="${PWD}/pyproject.toml" \
    pytest --cov=compose_lint --cov-report=term --cov-report=xml --cov-fail-under=80
}

patch_coverage() {
  if [ ! -f coverage.xml ]; then
    printf '  no coverage.xml - the test gate above did not produce one\n'
    return 1
  fi
  python .github/scripts/patch-coverage.py --base-sha "${base}" --fail-under 90
}

if [ "${quick}" -eq 0 ]; then
  gate "pytest + coverage floor (>= 80% statement)" coverage_run
  gate "patch coverage (>= 90% of the lines you changed)" patch_coverage
else
  printf '\n== pytest / coverage: skipped (--quick)\n'
fi

# ---- commit gates (ci.yml: dco, no-ai-attribution; .githooks/pre-push) -----

# Bot commits cannot sign or sign off; CI allow-lists them the same way.
bot_pattern='(dependabot|renovate|github-actions|mend)\[bot\]'

commits_signed() {
  # Presence is read off the commit object's `gpgsig` header rather than
  # %G?, which needs gpg on PATH and your own key in a local allowed_signers
  # file before it says anything but N — the pre-push hook's %G? != G test
  # fails a correctly signed commit on a machine that simply cannot verify
  # it. Verifying is GitHub's job, against the keys on your account; what
  # can be checked here is that a signature exists, and that git does not
  # call it bad (B) where it can verify.
  local ok=1 sha status
  while read -r sha status; do
    if ! git cat-file commit "${sha}" | grep -q '^gpgsig '; then
      printf '  %s  unsigned: %s\n' "${sha:0:7}" "$(git log -1 --format=%s "${sha}")"
      ok=0
    elif [ "${status}" = "B" ]; then
      printf '  %s  BAD signature: %s\n' "${sha:0:7}" "$(git log -1 --format=%s "${sha}")"
      ok=0
    fi
  done < <(git log --no-merges --format='%H %G?' "${range}" 2>/dev/null)
  [ "${ok}" -eq 1 ] || printf '  see CONTRIBUTING.md "Commit signing"\n'
  [ "${ok}" -eq 1 ]
}

commits_signed_off() {
  # Mirrors ci.yml's dco job: the trailer must match the author's name AND
  # email exactly. A trailer with a different address is the most common
  # failure on external PRs, and "missing" is the wrong word for it, so the
  # trailers that are present are shown next to the one expected.
  local ok=1 sha author_name author_email expected message found
  while IFS=$'\t' read -r sha author_name author_email; do
    if printf '%s' "${author_name}${author_email}" | grep -iqE "${bot_pattern}"; then
      continue
    fi
    expected="Signed-off-by: ${author_name} <${author_email}>"
    message="$(git log -1 --format='%B' "${sha}")"
    if printf '%s\n' "${message}" | grep -qiF "${expected}"; then
      continue
    fi
    ok=0
    printf '  %s  %s\n' "${sha:0:7}" "$(git log -1 --format=%s "${sha}")"
    printf '    expected: %s\n' "${expected}"
    found="$(printf '%s\n' "${message}" | grep -i '^[[:space:]]*Signed-off-by:' || true)"
    if [ -z "${found}" ]; then
      printf '    found:    (none - this commit has no Signed-off-by trailer)\n'
    else
      printf '%s\n' "${found}" | while IFS= read -r line; do
        printf '    found:    %s\n' "${line#"${line%%[![:space:]]*}"}"
      done
    fi
  done < <(git log --no-merges --format='%H%x09%an%x09%ae' "${range}")
  if [ "${ok}" -eq 0 ]; then
    printf '  fix the last commit with: git commit --amend --signoff\n'
    printf '  or every commit with:     git rebase --signoff %s\n' "$(git rev-parse --short "${base}")"
    printf '  then: git push --force-with-lease   (not the "Update branch" button)\n'
  fi
  [ "${ok}" -eq 1 ]
}

commits_without_ai_attribution() {
  # Mirrors ci.yml's no-ai-attribution job, same pattern.
  local pattern bad
  pattern='co-authored-by:.*(claude|anthropic|@anthropic\.com)|generated (by|with) (claude|anthropic|ai)|🤖 generated'
  bad="$(git log --format='%H%n%B%n--END--' "${range}" \
    | awk -v RS='--END--' -v pat="${pattern}" 'tolower($0) ~ pat { print substr($0, 1, 40) }')"
  if [ -n "${bad}" ]; then
    printf '%s\n' "${bad}" | while read -r sha; do
      [ -n "${sha}" ] && printf '  %s  %s\n' "${sha:0:7}" "$(git log -1 --format=%s "${sha}")"
    done
    printf '  CONTRIBUTING.md: no AI credit lines in commit messages; say it in the PR Origin section instead\n'
    return 1
  fi
}

commit_subjects() {
  # CONTRIBUTING "Commit conventions": imperative subject under 72 characters,
  # no Conventional Commits prefix. Reviewed by hand until now (#726).
  local ok=1 sha subject
  while IFS=$'\t' read -r sha subject; do
    if [ "${#subject}" -ge 72 ]; then
      printf '  %s  subject is %d characters (limit 72): %s\n' "${sha:0:7}" "${#subject}" "${subject}"
      ok=0
    fi
    if printf '%s' "${subject}" | grep -qiE '^(feat|fix|chore|docs|refactor|test|tests|ci|build|perf|style|revert)(\([^)]*\))?!?:'; then
      printf '  %s  Conventional Commits prefix; use a plain imperative subject: %s\n' "${sha:0:7}" "${subject}"
      ok=0
    fi
  done < <(git log --no-merges --format='%H%x09%s' "${range}")
  [ "${ok}" -eq 1 ]
}

gate "commits signed"                commits_signed
gate "commits signed off (DCO)"      commits_signed_off
gate "no AI attribution in commits"  commits_without_ai_attribution
gate "commit subjects"               commit_subjects

# ---- summary ----------------------------------------------------------------

printf '\n== summary\n'
printf '  %s\n' "${results[@]}"
if [ "${failed}" -eq 1 ]; then
  printf '\npreflight: FAIL - fix the items above before pushing\n'
  exit 1
fi
printf '\npreflight: PASS - this branch is ready to push\n'
