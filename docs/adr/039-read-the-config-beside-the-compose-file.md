# ADR-039: Read the Config Beside the Compose File

**Status:** Accepted

**Context:** An implicit run (no `--config`) read `.compose-lint.yml` from the
working directory only. Compose does not work that way: it takes the first
compose file's directory as the project directory. So
`compose-lint app/docker-compose.yml`, run from a repository root as CI and
pre-commit do, ignored `app/.compose-lint.yml` and reported every finding its
author had suppressed.

The fix for that was a stderr notice (#625): on any failing `check`, or any
`fix` with something to change, with no config loaded, print
`Note: no .compose-lint.yml or .compose-lint.yaml found in '<cwd>' — all rules
are enabled and no suppressions are in effect.` It could not tell a config
that was never found from one that was never written, so it printed on the
most common run there is: a first run, by someone who has never heard of the
config file and has nothing to act on. For that reader it reads as a fault,
and possibly as the reason the run failed. It also crowded the README casts
by a row each.

**Decision:**

1. An implicit run looks for `.compose-lint.yml`, then `.compose-lint.yaml`,
   in the directory of the first Compose file it lints, and then in the
   working directory. The first directory holding either name wins; both
   names in that one directory keep the existing both-spellings diagnostic.
   Parent directories are not searched. `--config` is unchanged.
2. The no-config notice is removed. The banner already names the file read,
   or `config: none`, on every text run, which is the place a reader looks
   when suppressed findings come back. The Docker case #625 described —
   mounting only the Compose file — is documented beside the mount recipe in
   [configuration.md](../configuration.md).
3. The working directory's own config keeps the working-directory boundary
   it always had. One found beside the Compose file is contained the way every
   other file that Compose file leads to is ([ADR-038](038-contain-references-to-the-repository.md)):
   to the repository holding it, else the run directory when that holds it,
   else its own directory — so `../other/.compose-lint.yml` and a config under
   a linked project directory load, and a link out of the repository is still
   refused.
4. `init FILE` writes its baseline where `check` reads first: beside `FILE`.
   An existing config of either spelling there is the target, so the
   "already exists" guard sees it. `-o` still overrides. When the new file
   takes over from a config in the working directory, `init` says so on
   stderr: configs do not merge, so that config's suppressions stop applying
   to the project — the one case where something the user set up stops
   applying, and so the one case worth a line.

**Consequences:**

- A config beside the Compose file now applies where it used to be ignored.
  This is the one behaviour change for existing setups: a repository with a
  config both at its root and beside a Compose file it lints from the root
  now gets the nearer one. The banner names which.
- A config at the working directory still covers Compose files in
  subdirectories that have none of their own, so a single root config keeps
  working.
- One run linting files from several directories reads one config, chosen by
  the first file, as Compose chooses one project directory. A per-file config
  is not attempted.
- `init` run from a repository root on a project below it now writes into
  the project directory instead of refusing because the root config exists.
- Suppression reasons name the config as found (`app/.compose-lint.yml`)
  rather than its bare name, so a reader can tell which file disabled a rule.
