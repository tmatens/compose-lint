# ADR-034: `--explain` Pages Through a Pager on an Interactive Terminal

**Status:** Accepted

**Context:** `--explain CL-XXXX` dumps the rule's full markdown doc to
stdout. The docs have grown past 100 lines (CL-0001 is 115), so on an
interactive terminal the top of the doc — the directive and the
why-it-matters prose, the strongest content — scrolls out of view instantly
and the reader lands on the tail. The README hero GIF captured this
faithfully: the recorded `--explain` step shows a single-frame whoosh and
settles on the ATT&CK table. The GIF is a symptom; the terminal UX is the
problem.

The constraint is [the CLI output contract](../../AGENTS.md): stdout carries
data, and `--explain` prints the doc raw — machine consumers pipe it, tests
byte-compare it, and `fix`/CI never touch a pager.

**Decision:** When stdout is a TTY, `--explain` pipes the doc through a
pager, exactly the way `git log` does; in every other case the output is
byte-identical to before. The gate, in order:

- not a TTY → plain dump (pipes, redirects, CI, tests — by construction,
  not by configuration);
- `NO_PAGER` set (any non-empty value) → plain dump, mirroring `NO_COLOR`'s
  contract for color;
- `TERM` unset or `dumb` → plain dump;
- `--no-pager` → plain dump;
- `PAGER` set → that command (split with `shlex`; blank disables), else
  `less -RFX` (`-F` exits when the doc fits one screen, so short docs never
  trap the reader; `-X` keeps the tail in scrollback) plus a labeled status
  prompt — `-Ps"CL-XXXX · Space next · b back · q quit"` — because the
  pager's controls are pure convention and the bare `:` labels none of
  them. The prompt rides only on the default pager; a user's own `PAGER`
  keeps whatever prompt they configured.

A pager that cannot be spawned falls back silently to the plain dump. That
case is real, not defensive: the published image is distroless, so
`docker run -t` produces a TTY with no pager binary behind it — the
fallback is what keeps that invocation working unchanged. A pager that
exits nonzero falls back the same way: busybox's `less` (Alpine) rejects
`-Ps` with a usage error, and without the rescue that rejection would
swallow the doc. The cost is bounded — a pager dying nonzero after showing
content prints the doc twice, never zero times.

**Consequences:** Non-TTY output is untouched, so the stdout-carries-data
contract and every existing consumer are unaffected; the tests prove the
piped bytes identical with and without a pager configured. A human at a
terminal reads the doc top-down. The change is presentation only and ships
as MINOR. The paging applies to `--explain` alone — the findings report
stays unpaged, because a lint run's verdict belongs in the scrollback of
the command that produced it, not behind a `q`.

**Amendment (rendered on a terminal):** a terminal now gets the rule doc
rendered, not raw: `_terminal_markdown.py` strips the markdown markup, styles
headings, bold, code and links, lines up tables, and re-wraps prose to the
terminal (at most 100 columns). It applies whenever stdout is a terminal,
including the cases above that print a plain dump instead of paging
(`--no-pager`, `NO_PAGER`, `TERM=dumb`, a missing pager); color follows the
`NO_COLOR`/`FORCE_COLOR` rules every other output uses. The guarantee this ADR
made for everything that is not a terminal is unchanged: piped and redirected
output is the doc's raw markdown, byte for byte. The renderer covers the
markdown the rule docs use and no more, so it adds no runtime dependency;
`tests/test_terminal_markdown.py` renders every shipped doc and fails on any
marker left behind, including syntax the renderer does not handle.
