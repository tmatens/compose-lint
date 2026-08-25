# ADR-033: The Library Tree Is Root-Equivalent, Graded by Containment

**Status:** Proposed

**Context:** [#737](https://github.com/tmatens/compose-lint/issues/737) added
the host's executable tree to CL-0025 and deliberately left the **library
tree** out — `/lib/modules`, `/usr/lib`, `/lib`, `/lib64` — recording it as
deferred on the rule page and in the `ROOT_EQUIVALENT_PATHS` comment so the
gap would read as a disposition rather than an omission. This ADR is that
disposition.

The grant is real and the same shape as `/etc`'s. Measured on Docker 29.7.2
(Arch, merged-`/usr`), unprivileged, default capabilities, both legs:

| host path | rw bind | ro bind (control) |
|---|---|---|
| `/lib/modules` | WROTE | REFUSED |
| `/usr/lib` | WROTE | REFUSED |
| `/lib` | WROTE | REFUSED |
| `/lib64` | WROTE | REFUSED |

What a write there buys, with no further technique:

- **`/lib/modules/<release>/`** — the kernel loads modules from here by name,
  as root, on demand: udev, a network stack bringing up a protocol, the next
  boot. Replacing a module file the host will autoload is kernel-mode code
  execution on the host. `CAP_SYS_MODULE` (CL-0024) is *not* needed — the
  container only writes a file; the host does the loading.
- **`/usr/lib/systemd/system/`** (and `/lib/systemd/system/` on split-`/usr`
  hosts) — vendor unit files; a unit that runs on the next boot or timer.
  `/etc/systemd/system/` is already CL-0025's via `/etc`; this is the other
  half of the same directory pair.
- **`/usr/lib/x86_64-linux-gnu/`, `/usr/lib64/`, `ld.so` and friends** — every
  root process on the host links against these. `/etc/ld.so.preload` is
  already the canonical member of CL-0025's `/etc` grant; the libraries it
  preloads live here.

So the question was never *whether* these are root-equivalent. It was the
**match shape**, and the corpus decides it:

| corpus (5,417 files) | rw | ro | what they are |
|---|---:|---:|---|
| `/lib/modules` | 7 | 10 | all VPN / kernel-module workloads (WireGuard, strongSwan) |
| `/usr/lib` (any descendant) | 0 | 0 | — |
| `/lib`, `/lib64` bare | 0 | 0 | — |
| `/usr/local/lib/python3.9/dist-packages` | 1 | 0 | application data |

Matched **by descent**, `/usr/lib` would claim `/usr/lib/python3`,
`/usr/lib/node_modules`, `/usr/lib/jvm` — an application's own tree, on root's
`PATH` nowhere and executed by root never. That is the `/var/lib` containment
failure ([ADR-028](028-pre-1.0-rule-id-sweep.md); 24 of 25 hits were
`/var/lib/mysql`-shaped) and the `/usr` one (#737; 22% of naive-descent hits
were `/usr/src` and `/usr/share`). The rule's own words apply: root-equivalent
*because of what it contains, not because of what lies below it*.

`/lib/modules` is different: everything below it is a module the host may load,
so descent is the right match — and the 7 writable corpus binds are **true
positives**, not friction. The workload only needs to *read* the tree (measured:
`ls`, `find`, and module lookup all work through a `:ro` bind), so the fix the
finding names — add `:ro` — keeps every one of those seven working. That is the
CL-0029 `IPC_LOCK` test from ADR-028: a real grant with a correct, followable
fix is a finding users argue with, not a false positive.

**Decision:**

1. **Add to CL-0025, matched by descent:** `/lib/modules` and
   `/usr/lib/modules` (both spellings, as for the executable tree — matching is
   lexical on what the document wrote). Writable only; the grant is a file the
   host loads, so the `read-only` qualifier sends the same mount to nothing:
   modules are world-readable by design and a `:ro` bind discloses nothing.
   Exempt from CL-0013 as well, joining the executable tree in
   `EXEC_TREE_PATHS` (renamed to say what it now is, e.g. `WRITE_ONLY_GRANTS`).
2. **Add to CL-0025, matched exactly:** `/usr/lib`, `/lib`, `/lib64` — the
   `/var/lib` and `/usr` mechanism. `-v /usr/lib` reaches `systemd/system` and
   `ld.so`; `-v /usr/lib/python3` reaches an interpreter's site-packages and
   nothing the host runs as root. Zero corpus incidence in either shape, so no
   measured false-positive risk and no measured finding — the entries exist so
   a whole-tree bind is priced when it appears, as the `/var/lib` entry did.
3. **Do not add** `/usr/lib/systemd`, `/lib/systemd`, or the multiarch library
   directories by descent yet. Each is a genuine root primitive, but none has
   corpus incidence, the unit directories' `/etc` half is already graded, and
   the exact-match parent covers the whole-tree case. Revisit if they appear;
   the premise check below makes adding one a tuple entry plus a table row.
4. **Severity:** Direct × Host = CRITICAL, the existing CL-0025 cell; no
   override. New premise check `_cl0025_module_tree`: plant a file under
   `/lib/modules/<release>/` through an rw bind, observe from a second
   container, remove; the ro leg refuses. The kernel is never asked to load it.
5. **Release class:** new findings, MINOR, no runway
   ([ADR-031](031-severity-upgrades-are-minor-with-runway.md)). The changelog
   entry names the seven-service corpus impact and the one-token fix.

**Consequences:**

- Seven corpus services gain a CRITICAL whose fix is `:ro`. The linuxserver
  WireGuard template and its descendants are the main population; the finding's
  fix text should say "add `:ro` — the container only reads module files" ahead
  of "remove the mount", because for this member the first is the whole fix.
- CL-0025's read-only-exempt set stops being "the executable tree" and becomes
  "members whose grant is write-only" — the doc and the constant should say so.
- `tests/test_rule_membership.py::TestMountOwnership` gains the new members;
  `test_no_root_equivalent_entry_shadows_another` needs `/usr/lib/modules`
  (descent) checked against `/usr/lib` (exact) — the existing assertion that an
  exact member is unreachable by descent still holds, and the new assertion is
  that a descent member *under* an exact one resolves to itself.
- The general ancestor-aware matcher that `/var/lib`, `/usr` and now `/usr/lib`
  each work around is a third data point for building it. It still has to
  re-settle the CL-0001 boundary (`/` and `/var` contain the control socket) and
  remains out of scope here.

**Not decided here:** whether a *read-only* `/lib/modules` should carry a LOW
hygiene note (it hands the container the host's exact kernel build, which is
reconnaissance, not a grant). The severity model has no cell for disclosure of
non-secret state, and inventing one for this member would be the CL-0014
judgment path ADR-028 records as the exception, not the rule.
