# ADR-018: Confidence as a multi-axis score, not a single scalar

**Status:** Accepted (amends [ADR-017 §4 Confidence](017-security-profile-catalog.md)).

**Context:** A profile's `derivation.confidence` is today a single scalar —
`high | moderate | low`. In practice that one word was being asked to answer four
different questions at once, and it answered only one of them:

1. **Was the experiment sound?** (leave-one-out drop-test, a discriminating
   correctness check, every granted element tested)
2. **Did the workload bound the image's feature surface?** (or only a subset)
3. **On what environment was it derived?** (kernel, cgroup version, confinement
   posture, runtime, userns)
4. **Was it observed in a real deployment, or only a synthetic lab run?**

`high` almost always meant "(1) yes" — a sound drop-test — while silently
implying "(2) yes" to a consumer who reads `high` as *this is my minimum*. Those
two claims come apart exactly when a feature was not exercised or the environment
differs.

**The receipt.** `netdata` was published at `confidence: high`. Its workload
asserted per-process metrics (so `SYS_PTRACE` was correctly kept) but never drove
per-container **network** metrics — whose collector enters container network
namespaces. `SYS_ADMIN` read as removable because that path was never exercised;
the `high` label hid the coverage gap entirely. (The removal turned out correct
anyway — netdata degrades to a privilege-free fallback — but only a *live
deployment* settled that, which is itself the point: see item 4.) A single scalar
had no way to say "sound experiment, partial coverage."

## Decision

Model confidence as **four orthogonal axes** plus a derived overall. The overall
is the **weakest link**, never an average — a profile is only as trustworthy as
its least-covered axis.

### The axes

| Axis | Question | Values |
|---|---|---|
| `rigor` | Was the drop-test experiment sound? | `high` / `moderate` / `low` |
| `coverage` | Did the workload bound the feature surface? | `bounded` / `partial` / `smoke` |
| `environment` | What was held fixed? (descriptive) | a record: kernel, cgroup, confinement, runtime, userns |
| `observation` | Lab run, or confirmed on a live deployment? | `lab` / `production` |

- **`rigor`** — `high`: leave-one-out drop-test; the correctness check asserts real
  *function* **and** the privilege drop (not a liveness endpoint); every granted
  element is a tested candidate (a non-empty `fixed` is already rejected by the
  producer). `moderate`: drop-test with a known check weakness. `low`:
  observation-only.
- **`coverage`** — `bounded`: the workload provably exercises everything that
  could need a privilege, so no unexercised path can raise the minimum. `partial`:
  an **unexercised feature could exercise a privileged operation** — a capability,
  device, namespace, or extra mount — beyond the derived minimum; **requires an
  explicit `uncovered:` list**. `smoke`: only readiness/health.
  The test is *privilege*, not features: a feature-rich app whose optional
  features are all **userland** stays `bounded` (a WordPress plugin or a Postgres
  extension is application code and cannot grant a Linux capability), whereas a
  monitoring/network tool whose optional collectors enter namespaces, open raw
  sockets, or touch devices is `partial`.
- **`environment`** — descriptive, not graded. Records the axes a cap's necessity
  can depend on, because a cap removable here can be required elsewhere (a
  stricter AppArmor/SELinux policy, containerd/CRI-O, an older kernel, rootless).
- **`observation`** — `production`: additionally confirmed on a live deployment
  running this exact config, carrying real traffic/features. `lab`: synthetic
  workload on a derivation host only. **This is the strongest signal and the old
  rubric ignored it** — the netdata question was only settled by the live box.

### Overall

```
overall = min(rigor, map(coverage))     # bounded→high, partial→moderate, smoke→low
```

`observation: production` does **not** inflate `overall` — production still only
exercises what production runs — but it is surfaced as a distinct badge that a
consumer should weigh above any lab `high`.

### What is programmatic vs. human

Deliberately, only one axis needs per-profile judgment, and it fails safe:

- **`environment`** — 100% auto-populated from the derivation host (`uname`,
  cgroup version, `docker info`, the `security_opt` used).
- **`observation`** — set from provenance: the deploy-check pipeline knows it ran
  against a live compose (`production`); a lab drop-test is `lab`. No one guesses.
- **`rigor`** — mostly computable: "drop-test used" and "no `fixed`" are known
  from the run and already enforced. The one seam — "is the correctness check
  *discriminating*?" — is made programmatic by having the check self-declare its
  assertions (`# asserts: function-roundtrip, non-root-uid`) and validating them;
  until then it is a review item.
- **`coverage`** — the genuinely human axis: deciding "did we exercise everything
  that could need a privilege" requires external knowledge of the image's full
  feature set, which is not derivable from the container. **It therefore defaults
  to `partial`** (→ `overall: moderate`); a human only ever *upgrades* to
  `bounded` with justification. Uncertainty resolves **downward**. This default
  alone would have caught netdata: it defaults to `moderate` and stays there
  unless someone proves the surface bounded.

### Schema & migration

The structured block is a **future backward-compatible schema minor**: `confidence`
becomes `oneOf: [the existing scalar, the block]`, so old profiles stay valid and
producers migrate incrementally. That bump is deferred until a consumer
(compose-lint enrichment) actually reads the axes.

**Interim (now), no schema change:** the catalog recalibrates the existing scalar
to the computed `overall` — `high` is retained only where `coverage: bounded` is
defensible, everything else drops to `moderate` — and records the per-dimension
`coverage` classification and any `uncovered:` scope in the criteria docs. This
is applied across the catalog in the companion change.

## Consequences

- **The interim scalar recalibration** (companion catalog change) drops a
  capabilities dimension from `high` to `moderate` where an unexercised feature is
  **documented to need more capability** than the derived minimum:
  - `netdata` — per-container network collector (`cgroup-network` → `SYS_ADMIN`),
    ebpf collectors.
  - `home-assistant` — hardware/USB/Bluetooth/network integrations (devices,
    D-Bus, `NET_ADMIN`/`NET_RAW`).
  - `uptime-kuma` — ping monitors add `NET_RAW`.
  - `adguardhome` — the DHCP server adds `NET_ADMIN`.
  - `pihole` — DHCP (`NET_ADMIN`), NTP (`SYS_TIME`), `SYS_NICE` — the vendor's own
    conditional caps, none in the DNS-only minimum.
  - `alloy` — configurable collection pipelines (process/ebpf) can need
    `SYS_PTRACE`/BPF.
  Each gets an `uncovered:`-style note in its criteria doc.
- **Profiles that stay `high` genuinely earn it** — their *privilege* surface is
  bounded by start-up + one primary function even when their *feature* surface is
  large: the databases (extensions/replication are userland), the web/CMS apps
  (WordPress/Nextcloud/paperless plugins are userland), the proxies and brokers,
  and the zero-cap stores (memcached, minio, prometheus, loki, keycloak).
  Filesystem dimensions likewise stay `high` where the optional feature affects
  caps/devices, not the write surface (e.g. a ping monitor needs `NET_RAW`, not a
  new tmpfs).
- **Under the structured field (target state), `coverage` defaults to `partial`**
  and every `bounded` must be affirmatively justified — a stricter bar than this
  interim pass, which only *demotes on known evidence*. The migration will surface
  the profiles currently assumed-bounded-by-omission.
- **The honest answer to "should this be `high` if we didn't run it ourselves":**
  for profiles we *do* run (the deploy-check / homelab services — netdata among
  them), `observation: production` is the strong signal; for the rest, cap
  `overall` at what the workload provably bounds.
