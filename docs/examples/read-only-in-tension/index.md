# Two rules in tension — buying `read_only` with a CL-0022

**Verified against:** compose-lint 0.16.0, 2026-08-11

Most hardening advice reads as though the rules point the same direction. Sometimes satisfying one means violating another, and the useful skill is deciding which finding you would rather have.

This service runs its own s6 init as root and cannot be pinned to a non-root user, so a read-only root filesystem is one of the few controls genuinely available to it. Applying it requires accepting a different finding.

## The failure that looks like a dead end

Adding `read_only: true` with an ordinary tmpfs for `/run` kills the container before the application starts:

```
/package/admin/s6-overlay/libexec/stage0: exec: line 83: /run/s6/basedir/bin/init: Permission denied
```

The chain is worth following, because every step is correct:

1. s6-overlay execs its init from `/run`.
2. Under a read-only root, `/run` has to be a tmpfs to be writable at all.
3. Docker mounts every tmpfs `noexec` by default — see [CL-0022](../../rules/CL-0022.md).
4. So the init binary is present, executable, owned correctly, and refused.

This is the exact trap CL-0022's own docs describe: a file with the execute bit set, refused by the *mount*, where `chmod +x` changes nothing because the restriction is not on the file.

## Where the reasoning usually goes wrong

It is easy to stop here and record "`read_only` is impractical for this image". That conclusion was, in fact, recorded for this stack for months, on the strength of a real boot test that produced exactly the error above.

The step that does not hold is the assumption that Compose cannot ask for anything else. It can:

```yaml
    tmpfs:
      - "/run:exec"
      - /tmp
```

The list form takes mount options and passes them through. Verified against a running container:

```
tmpfs: ["/run:exec"]  ->  /run rw,nosuid,nodev,relatime          noexec absent
tmpfs: [/tmp]         ->  /tmp rw,nosuid,nodev,noexec,relatime   noexec present
```

The size-and-mode-only limitation that the old note relied on is real, but it belongs to the **long** `volumes: [{type: tmpfs}]` form, which is a different syntax. With `:exec` on `/run`, the container boots normally.

A sound observation, a correct mechanism, and a conclusion that reached one step too far. That combination is far more common than a careless waiver, and much harder to notice.

## What it costs, stated honestly

`:exec` re-enables execution on a writable in-memory filesystem. That is a genuine weakening and CL-0022 exists to flag it. The finding does not go away — it is traded:

```
before:  CL-0007  low      writable root filesystem
after:   CL-0022  low      /run permits execution
```

The trade is worth taking. Before, the *entire* root filesystem was writable, and a tmpfs at `/run` was writable and executable anyway once the container booted. After, exactly one mount is writable-and-executable and everything else is read-only. The attack surface strictly shrinks.

**The output does not shrink with it.** One low leaves and one low arrives, so a reader comparing severities across the change sees no movement at all, and a reader comparing counts sees none either. That is not the linter failing to notice — it is the linter declining to price two different weaknesses against each other, which is not something a static rule can do without knowing what writes to `/run`. The decision here was made by reading the posture, and the output is the same either way. Elsewhere in this library the number moves the *wrong* way against a real improvement ([that one](../read-only-multi-service/index.md#when-the-number-and-the-posture-disagree)); this is the quieter version of the same warning.

Neither file reports anything for the capability add-backs. `DAC_OVERRIDE` and `NET_RAW` are both in Docker's default set, so adding them back after `cap_drop: ALL` returns the container to the default posture rather than exceeding it — and a rule that flagged them would be scoring the declaration rather than the runtime state. `DAC_OVERRIDE` was flagged here until 0.16.0, which is why an earlier version of this page named a capability finding that no longer exists. The comments in the file explaining why each one is needed are still worth keeping: they are the record of a drop-test, and the next person to prune that list needs them whether or not a rule fires.

## Scoping the exception

Only `/run` gets `:exec`. `/tmp` is listed as a plain tmpfs and keeps `noexec`, `nosuid` and `nodev`:

```yaml
    tmpfs:
      - "/run:exec"     # s6 execs its init from here
      - /tmp            # secure defaults, nothing runs from here
```

This matters more than it looks. The reflex when hitting the error is to make the whole thing permissive, or to drop `read_only` entirely and move on. Neither is necessary. The exception is one mount wide, and the suppression says which one and why — so a reviewer can see the scope of what was given up rather than inferring it.

## When to reach for this

Ask whether the finding you are about to accept is *smaller* than the one you are closing. Here a low replaces a medium and the writable surface shrinks from a whole filesystem to one directory, so the answer is clear. If accepting CL-0022 had meant `:exec` on a mount that untrusted input can write to, the answer would be the opposite — and the right move would have been to leave `read_only` off and say so.

## Scope note

Sanitized: hostnames, domains and paths are replaced. The boot behaviour, capability set and tmpfs configuration are as deployed, and all three states in this page — as-deployed, `read_only` with a plain tmpfs, and `read_only` with `/run:exec` — were boot-tested against the pinned digest above rather than reasoned about.
