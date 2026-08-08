# A true premise and a false conclusion

**Verified against:** compose-lint 0.15.1, 2026-08-08

A four-service stack — application server, database, cache, machine-learning worker — where every service runs with a read-only root filesystem. For a long time its config said that was impossible:

> Server/ML/db write to named data/cache volumes so cannot be fully read_only

The first half is true. All three write constantly: uploads, thumbnails, transcodes, database pages, model caches. The second half does not follow from it, because **`read_only` does not affect volumes.** It makes the container's own image layer read-only. Every volume and bind mount stays exactly as writable as it was.

The waiver was deleted rather than reworded. All four services were already able to do this.

## Why this kind of error survives

Nothing about the stack looked wrong. The reason was written by someone who knew what the services do, it named a real behaviour, and every run linted clean. A reader checking it would think about whether those services write data — they obviously do — and move on.

The failure is one step upstream of the evidence: it is a claim about what `read_only` *means*, and no amount of looking at the application tells you that. This is the same shape as the [rules-in-tension example](../read-only-in-tension/index.md), where a correct boot test carried a conclusion one step too far.

## What each service actually needed

Three of the four needed nothing beyond `read_only` and a tmpfs for scratch space. The database needed one more thing:

```yaml
    read_only: true
    tmpfs:
      - /run
      - /tmp
      - /etc/postgresql      # ships EMPTY; the entrypoint copies a template in at runtime
```

That third entry is worth checking before copying. A tmpfs over a directory **masks whatever the image ships there** — the mistake that broke an earlier attempt at this on a different service, where a tmpfs over an init system's directory hid the service definitions and produced a container that ran and served nothing. Here the directory is genuinely empty in the image and populated at runtime, so a tmpfs is exactly right. Verify that before assuming.

The cache service goes further and puts its *data* on a tmpfs, since it holds nothing durable:

```yaml
    read_only: true
    tmpfs:
      - /data
```

That is the strongest available statement of "this container writes nothing that outlives it".

## Testing a photo library means uploading a photo

`read_only` on an application server is exactly the kind of change that starts cleanly and fails on the first real write. A container that boots and answers its health endpoint proves very little — several examples in this library exist because a green container was hiding missing functionality.

So the verification was an actual upload against a scratch instance:

```
login:          OK
upload:         {"id":"f10b3bed-...","status":"created"}
asset on disk:  /data/upload/9a8bdd45-.../8cbbd832-....jpg
dirs created:   backups encoded-video library profile thumbs upload
read-only fs errors: 0
```

All six data directories created, the asset written and readable. That is the evidence that `read_only` is safe here — not the health check.

The database was checked the same way: inserts, all three vector extensions available, and a successful `CHECKPOINT` to force a real write through to the volume.

## The waiver that nearly got deleted by a bad test

The database keeps `DAC_OVERRIDE`, and the honest version of how that was confirmed is more useful than the conclusion.

The first test dropped the capability against a scratch instance with a **named volume**. It started fine, so the capability looked removable — a finding that would have been written up confidently.

Production does not use a named volume. It binds a host directory owned by the database uid with mode `700`. Re-run that way:

```
with DAC_OVERRIDE     READY
without DAC_OVERRIDE  FAILED — find: '/var/lib/postgresql/data': Permission denied
```

The entrypoint starts as root, and root without `DAC_OVERRIDE` cannot traverse a directory it does not own with mode 700. Docker creates named volumes with ownership that makes the problem disappear, so the wrong mount type produces a clean, confident, wrong answer.

The suppression records that, so the next person to re-derive it does not repeat the shortcut.

## When the number and the posture disagree

Worth knowing before hardening a service that currently has no `cap_drop` at all: dropping capabilities can make the linter's output *worse*.

A service with no `cap_drop` holds roughly fourteen default capabilities, several of them dangerous, and reports a single CL-0006 **medium**. Convert it to `cap_drop: ALL` plus explicit add-backs and any dangerous capability you keep becomes a CL-0011 **high** — a strictly smaller set of privileges, reported more severely, because the implicit ones were never visible and the explicit one is.

That happened on a different stack in this library and is being tracked upstream. It does not apply to this example — the database's `DAC_OVERRIDE` was always explicit — but it is the reason to read a suppression file for what it *permits* rather than counting entries.

## Two waivers that survived

Not every waiver on this page was wrong, and it would be a poor lesson if they all were.

`DAC_OVERRIDE` above is real, once tested properly. The **CL-0019** digest-pinning waiver is real too: these images are tracked by an automated update tool through a custom matcher whose pattern ends in a version-tag capture, so appending a digest would silently stop version tracking rather than improve it. That is a genuine tooling constraint, and the correct answer is a documented waiver rather than a pinned digest that quietly freezes updates.

The useful ratio is not "waivers are usually wrong". It is that a waiver nobody has re-tested is *unverified*, and unverified claims fail at whatever rate the original reasoning fails.

## Scope note

Sanitized: hostnames, domains, addresses and paths are replaced, and a tailnet sidecar unrelated to the story is omitted. Capability, mount and `read_only` behaviour are as deployed, and every claim here was tested against the pinned digests above on scratch instances — the production database was never touched.
