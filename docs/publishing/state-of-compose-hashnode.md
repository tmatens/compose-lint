# Hashnode cross-post — State of Docker Compose Security

The Hashnode post is a **cross-post of the dev.to teaser**, published **~48h after**
dev.to so dev.to keeps indexing priority. To avoid two prose copies drifting apart,
the body is single-sourced: **use the body of [`state-of-compose-devto.md`](state-of-compose-devto.md)
verbatim** (everything below its frontmatter and the draft note). The only differences
are the publish settings below.

## Publish settings (set in the Hashnode editor)

| Setting | Value |
| --- | --- |
| **Title** | 9 in 10 Docker Compose files skip the basic security flags |
| **Subtitle** | What real-world Compose files actually look like, and why even the examples people copy ship insecure defaults. |
| **Canonical URL** | Set under *Settings → Canonical URL* to the live dev.to post: `https://dev.to/tmatens/9-in-10-docker-compose-files-skip-the-basic-security-flags-2dpf`. Mandatory — it points search authority at dev.to and stops Hashnode competing with it. |
| **Tags** | docker, security, containers, opensource |
| **Cover image** | Upload `docs/publishing/assets/cover.png` (same hardening-triple cover as dev.to). |

## Image rendering

The four charts are referenced by `raw.githubusercontent.com` PNG URLs in the dev.to
body. PNGs render on Hashnode the same way they do on dev.to — paste the body as-is, no
re-upload needed. (The repo SVGs would *not* render via raw GitHub; that's why the blog
charts are PNG. See `docs/publishing/README.md`.)

## Timing checklist

1. dev.to post goes live (set `published: true`, `canonical_url` blank).
2. Wait ~48h.
3. Create the Hashnode post: paste the dev.to body, apply the settings above, and set
   the Canonical URL to the live dev.to link.
4. Publish.
