# Hashnode cross-post: State of Docker Compose Security

The Hashnode post is a cross-post of the dev.to article. Its body is the body
of [`state-of-compose-devto.md`](state-of-compose-devto.md), everything below
the front matter and the source note, pasted unchanged. Keeping one body means
the two posts cannot drift apart. Only the publish settings below differ.

## Publish settings (set in the Hashnode editor)

| Setting | Value |
| --- | --- |
| **Title** | More than 9 in 10 Docker Compose files skip the basic security flags |
| **Subtitle** | What 11,111 public Compose files look like to a security linter, and why the examples people copy are no better than the rest. |
| **Canonical URL** | Under *Settings → Canonical URL*, the live dev.to post: `https://dev.to/tmatens/9-in-10-docker-compose-files-skip-the-basic-security-flags-2dpf`. This is required. It tells search engines that dev.to holds the original. |
| **Tags** | docker, security, containers, opensource |
| **Cover image** | Upload `docs/publishing/assets/cover.png`, the same cover as dev.to. |

## Images

The article's four charts are PNG files in `docs/publishing/assets/`, linked by
their `raw.githubusercontent.com` URLs. They render on Hashnode the same way
they do on dev.to, so paste the body as it is. The report's SVGs would not
render through raw GitHub, which is why the article uses PNGs. See
[`README.md`](README.md).

## Updating the post for a new edition

1. Merge the report and this folder's changes to `main`, so the chart URLs
   serve the new images.
2. Update the dev.to article first.
3. Replace the Hashnode body with the same text, set the title and subtitle
   above, and upload the new cover.
4. Check that the Canonical URL still points at the dev.to post.
