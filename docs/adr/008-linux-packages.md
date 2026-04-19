# ADR-008: Linux Package Distribution

**Status:** Deferred — revisit when a user requests `.deb`/`.rpm` install.

**Context:** compose-lint is currently distributed via PyPI, Docker Hub, and a GitHub Action. Users who install via system package managers (apt, dnf, pacman) cannot install from PyPI without pip, which is not always present in minimal or managed Linux environments. Adding native `.deb`, `.rpm`, and AUR packages lowers the installation barrier for those users and makes compose-lint installable alongside other system security tools.

**Deferral rationale:**

- Zero demand signal today. No issues or discussions have asked for `.deb`/`.rpm`.
- Packages on GitHub Releases require manual `curl + dpkg -i` install and manual re-download on every upgrade — strictly worse UX than `pip install --upgrade` or the already-shipped multi-arch Docker image, which covers the same "no Python toolchain" persona.
- A hosted APT/DNF repo (where `apt upgrade` works) is the only shape that materially improves on existing channels, and its infra cost is out of proportion with the product's current scale.
- AUR maintenance is a manual push per release forever; CI automation was already rejected due to supply-chain surface area.
- Build + smoke + publish jobs would be maintained indefinitely against speculative demand. The homebrew tap (tracked in the roadmap) covers the "not everyone has pip" gap with lower maintenance cost and working upgrade UX.

Revisit this ADR when a user files a concrete request. If that happens, the proposed approach below is the starting point; if the request is for `apt install`-style flow specifically, hosted-repo tradeoffs need re-evaluation at that time.

**Proposed approach (retained for future revisit):**

- **Build tool:** nfpm, SHA-pinned in CI, produces `.deb` and `.rpm` from a wheel + PyYAML bundled into `/usr/lib/compose-lint/`. An `entrypoint.sh` wrapper at `/usr/bin/compose-lint` invokes the bundled install via `python3`.
- **Distribution:** Packages are attached to GitHub Releases via `gh release create`. GitHub Artifact Attestation (`gh attestation verify`) satisfies the signing requirement from DISTRIBUTION.md.
- **AUR:** A `PKGBUILD` is maintained in `packaging/aur/` and pushed to AUR manually at release time. AUR uses `python-yaml` as a declared dep (Arch convention) rather than bundling.
- **CI shape:** Three new jobs in `publish.yml` — `linux-packages-build`, `linux-packages-smoke`, `linux-packages-publish` — following the staging → smoke → gate → prod pattern from DISTRIBUTION.md. `linux-packages-smoke` feeds the existing `release-gate`.

**Alternatives rejected:**

- **Hosted APT/DNF repository:** Requires custom repo infrastructure and GPG package signing. Not justified for current scale; GitHub Releases only.
- **arm64 packages:** amd64 first. nfpm supports a matrix build with minimal changes if demand warrants it.
- **AUR automation via CI:** Would require an AUR SSH key repo secret. Not worth the supply-chain surface area; AUR pushes remain a manual post-release step.

**Rationale:**

- nfpm produces standards-compliant `.deb` and `.rpm` from a single config with no distro-specific tooling on the build host.
- Bundling PyYAML into the package (`pip install --target`) avoids declaring a system `python3-yaml` dep on Debian/RPM targets, where the package name and availability vary. AUR is the exception — Arch convention prefers declared deps over bundling.
- GitHub Releases with Artifact Attestation matches the signing posture already established for the Docker image. GPG signing for hosted repos is deferred until there is a reason to run repo infrastructure.
- GitHub Release creation currently happens manually as a post-release checklist step. `linux-packages-publish` takes this over atomically, removing a manual step.
