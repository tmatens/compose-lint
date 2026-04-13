# ADR-008: Linux Package Distribution

**Status:** Pending decision

**Context:** compose-lint is currently distributed via PyPI, Docker Hub, and a GitHub Action. Users who install via system package managers (apt, dnf, pacman) cannot install from PyPI without pip, which is not always present in minimal or managed Linux environments. Adding native `.deb`, `.rpm`, and AUR packages lowers the installation barrier for those users and makes compose-lint installable alongside other system security tools.

**Decision:** Distribute `.deb` and `.rpm` packages via GitHub Releases, built with nfpm. Maintain an AUR package for Arch Linux. No hosted APT or DNF repository.

**Proposed approach:**

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
