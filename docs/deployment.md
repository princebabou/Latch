# Deploying Latch

Latch is distributed as static binaries, checksummed archives, Linux packages,
a multi-architecture OCI image, and source. Releases include an SBOM and
GitHub artifact attestations.

## Local binary

Install the latest release into a user-local directory:

```sh
curl -fsSL https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.ps1 | iex
```

Both installers resolve the release through the GitHub API and verify the
downloaded archive against the release's SHA-256 checksum list before
installation. Review the script before piping it into a shell in a
high-assurance environment.

Pin a version or installation directory:

```sh
LATCH_VERSION=1.2.3 LATCH_INSTALL_DIR=/usr/local/bin ./scripts/install.sh
```

```powershell
.\scripts\install.ps1 -Version 1.2.3 -InstallDir C:\Tools\Latch
```

Release assets also include `.deb`, `.rpm`, and `.apk` packages for supported
Linux architectures. Those packages install a starting policy at
`/etc/latch/latch.yaml`; a local `latch.yaml` or explicit `LATCH_CONFIG`
takes precedence.

## Source and reproducible metadata

```sh
go install github.com/princebabou/Latch/cmd/latch@latest
latch version --json
```

Official release builds embed the version, source commit, build time,
builder, Go toolchain, and target platform. Local builds report `dev` unless
metadata is supplied through the documented linker variables.

Verify downloaded release artifacts:

```sh
sha256sum --check checksums.txt
gh attestation verify latch_1.2.3_linux_amd64.tar.gz \
  --repo princebabou/Latch
```

Each archive has a Syft-generated SBOM beside the release artifacts. Container
images include registry provenance and SBOM attestations as well.

## Container image

The release workflow publishes:

```text
ghcr.io/princebabou/latch:<version>
```

It is a non-root, multi-architecture (`linux/amd64`, `linux/arm64`) distroless
image built from digest-pinned base images. Persistent policy state belongs
on `/var/lib/latch`:

```sh
docker run --rm ghcr.io/princebabou/latch:latest version --json

docker run --rm \
  -v latch-state:/var/lib/latch \
  -v "$PWD/latch.yaml:/etc/latch/latch.yaml:ro" \
  ghcr.io/princebabou/latch:latest \
  doctor --agent desktop-agent
```

The image includes `latch-demo-mcp` for smoke testing:

```sh
docker run --rm -i \
  -v latch-state:/var/lib/latch \
  ghcr.io/princebabou/latch:latest \
  proxy --agent desktop-agent -- /usr/local/bin/latch-demo-mcp
```

An MCP stdio proxy must spawn the real server in the same container and
connect to its stdin/stdout. For production, derive an image and copy the
server into it:

```dockerfile
FROM ghcr.io/princebabou/latch:1.2.3
COPY --chown=nonroot:nonroot my-mcp-server /usr/local/bin/my-mcp-server
ENTRYPOINT ["/usr/local/bin/latch"]
CMD ["proxy", "--agent", "desktop-agent", "--", "/usr/local/bin/my-mcp-server"]
```

Do not deploy a stdio proxy as an unrelated network sidecar: it cannot
intercept another container's process streams. Use `proxy-http` as the network
boundary for an MCP Streamable HTTP server:

```sh
docker run --rm \
  -p 7071:7071 \
  -e LATCH_AGENT=remote-agent \
  -e LATCH_MCP_TOKEN \
  -e LATCH_MCP_UPSTREAM_TOKEN \
  -v latch-state:/var/lib/latch \
  -v "$PWD/latch.yaml:/etc/latch/latch.yaml:ro" \
  ghcr.io/princebabou/latch:latest \
  proxy-http --listen 0.0.0.0:7071 --behind-tls-proxy \
  --upstream http://mcp-server:8080/mcp --allow-http-upstream
```

Terminate TLS at a trusted reverse proxy before exposing this listener. The
explicit `--allow-http-upstream` is required for a cleartext container-network
hop; prefer upstream TLS when available.

## Service hardening

- Mount policy files read-only and state directories read/write.
- Run as a dedicated non-root identity.
- Keep the Latch executable, policy, launcher config, trusted agent binding,
  and approval store in the same integrity boundary.
- Give every launcher a separate verified agent ID and capability ceiling.
- Persist approval and budget state across restarts.
- Forward `stderr` to operator logs; reserve `stdout` for MCP protocol data.
- Keep client-facing and upstream MCP tokens separate; never forward the Latch
  boundary credential to the tool server.
- Back up audit logs according to the organization's retention requirements,
  but do not make enforcement depend on a remote log collector.
- Run `latch doctor` in deployment validation before starting the launcher.

## GitHub Actions

The repository root is a cross-platform composite action. It installs an exact
release and verifies its checksum before running the native CI adapter:

```yaml
- uses: princebabou/Latch@v0.2.0
  id: latch
  with:
    config: latch.yaml
    agent: github-actions
    tool: deployment.apply
    operation: write
    arguments: '{"environment":"production"}'
```

Pin to a commit SHA for the strongest integrity. Keep the gate job read-only,
never use `continue-on-error`, and place deployment credentials only after an
explicit `allowed == 'true'` result. See
[CI/CD and GitHub Actions](ci-cd-github-actions.md).

## Release process

Pushing a `v*` tag triggers:

1. tests on the release source;
2. static cross-platform builds and Linux packages;
3. SHA-256 checksums and archive SBOMs;
4. a GitHub release and artifact attestation;
5. multi-architecture GHCR images with provenance and an SBOM.

The default branch also runs Go tests on Linux, Windows, and macOS, static
analysis, cross-compilation, a container smoke test, CodeQL, and dependency
review.
