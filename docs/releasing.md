# Releasing & verifying artifacts

## How a release is cut

Releases are tag-driven. Pushing a `v*` tag runs [`.github/workflows/release.yml`](../.github/workflows/release.yml), which:

1. builds and runs the full test suite on **.NET 8 and .NET 10**;
2. `dotnet pack`s every package (`.nupkg` + `.snupkg`);
3. generates a **CycloneDX SBOM per package** under `artifacts/sbom/`;
4. writes **`SHA256SUMS.txt`** for all packages;
5. produces a **build-provenance attestation** ([SLSA](https://slsa.dev/)-style) binding the packages to the exact workflow run and commit;
6. optionally **signs** the packages and **publishes** to NuGet.org (see below);
7. creates a **GitHub Release** with the packages, checksums, and SBOMs attached.

```bash
git tag v0.9.0
git push origin v0.9.0
```

Versions containing a hyphen (e.g. `v0.9.0-preview.1`) are marked as pre-releases automatically.

## Optional secrets

These steps no-op unless the corresponding repository secret is set:

| Secret | Effect |
|--------|--------|
| `NUGET_API_KEY` | Pushes the packages to NuGet.org (`--skip-duplicate`). |
| `SIGNING_CERTIFICATE_BASE64` | Base64 of a code-signing `.pfx`; enables `dotnet nuget sign`. |
| `SIGNING_CERTIFICATE_PASSWORD` | Password for the signing certificate. |

Without `NUGET_API_KEY`, a release still builds, attests, and publishes artifacts to the GitHub
Release — it just doesn't push to NuGet. Author-signing requires your own certificate; until one is
configured, packages rely on NuGet.org's repository signature.

## Verifying what you downloaded

**Provenance** (proves the package was built by this repo's release workflow, from a specific commit):

```bash
gh attestation verify PostQuantum.LMS.Signer.0.9.0.nupkg \
  --repo systemslibrarian/postquantum-lms-signer
```

**Checksums**:

```bash
sha256sum -c SHA256SUMS.txt
```

**Package signature** (if author-signed, or to inspect the NuGet repository signature):

```bash
dotnet nuget verify PostQuantum.LMS.Signer.0.9.0.nupkg
```

**SBOM**: each package ships a CycloneDX JSON SBOM (`<package>.cyclonedx.json`) listing its dependency
graph — feed it to your vulnerability scanner or SCA tooling.

## Support policy

This project is **preview** (pre-1.0). Until 1.0, minor/patch releases may contain breaking changes;
see [/CHANGELOG.md](../CHANGELOG.md). Security fixes target the latest preview — report issues per
[/SECURITY.md](../SECURITY.md). Assurance status and non-goals are documented in
[security-assurance.md](security-assurance.md).
