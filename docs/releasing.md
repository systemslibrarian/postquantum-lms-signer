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
git tag v1.0.0
git push origin v1.0.0
```

Versions containing a hyphen (e.g. `v1.1.0-rc.1`) are marked as pre-releases automatically.

## Publishing to NuGet.org (Trusted Publishing)

Publishing uses **[NuGet Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing)**
(OIDC) — there is **no long-lived `NUGET_API_KEY` secret**. At publish time the workflow exchanges a
GitHub-issued OIDC token for a short-lived (1-hour) NuGet API key via the `NuGet/login` action, then pushes.

One-time setup:

1. On **nuget.org → your username → Trusted Publishing**, add a policy:
   - **Repository Owner:** `systemslibrarian`
   - **Repository:** `postquantum-lms-signer`
   - **Workflow File:** `release.yml` (file name only — no `.github/workflows/` prefix)
   - **Environment:** leave empty (this workflow uses no GitHub environment)
2. Add a repository secret **`NUGET_USER`** = your nuget.org **profile name** (not your email).
   It is an identifier, not a credential; the publish step is skipped when it is unset.

> Private-repo policies start in a 7-day "pending activation" window and become permanent after the
> first successful publish (nuget.org needs the repo/owner IDs from a real run to lock the policy).

## Optional secrets

These steps no-op unless the corresponding repository secret is set:

| Secret | Effect |
|--------|--------|
| `NUGET_USER` | Your nuget.org profile name; enables the Trusted-Publishing push (`--skip-duplicate`). |
| `SIGNING_CERTIFICATE_BASE64` | Base64 of a code-signing `.pfx`; enables `dotnet nuget sign`. |
| `SIGNING_CERTIFICATE_PASSWORD` | Password for the signing certificate. |

Without `NUGET_USER`, a release still builds, attests, and publishes artifacts to the GitHub
Release — it just doesn't push to NuGet. Author-signing requires your own certificate; until one is
configured, packages rely on NuGet.org's repository signature.

## Verifying what you downloaded

**Provenance** (proves the package was built by this repo's release workflow, from a specific commit):

```bash
gh attestation verify PostQuantum.LMS.Signer.1.0.0.nupkg \
  --repo systemslibrarian/postquantum-lms-signer
```

**Checksums**:

```bash
sha256sum -c SHA256SUMS.txt
```

**Package signature** (if author-signed, or to inspect the NuGet repository signature):

```bash
dotnet nuget verify PostQuantum.LMS.Signer.1.0.0.nupkg
```

**SBOM**: each package ships a CycloneDX JSON SBOM (`<package>.cyclonedx.json`) listing its dependency
graph — feed it to your vulnerability scanner or SCA tooling.

## Support policy

This project is **1.0**. It follows [Semantic Versioning](https://semver.org/): no breaking API or
on-disk/wire-format changes within the 1.x line; breaking changes wait for 2.0. See
[/CHANGELOG.md](../CHANGELOG.md). Security fixes target the latest 1.x release — report issues per
[/SECURITY.md](../SECURITY.md). Assurance status and non-goals are documented in
[security-assurance.md](security-assurance.md).
