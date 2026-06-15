# Samples

Runnable, in-solution reference apps (kept compiling by CI).

| Sample | What it shows |
|--------|---------------|
| [FirmwareSigning.Console](FirmwareSigning.Console) | End-to-end console: generate-or-reload an HSS key with a crash-safe `FileStateStore`, sign an artifact (persist-before-sign), verify with the public key, and demonstrate tamper detection. |
| [FirmwareSigning.Web](FirmwareSigning.Web) | ASP.NET Core minimal API: `AddLmsSigner(...)`, a `POST /sign` endpoint, `GET /pubkey`, `GET /status`, and a `/health` capacity check. |

## Run

```bash
# Console — signs a generated demo artifact (or pass your own file path)
dotnet run --project samples/FirmwareSigning.Console
dotnet run --project samples/FirmwareSigning.Console -- ./my-firmware.bin

# Web — then: curl --data-binary @firmware.bin http://localhost:5xxx/sign -o firmware.sig
dotnet run --project samples/FirmwareSigning.Web
```

> Both samples write signer **state** under a local `signer-state/` directory. That directory is the
> private key — see the [operations playbook](../docs/operations.md) before deploying anything like this.

For project scaffolding instead of a sample to read, use the template:
`dotnet new pqlms-firmware-signer`.
