# Unified server operations

Copy `config/unified/example.yaml` and set deployment URLs, distinct data roots, public IdP issuer, and service audiences. Keep the listener on loopback. Put external access behind a TLS-terminating reverse proxy.

Create three confidential IdP clients with `idp-server provision-service-client`, using an existing canonical application:

| Client               | Allowed audience              | Allowed scopes                                             |
| -------------------- | ----------------------------- | ---------------------------------------------------------- |
| Management → IdP     | IdP `service_audience`        | `idp.token.validate idp.device.lookup`                     |
| Storage → IdP        | IdP `service_audience`        | `idp.token.validate idp.device.list`                       |
| Storage → Management | Management `storage_audience` | `management.replication.read management.replication.admit` |

Set each client ID and audience in the config file. Load each secret from its own environment variable:

- `UNIFIED_MANAGEMENT_IDP_CLIENT_SECRET`
- `UNIFIED_STORAGE_IDP_CLIENT_SECRET`
- `UNIFIED_STORAGE_MANAGEMENT_CLIENT_SECRET`

Do not put secrets in YAML or commit local configuration. Provisioning remains an operator action; unified startup does not create OAuth clients or credentials.

Run the host with either binary:

```sh
cargo run -p unified-server --features cli -- --config config/unified/local.yaml
cargo run -p idp-unified -- --config config/unified/local.yaml
```

Use one endpoint key and separate IdP, Management, and Storage data roots. Do not run service binaries against those roots while unified mode is active. The service clients use the actual loopback listener port and the fixed `/idp`, `/management`, and `/storage` prefixes.

Build images from the workspace parent directory so the Docker build can include the sibling `ofdb`, `offs`, and `ofnet` sources required by path dependencies:

```sh
docker build -f of/Dockerfile -t idp-unified .
docker build -f of/Dockerfile -t idp-server --build-arg PROJECT=idp-server --build-arg BIN=idp-server .
docker build -f of/Dockerfile -t management-server --build-arg PROJECT=management-server --build-arg BIN=management-server .
docker build -f of/Dockerfile -t storage-server --build-arg PROJECT=storage-server --build-arg BIN=storage-server .
```

The default image is `idp-unified` and uses the `cli` feature. Mount the selected YAML at `/app/config.yaml` and mount persistent storage at the data paths in that config. For non-loopback access, use a TLS-terminating proxy.
