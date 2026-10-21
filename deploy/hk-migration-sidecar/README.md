# HK New API Migration Sidecar

The sidecar connects the New API database to Sub2API's self-service account migration flow. It needs to join both existing Docker networks: the network containing the New API PostgreSQL service and the network containing the Sub2API service.

## Configure

Copy `.env.example` to `.env`, then set the public authorization URL, database credentials, and a random shared secret. Set `HKM_NEW_API_NETWORK` and `HKM_SUB2API_NETWORK` to the exact existing network names shown by `docker network ls`. The generic defaults are examples and may need to match your deployment.

The shared secret must be at least 16 characters and must exactly match `migration.shared_secret` in Sub2API's configuration. `HKM_PUBLIC_BASE_URL` is the browser-facing HTTPS URL for the sidecar authorization page; Sub2API's `migration.hk_base_url` is its container-reachable URL, typically `http://hk-migration-sidecar:8290`.

The database URL must use the PostgreSQL service hostname and credentials available on the New API network. The sidecar only needs network access to this database and Sub2API.

## Deploy

```bash
cp .env.example .env
# Edit .env and verify the external network names and credentials.
bash deploy.sh
```

`deploy.sh` builds the sidecar, starts it, and checks `http://127.0.0.1:8290/health`. Keep the `.env` file private because it contains database credentials and the shared secret.
