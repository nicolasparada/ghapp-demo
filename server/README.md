# Control-plane server

This service is the control-plane for the PoC.

It provides:
- GitHub OAuth login for users
- Project management UI (server-rendered templates)
- GitHub App webhook ingestion (installations/repositories)
- Run ingestion with **verifiable payload integrity** using:
  1. GitHub Actions OIDC token (`/runs/token`)
  2. short-lived signed upload token bound to payload hash (`/runs`)

---

## 1) Prerequisites

- Docker + Docker Compose
- Go (version compatible with this repo's `go.mod`)
- A GitHub account with permission to create:
  - an OAuth App
  - a GitHub App

---

## 2) Run dependencies locally

From repo root:

```sh
docker compose -f server/compose.yaml up -d postgres
```

> This repo uses `postgres:18` and mounts `/var/lib/postgresql` (the 18+ recommended layout).

You can also use the server Makefile target, which starts/waits for Postgres automatically:

```sh
cd server
make migrate
```

---

## 3) Environment configuration

Create `server/.env`:

```env
# Server
PORT=8080
BASE_URL=http://localhost:8080

# Postgres (matches compose.yaml)
DATABASE_URL=postgres://ghapp_demo:ghapp_demo@localhost:5432/ghapp_demo?sslmode=disable

# GitHub OAuth App
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# GitHub App
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY=
GITHUB_APP_WEBHOOK_SECRET=
# Optional: used by "Connect repositories" page install button
GITHUB_APP_INSTALL_URL=https://github.com/apps/<your-app-slug>/installations/new

# OIDC verification (defaults shown)
OIDC_ISSUER=https://token.actions.githubusercontent.com
OIDC_AUDIENCE=http://localhost:8080
```

### Important note on `GITHUB_APP_PRIVATE_KEY`

The app private key can be stored as a single line with escaped newlines, for example:

```env
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
```

The server converts `\n` into real newlines automatically.

If you configure this value in **GitHub repository secrets** for CI/Terraform:
- paste the full PEM block exactly (recommended), or valid escaped-newline form
- avoid wrapping the entire value in extra quotes in the secret UI
- if rotating the key, bump `CONTROL_PLANE_APP_SECRETS_VERSION` so Terraform writes a new Secret Manager version

---

## 4) Configure GitHub OAuth App (for user login)

Go to GitHub:
- **Settings → Developer settings → OAuth Apps → New OAuth App**

Set:
- **Application name**: e.g. `ghapp-demo-local`
- **Homepage URL**: `BASE_URL` (e.g. `http://localhost:8080`)
- **Authorization callback URL**: `BASE_URL/auth/github/callback`

After creation:
- copy **Client ID** → `GITHUB_CLIENT_ID`
- generate/copy **Client secret** → `GITHUB_CLIENT_SECRET`

---

## 5) Configure GitHub App (for webhooks + signed run upload tokens)

Go to GitHub:
- **Settings → Developer settings → GitHub Apps → New GitHub App**

### Basic settings
- **GitHub App name**: e.g. `ghapp-demo-app-local`
- **Homepage URL**: `BASE_URL`
- **Webhook URL**: `BASE_URL/webhooks/github`
- **Webhook secret**: generate a random string → `GITHUB_APP_WEBHOOK_SECRET`

### Permissions
At minimum for current functionality:
- **Repository permissions**
  - Metadata: **Read-only**

Recommended for planned PR comments feature:
- Pull requests: **Read and write**

### Subscribe to events
Enable:
- Installation
- Installation repositories

(Recommended for next phases: Pull request)

### App credentials
After creating the app:
- copy **App ID** → `GITHUB_APP_ID`
- generate/download a **Private key** (`.pem`) → `GITHUB_APP_PRIVATE_KEY`

### Install the app
Install the app into the user/org and selected repos you want to monitor.

The server uses webhook events to populate `installations` and `repo_links`.
A repo must be present in `repo_links` to be accepted by `/runs/token` and `/runs`.

---

## 6) Local dev with GitHub callbacks/webhooks

GitHub must reach your server publicly for:
- OAuth callback
- GitHub App webhooks

For local development, use a tunnel (example):

```sh
cloudflared tunnel --url http://localhost:8080
```

Then set `BASE_URL` to the public tunnel URL and update both GitHub apps:
- OAuth callback: `<BASE_URL>/auth/github/callback`
- Webhook URL: `<BASE_URL>/webhooks/github`

Also set:
- `OIDC_AUDIENCE=<BASE_URL>`

---

## 7) Run the server

From `server/`:

```sh
make migrate
make run
```

Open:
- `http://localhost:8080`

---

## 8) Verifiable run ingestion flow

The server expects a 2-step flow.

### Step A: request upload token
`POST /runs/token`

Headers:
- `Authorization: Bearer <github-actions-oidc-token>`

Body:

```json
{
  "payload_sha256": "<sha256 hex of exact JSON bytes to upload>",
  "job_name": "build",
  "job_key": "build"
}
```

Response:

```json
{
  "upload_token": "...",
  "expires_at": "2026-01-01T00:00:00Z"
}
```

### Step B: upload run payload
`POST /runs`

Headers:
- `Authorization: Bearer <upload_token>`
- `Content-Type: application/json`

Body:
- The **exact** JSON payload whose SHA-256 was sent in step A.
- Must be `schema_version: "v2"` and include `lineage_tree` (the PoC lineage-first payload shape).

Minimal accepted payload shape:

```json
{
  "schema_version": "v2",
  "capture_backend": "bpftrace:sudo:connect-v4v6",
  "total_events": 42,
  "dropped_events": 0,
  "dropped_lines": 0,
  "errors": [],
  "events": [],
  "lineage_tree": []
}
```

The server verifies:
- upload token signature + expiry
- payload hash matches the token's `payload_sha256`
- repo is still linked via GitHub App installation

On success: `202 Accepted`.

---

## 9) Troubleshooting

### `connection refused` on migrate
Postgres is not running. Start it:

```sh
docker compose -f server/compose.yaml up -d postgres
```

or just run:

```sh
make migrate
```

### Postgres 18 mount-layout error
If you had old volumes from pre-18 layout, recreate cleanly:

```sh
docker compose -f server/compose.yaml down
docker volume rm ghapp-demo_postgres18_data || true
docker compose -f server/compose.yaml up -d postgres
```

### `runs token manager not configured`
Expected during bootstrap if GitHub App is not configured yet.
To enable run upload token signing later, set both:
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`

### `invalid oidc token`
Most common cause is audience mismatch.
Ensure the action requests an ID token with audience exactly equal to `OIDC_AUDIENCE`.

### Cloud SQL tier error: `Invalid Tier (...) for (ENTERPRISE_PLUS) Edition`
This PoC Terraform is pinned to Cloud SQL `ENTERPRISE` on PostgreSQL 18 with a `db-custom-*` tier (cheaper than ENTERPRISE_PLUS).
If you later change Terraform to `ENTERPRISE_PLUS`, you must also switch to a compatible `db-perf-optimized-*` tier.

### Cloud SQL Studio says `enable data_api_access for this instance`
This Terraform enables Data API access (`ALLOW_DATA_API`). After applying, verify your IAM user has Cloud SQL Studio permissions (`roles/cloudsql.studioUser`) and exists as a `CLOUD_IAM_USER` on the instance.

For table/query access, the server now uses a DB role model (`ghapp_readonly`). To grant read access to another IAM DB user:

```sql
GRANT ghapp_readonly TO "user@example.com";
```

### IAM API disabled in CI (`iam.googleapis.com`)
Enable IAM API for the project and rerun. The CI workflow now pre-enables foundational APIs, but first-time propagation can take a few minutes.

### Forbidden while applying project IAM bindings
This Terraform stack grants Cloud SQL access roles (`cloudsql.client`, `cloudsql.instanceUser`, `cloudsql.studioUser`) to every email in `local.iam_db_login_user_emails` in `server/infra/terraform/main.tf`.

If apply fails with permission errors, grant the deployer service account project IAM admin rights (as documented in the CI bootstrap steps), then rerun.

### Secret Manager payload required (`Field [payload] is required`)
This happens when Terraform tries to create secret versions with empty values.
In this repo, GitHub app-related secrets are optional during bootstrap. If unset, Terraform now skips those secret resources.

---

## 10) Deploy to Google Cloud Run with Terraform (CI)

This repository includes:

- Terraform stack: `server/infra/terraform`
- CI workflow: `.github/workflows/deploy-control-plane.yml`
- Server image Dockerfile: `server/Dockerfile`

The workflow does:
1. Authenticate to Google Cloud with GitHub OIDC (Workload Identity Federation)
2. Terraform init (GCS backend)
3. Ensure Artifact Registry repository exists
4. Build/push control-plane image
5. Terraform apply (Cloud Run + Cloud SQL + IAM + Secret Manager wiring)

### A) Prepare Google Cloud (step-by-step)

> You can do this in Cloud Shell or locally with `gcloud` authenticated.

Set your values first (for this repo):

```sh
PROJECT_ID="ghapp-demo"
REGION="us-central1"
GITHUB_OWNER="nicolasparada"
GITHUB_REPO="ghapp-demo"

# Billing account display name recommendation
BILLING_ACCOUNT_NAME="ghapp-demo-billing"

TF_STATE_BUCKET="${PROJECT_ID}-tf-state"
WIF_POOL_ID="github-pool"
WIF_PROVIDER_ID="github-provider"
DEPLOYER_SA_NAME="ghapp-deployer"
DEPLOYER_SA_EMAIL="${DEPLOYER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
```

> If `ghapp-demo-tf-state` is already taken globally, use a suffix such as `ghapp-demo-tf-state-001`.

1) Create/select project and enable billing in GCP Console.

2) Set active project and get project number:

```sh
gcloud config set project "${PROJECT_ID}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
```

3) Enable required APIs:

```sh
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  serviceusage.googleapis.com \
  iam.googleapis.com \
  run.googleapis.com \
  sqladmin.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com
```

4) Create Terraform state bucket:

```sh
gcloud storage buckets create "gs://${TF_STATE_BUCKET}" \
  --location="${REGION}" \
  --uniform-bucket-level-access
```

5) Create deployer service account:

```sh
gcloud iam service-accounts create "${DEPLOYER_SA_NAME}" \
  --display-name="ghapp-demo deployer"
```

6) Grant deployer permissions:

```sh
for ROLE in \
  roles/run.admin \
  roles/iam.serviceAccountUser \
  roles/iam.serviceAccountAdmin \
  roles/resourcemanager.projectIamAdmin \
  roles/cloudsql.admin \
  roles/secretmanager.admin \
  roles/artifactregistry.admin \
  roles/serviceusage.serviceUsageAdmin
 do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${DEPLOYER_SA_EMAIL}" \
    --role="${ROLE}"
done

gcloud storage buckets add-iam-policy-binding "gs://${TF_STATE_BUCKET}" \
  --member="serviceAccount:${DEPLOYER_SA_EMAIL}" \
  --role="roles/storage.objectAdmin"
```

7) Create Workload Identity Federation pool + provider for GitHub Actions:

```sh
gcloud iam workload-identity-pools create "${WIF_POOL_ID}" \
  --project="${PROJECT_ID}" \
  --location="global" \
  --display-name="GitHub Actions Pool"

gcloud iam workload-identity-pools providers create-oidc "${WIF_PROVIDER_ID}" \
  --project="${PROJECT_ID}" \
  --location="global" \
  --workload-identity-pool="${WIF_POOL_ID}" \
  --display-name="GitHub OIDC Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner,attribute.ref=assertion.ref,attribute.actor=assertion.actor" \
  --attribute-condition="assertion.repository=='${GITHUB_OWNER}/${GITHUB_REPO}'"
```

8) Allow your GitHub repo to impersonate the deployer SA:

```sh
gcloud iam service-accounts add-iam-policy-binding "${DEPLOYER_SA_EMAIL}" \
  --project="${PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/attribute.repository/${GITHUB_OWNER}/${GITHUB_REPO}"
```

9) Compute the exact values you’ll place in GitHub repository variables:

```sh
GCP_WIF_PROVIDER="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/providers/${WIF_PROVIDER_ID}"
GCP_WIF_SERVICE_ACCOUNT="${DEPLOYER_SA_EMAIL}"

echo "GCP_PROJECT_ID=${PROJECT_ID}"
echo "GCP_REGION=${REGION}"
echo "TF_STATE_BUCKET=${TF_STATE_BUCKET}"
echo "GCP_WIF_PROVIDER=${GCP_WIF_PROVIDER}"
echo "GCP_WIF_SERVICE_ACCOUNT=${GCP_WIF_SERVICE_ACCOUNT}"
```

### B) Configure GitHub repository variables and secrets

The deploy workflow uses **repository variables for non-sensitive values** and **repository secrets only for sensitive values**.

Set these **Repository Variables** (`Settings → Secrets and variables → Actions → Variables`):

**Required for deploy**
- `GCP_PROJECT_ID` = `ghapp-demo`
- `GCP_REGION` = `us-central1` (or the region you chose)
- `GCP_WIF_PROVIDER` = `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider`
- `GCP_WIF_SERVICE_ACCOUNT` = `ghapp-deployer@ghapp-demo.iam.gserviceaccount.com`
- `TF_STATE_BUCKET` = `ghapp-demo-tf-state` (or the bucket name you created)

**Optional for bootstrap (set later)**
- `CONTROL_PLANE_BASE_URL` (optional for bootstrap; preferred once you know final URL/custom domain)
- `CONTROL_PLANE_GITHUB_CLIENT_ID` (GitHub OAuth client ID)
- `CONTROL_PLANE_GITHUB_APP_ID` (GitHub App ID)
- `CONTROL_PLANE_GITHUB_APP_INSTALL_URL` = `https://github.com/apps/ghapp-demo-app/installations/new` (non-sensitive; controls install button target in the connect UI)
- `CONTROL_PLANE_APP_SECRETS_VERSION` (default `1`; bump to rotate GitHub app-related Secret Manager versions, e.g. `2`, `3`, ...)

Set these **Repository Secrets** (`Settings → Secrets and variables → Actions → Secrets`):

**Optional for bootstrap (set later)**
- `CONTROL_PLANE_GITHUB_CLIENT_SECRET`
- `CONTROL_PLANE_GITHUB_APP_PRIVATE_KEY`
- `CONTROL_PLANE_GITHUB_APP_WEBHOOK_SECRET`

> GitHub does not allow custom variable/secret names starting with `GITHUB_`, so CI inputs use the `CONTROL_PLANE_` prefix.
> Terraform maps these into runtime env vars expected by the app (`GITHUB_CLIENT_SECRET`, `GITHUB_APP_PRIVATE_KEY`, etc.).

Sensitive values are written by Terraform into Secret Manager and consumed by Cloud Run via secret references when provided.
### C) Run deploy

Trigger workflow:
- **Actions → Deploy control-plane to Cloud Run** → Run workflow

or push to `main` touching `server/**`.

### D) Post-deploy GitHub configuration

After first deploy, get service URL from workflow output and update GitHub apps:

- OAuth App callback URL: `<BASE_URL>/auth/github/callback`
- GitHub App homepage URL: `<BASE_URL>`
- GitHub App webhook URL: `<BASE_URL>/webhooks/github`

Use a stable domain for production to avoid rotating callback/webhook URLs.

### E) How to know `CONTROL_PLANE_BASE_URL` beforehand?

You usually **don't** if you're using the default Cloud Run URL.

Two practical options:

1. **Best**: use a custom domain you already control (known ahead of time), and set `CONTROL_PLANE_BASE_URL` to that.
2. **Bootstrap**: leave `CONTROL_PLANE_BASE_URL` unset for first deploy (workflow falls back to `https://example.invalid`), then copy the deployed Cloud Run URL from Terraform output, set `CONTROL_PLANE_BASE_URL`, and redeploy.

The second deploy updates `BASE_URL`/OIDC audience to the real public URL.
