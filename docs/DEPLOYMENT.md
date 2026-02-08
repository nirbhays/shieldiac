# ShieldIaC Deployment Guide

> Step-by-step guide to deploying ShieldIaC to production.

---

## Architecture

```
Cloudflare (DNS) → Google Cloud Run (Backend API)
                 → Vercel (Next.js Frontend)

Cloud Run → Supabase PostgreSQL (Database)
         → Upstash Redis (Queue + Cache)
         → OpenAI API (AI Fix Suggestions)
         → Stripe (Billing)
         → GitHub API (PR Comments)
```

---

## Prerequisites

- Google Cloud account with billing enabled
- Supabase account (free tier works for getting started)
- Upstash account (free tier works for getting started)
- GitHub account (for creating a GitHub App)
- Stripe account (for billing)
- Clerk account (for authentication)
- OpenAI API key (optional, for AI fix suggestions)
- Domain name (e.g., shieldiac.dev)

---

## Step 1: Create GitHub App

1. Go to **GitHub Settings > Developer Settings > GitHub Apps > New GitHub App**
2. Configure:
   - **Name**: ShieldIaC
   - **Homepage URL**: `https://shieldiac.dev`
   - **Webhook URL**: `https://api.shieldiac.dev/api/v1/webhooks/github`
   - **Webhook Secret**: Generate a strong random string
3. Permissions:
   - **Repository > Contents**: Read-only
   - **Repository > Pull requests**: Read & Write
   - **Repository > Checks**: Read & Write
   - **Repository > Metadata**: Read-only
4. Subscribe to events:
   - Pull request
   - Push
5. Save and note the **App ID** and **Private Key**

---

## Step 2: Set Up Supabase

1. Create a new Supabase project
2. Run the database migration:
   ```bash
   psql $SUPABASE_DATABASE_URL -f database/migrations/001_initial.sql
   ```
3. Note the connection string: `postgresql+asyncpg://...`

---

## Step 3: Set Up Upstash Redis

1. Create a new Upstash Redis database
2. Note the Redis URL: `rediss://default:...@...:6379`

---

## Step 4: Set Up Stripe

1. Create products and prices for each plan tier
2. Note the price IDs for Pro and Enterprise plans
3. Set up the webhook endpoint: `https://api.shieldiac.dev/api/v1/webhooks/stripe`

---

## Step 5: Deploy Backend to Cloud Run

```bash
# Build and push Docker image
gcloud builds submit --tag gcr.io/PROJECT_ID/shieldiac-api

# Deploy to Cloud Run
gcloud run deploy shieldiac-api \
  --image gcr.io/PROJECT_ID/shieldiac-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 100 \
  --set-env-vars "\
SHIELDIAC_ENVIRONMENT=production,\
SHIELDIAC_DATABASE_URL=postgresql+asyncpg://...,\
SHIELDIAC_REDIS_URL=rediss://...,\
SHIELDIAC_GITHUB_APP_ID=123456,\
SHIELDIAC_GITHUB_WEBHOOK_SECRET=...,\
SHIELDIAC_OPENAI_API_KEY=sk-...,\
SHIELDIAC_STRIPE_SECRET_KEY=sk_live_...,\
SHIELDIAC_CLERK_SECRET_KEY=sk_live_..."
```

**Or use Terraform** (recommended):
```bash
cd infra
terraform init
terraform apply
```

---

## Step 6: Deploy Frontend to Vercel

1. Connect your GitHub repository to Vercel
2. Set environment variables:
   - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
   - `NEXT_PUBLIC_API_URL=https://api.shieldiac.dev`
   - `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
3. Deploy

---

## Step 7: Configure DNS (Cloudflare)

| Record | Type | Value |
|--------|------|-------|
| `shieldiac.dev` | CNAME | `cname.vercel-dns.com` |
| `api.shieldiac.dev` | CNAME | Cloud Run URL |

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `SHIELDIAC_ENVIRONMENT` | Yes | `production` |
| `SHIELDIAC_DATABASE_URL` | Yes | PostgreSQL connection string |
| `SHIELDIAC_REDIS_URL` | Yes | Redis connection string |
| `SHIELDIAC_GITHUB_APP_ID` | Yes | GitHub App ID |
| `SHIELDIAC_GITHUB_APP_PRIVATE_KEY` | Yes | GitHub App private key (PEM) |
| `SHIELDIAC_GITHUB_WEBHOOK_SECRET` | Yes | Webhook verification secret |
| `SHIELDIAC_OPENAI_API_KEY` | No | For AI fix suggestions |
| `SHIELDIAC_CLERK_SECRET_KEY` | Yes | Clerk authentication |
| `SHIELDIAC_STRIPE_SECRET_KEY` | Yes | Stripe billing |
| `SHIELDIAC_STRIPE_WEBHOOK_SECRET` | Yes | Stripe webhook verification |

---

## Production Costs

| Service | Monthly Cost |
|---------|-------------|
| Cloud Run | $5-25 (scales to zero) |
| Supabase PostgreSQL | $25 |
| Upstash Redis | $10 |
| OpenAI API | $3-30 (usage-dependent) |
| Vercel | Free tier |
| Cloudflare | Free |
| **Total** | **$45-90/mo** |

---

## Monitoring

- **Error tracking**: Sentry (free tier: 5K events/mo)
- **Uptime**: BetterUptime (free tier: 10 monitors)
- **Metrics**: Grafana Cloud (free tier: 50GB logs)
- **Alerting**: PagerDuty or OpsGenie for service outages
