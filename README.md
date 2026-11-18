# FUST HOST Cloud (Cloudflare Free deployment starter)

This is a deployable cloud web-app starter: static web UI + Worker API + D1 metadata DB + R2 file bucket. It does **not** run FXServer/FiveM. Cloudflare free tiers have usage and storage limits; the plan UI's 200 GB is a configured customer quota, not free physical storage provisioned. R2 free storage is currently 10 GB-month and Workers Free requests/CPU are limited.


## 1. Create Cloudflare resources
1. Create a D1 database named `fust-host-db` in Cloudflare dashboard and run `schema.sql` in its SQL console.
2. Create an R2 bucket named `fust-host-files`.
3. In your Cloudflare account create a Workers project, or deploy with Wrangler CLI.
4. Replace `REPLACE_WITH_D1_DATABASE_ID` in `wrangler.toml` with the database ID shown in D1.
5. Install Node.js locally and run `npm install -g wrangler`, then `wrangler login`.
6. Set Worker secrets: `wrangler secret put JWT_SECRET` (use a long random secret) and `wrangler secret put OWNER_SETUP_SECRET` (a separate long secret).
7. Deploy from this folder: `wrangler deploy`.

## 2. Initialize the Owner account
After deployment, use a POST request to `https://YOUR-WORKER-DOMAIN/api/setup-owner` once:
```json
{
  "setupSecret": "YOUR_OWNER_SETUP_SECRET",
  "email": "your-email@example.com",
  "username": "Owner",
  "password": "A-long-password-12+"
}
```
The endpoint only works once, when no Owner exists. After creating the Owner, remove the `OWNER_SETUP_SECRET` Worker secret or rotate it.


## 3. Free-plan constraints
- R2 Free tier is 10 GB-month total storage; a 200 GB plan shown in the app is a quota definition only, not capacity you currently have.
- Worker request-body limit on Cloudflare Free is 100 MB. This app currently rejects uploads over 90 MB to stay below that boundary. Uploading FiveM server packs larger than that needs multipart/direct R2 uploads or another storage provider.
- The app stores files and metadata only. It cannot start or keep FXServer processes online. A separate game-server runtime is required for actual FiveM hosting.
- This starter is not audited production software. Do not store customer files or invite paying users before reviewing access controls, backups, quotas, and security.

## 4. UI
Visit the Worker URL after deploying. Use Create account for customer users. The Owner uses the same login UI after initializing the Owner. Owner menu can manage plans, accounts, all cities, city files, and audit log. Clients see only their cities.
