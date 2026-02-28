# Gain-O-Meter Monorepo

This repository contains:
- `apps/api` — Express + TypeScript backend
- `apps/next-web` — Next.js frontend (port `3001`)
- `apps/react-web` — React + Vite frontend
- `libs/*` — shared packages

## Prerequisites

- Node.js 18+
- pnpm 8+
- A running MongoDB instance

## 1) Install dependencies

From the repository root:

```bash
pnpm install
```

## 2) Configure environment variables

There is no committed `.env.example`, so create your own environment file for the API app.

Create `apps/api/.env` with:

```env
NODE_ENV=development
APP_ORIGIN=http://localhost:3001
PORT=5000
BASE_PATH=/api/v1

MONGO_URI=mongodb://127.0.0.1:27017
MONGO_DB_NAME=gainometer

JWT_SECRET=replace_with_a_long_random_secret
JWT_EXPIRES_IN=15m
JWT_REFRESH_SECRET=replace_with_a_different_long_random_secret
JWT_REFRESH_EXPIRES_IN=30d

MAILER_SENDER=your-verified-sender@example.com
RESEND_API_KEY=your_resend_api_key
```

> `APP_ORIGIN` must match the frontend origin you run. Use `http://localhost:5173` if running the Vite app instead of Next.js.

Set frontend env vars:

### Next.js frontend (`apps/next-web/.env.local`)

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000/api/v1
```

### React Vite frontend (`apps/react-web/.env`)

```env
VITE_API_BASE_URL=http://localhost:5000/api/v1
```

## 3) Run the apps

Open separate terminals from repo root.

### API

```bash
pnpm --filter @gainometer/api dev
```

Backend starts on `http://localhost:5000`.

### Next.js frontend

```bash
pnpm --filter @gainometer/next-web dev
```

Frontend starts on `http://localhost:3001`.

### React Vite frontend

```bash
pnpm --filter @gainometer/react-web dev
```

Vite prints the exact local URL in the terminal (commonly `http://localhost:5173`).

## 4) Build apps

```bash
pnpm build-all
```

## 5) Notes

- The root `run-all` script currently expects `run:dev` scripts in workspaces, but the apps expose `dev` scripts. Run each app with `pnpm --filter ... dev` as shown above.
- If email features are not needed locally, keep valid placeholder values for `MAILER_SENDER` and `RESEND_API_KEY` or adjust code paths accordingly.

## Additional docs

- AAA protocol assessment: `AAA_PROTOCOLS_ASSESSMENT.md`
- OIDC/SAML/OAuth implementation plan: `IDENTITY_PROTOCOLS_IMPLEMENTATION_GUIDE.md`
