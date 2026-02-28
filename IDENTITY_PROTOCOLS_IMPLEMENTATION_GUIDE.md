# Implementing OIDC / SAML / OAuth in Gain-O-Meter

This guide describes **how to add standards-based identity protocols** to the current custom JWT + session system.

## Current baseline (already in repo)
- Custom JWT cookie authentication via `passport-jwt`
- Session persistence in DB for refresh/session lifecycle
- TOTP MFA flow (`speakeasy`)
- Frontend route guard middleware

---

## Recommendation: Implementation strategy

You have two realistic patterns:

1. **Identity Broker / Hosted IdP first (recommended for speed/security)**
   - Use Auth0, Okta, Azure AD, or Keycloak as the identity provider.
   - Your app integrates with OIDC/OAuth now; SAML comes “for free” via broker connections.

2. **Direct protocol implementation in your API**
   - Add OIDC + SAML endpoints directly in Express.
   - More control, but significantly more security and maintenance burden.

For this monorepo and team velocity, choose **(1)** first, then add direct SAML only if enterprise customers require SP-initiated SAML without broker.

---

## Libraries to use

## Backend (`apps/api`)

### OIDC/OAuth (Authorization Code + PKCE)
- **`openid-client`** (primary recommendation)
  - Standards-compliant OIDC/OAuth client
  - Handles discovery, token exchange, refresh, JWKS validation
- Optional passport wrapper: **`passport-openidconnect`** (if you want passport-style strategy ergonomics)

### Resource server JWT validation
- **`jose`** (preferred modern JWT/JWKS validation)
- or **`express-oauth2-jwt-bearer`** (if using Auth0 ecosystem)

### SAML Service Provider support
- **`@node-saml/passport-saml`** (actively maintained successor line)
  - Supports SP metadata, ACS endpoint, certificates, signature validation

### Session/cookie hardening helpers
- Continue with `cookie-parser`, but add CSRF middleware when using cookie auth:
  - **`csurf`** (or custom double-submit token pattern)

## Frontend (`apps/next-web` and `apps/react-web`)

### Next.js app
- **`auth.js` (next-auth v5)** for easiest OIDC social/enterprise providers
- Alternative: use backend-driven auth redirects and keep frontend mostly protocol-agnostic

### React SPA app
- **`oidc-client-ts`** for browser OIDC/OAuth flows
- If backend-for-frontend pattern is preferred, keep tokens out of SPA and rely on httpOnly cookie session

---

## Minimal architecture changes

## 1) Add external identity table / linkage
Create a model (e.g. `IdentityAccount`) that links local user to provider subject:
- `userId`
- `provider` (e.g. `google`, `azuread`, `okta`, `saml-acme`)
- `providerSubject` (`sub` for OIDC, NameID for SAML)
- `email`
- `lastLoginAt`

This lets one local account map to multiple IdPs.

## 2) New auth routes
Under `/api/v1/auth` add:
- `GET /oidc/:provider/login`
- `GET /oidc/:provider/callback`
- `GET /saml/:provider/login`
- `POST /saml/:provider/acs`
- `POST /saml/:provider/logout` (optional SLO)

## 3) Keep your existing token/session layer
After successful OIDC/SAML callback:
1. Resolve or create local user
2. Create app session record
3. Issue your existing `accessToken` + `refreshToken` cookies

This avoids rewriting all protected API logic at once.

---

## OIDC/OAuth implementation (backend-driven)

## Step A: configure provider metadata
Store per-provider config (DB or env):
- `issuer`
- `client_id`
- `client_secret` (if confidential client)
- `redirect_uri`
- scopes (`openid profile email offline_access`)

## Step B: login redirect
Using `openid-client`:
1. Discover issuer (`/.well-known/openid-configuration`)
2. Build authorization URL with:
   - `response_type=code`
   - `scope=openid profile email`
   - `code_challenge` + `code_challenge_method=S256` (PKCE)
   - `state` + `nonce`
3. Persist verifier/state/nonce in short-lived secure cookie or server session
4. Redirect user to provider

## Step C: callback exchange
1. Verify returned `state`
2. Exchange code for tokens
3. Validate ID token (`iss`, `aud`, `nonce`, signature)
4. Read `sub/email` claims from `userinfo` or id_token
5. Link/create local user
6. Issue existing app cookies (`accessToken`, `refreshToken`)
7. Redirect to `/home`

## Step D: refresh and logout
- OIDC refresh token can be stored encrypted in DB if needed for upstream API access.
- App logout should:
  - clear local cookies/session
  - optionally redirect to provider end-session endpoint

---

## SAML implementation (SP-initiated)

## Step A: configure IdP connection
Per tenant/provider store:
- `entryPoint` (SSO URL)
- `issuer` (your SP entity ID)
- `cert` (IdP signing cert)
- `callbackUrl` (ACS)
- optional `logoutUrl`

## Step B: metadata + ACS endpoints
With `@node-saml/passport-saml`:
- expose SP metadata endpoint for customer IdP admin
- route user to IdP login
- accept signed assertion at ACS

## Step C: assertion validation and user mapping
Validate:
- signature
- audience
- recipient
- NotBefore/NotOnOrAfter
Then map `NameID` / email attribute to local user, create session, set app cookies.

## Step D: multi-tenant safety
Never infer tenant purely from email domain in callback. Include a signed tenant hint in relay state and verify it.

---

## Security checklist (must-have)
- Use PKCE + state + nonce for OIDC
- Enforce exact redirect URI matching
- Validate JWT using provider JWKS cache (`jose`)
- Encrypt provider refresh tokens at rest (if stored)
- Rotate app refresh tokens (you already do partial sliding window)
- Add CSRF protection for cookie-auth state-changing routes
- Add session revocation checks during JWT auth (your current code has a FIXME)
- Log auth events with correlation IDs (login success/failure, token refresh, SAML assertion failures)

---

## Suggested phased rollout

## Phase 1 (1–2 sprints)
- Add **OIDC with one provider** (Google Workspace or Azure AD)
- Keep existing local login as fallback
- Issue current app cookies after OIDC callback

## Phase 2
- Add enterprise providers (Okta/Auth0/Keycloak)
- Add account linking and provider management UI

## Phase 3
- Add SAML via broker first; direct SP only if needed
- Add tenant-specific SAML config + metadata endpoints

## Phase 4
- Optional: migrate API authorization to standardized access tokens from IdP
- Keep BFF/session model if you want tokens hidden from browser JS

---

## Concrete dependency shortlist

For your stack, start with:
- API:
  - `openid-client`
  - `jose`
  - `@node-saml/passport-saml`
  - `csurf` (or equivalent CSRF strategy)
- Next frontend (if frontend-managed auth):
  - `next-auth` / Auth.js
- React frontend (if SPA-managed auth):
  - `oidc-client-ts`

If you choose backend-driven redirects/cookies, frontends need minimal protocol libs.

---

## How this fits your existing codebase
- Continue using current protected route middleware and JWT cookie approach.
- Replace “credential login only” with multiple login options (local + OIDC + SAML).
- Normalize all successful logins into the **same local session + cookie issuance path** so existing API authorization keeps working.

