# AAA / Identity Protocol Assessment

## Question
Do we currently have experience/implementation in:
- Authentication, Authorization, Access Control (AAA)
- OpenID Connect (OIDC)
- SAML
- OAuth

## Findings

### 1) Authentication: **Yes (implemented)**
- API exposes auth endpoints for login/register/refresh/logout.
- JWT authentication is implemented with `passport-jwt`, extracting `accessToken` from cookies.
- Next.js middleware checks for `accessToken` cookie to protect page routes.

### 2) Authorization: **Partial / basic only**
- Route-level protection exists (`authenticateJWT`) on selected API routes.
- Session operations are constrained to the authenticated user via `userId` checks.
- There is no visible role-based (RBAC) or permission-based (ABAC) policy framework.

### 3) Access Control: **Basic access control present**
- Protected routes require JWT auth.
- Frontend route guard middleware redirects unauthenticated users.

### 4) MFA: **Yes (TOTP-based, app authenticator flow)**
- MFA setup, verify, revoke, and MFA login verification endpoints exist.
- Uses `speakeasy` and QR generation (`qrcode`).

### 5) OpenID Connect (OIDC): **No evidence in implementation**
- No OIDC libraries or OIDC flow endpoints discovered.

### 6) SAML: **No evidence in implementation**
- No SAML libraries or SAML-specific routes/config discovered.

### 7) OAuth / OAuth2: **No evidence as an auth protocol implementation**
- The project uses custom JWT/session auth; no OAuth provider/client flow implementation is present.

## Practical summary
If you are evaluating whether this repo demonstrates experience with **OIDC/SAML/OAuth**, the answer is **no** from current code. It does demonstrate practical experience in **custom JWT auth + session management + MFA + basic access control**.
