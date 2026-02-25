Below is a detailed technical audit of the authentication + MFA implementation in this repository. I’ve referenced the exact files and called out security/code‑quality issues with corrected examples and the underlying principles.

---

# 1) MFA & Identity Flow

## 1.1 Enrollment (Enable MFA)
**Backend**
- **GET `/api/v1/mfa/setup`** (protected by JWT cookie)  
  **File:** `apps/api/src/modules/mfa/mfa.routes.ts`  
  **Handler:** `MfaController.generateMFASetup` → `MfaService.generateMFASetup`  
  **Flow:**
  1. Requires authenticated user via `authenticateJWT`.
  2. If user has `enable2FA` already → returns “MFA already enabled.”
  3. If `twoFactorSecret` missing, generates secret via `speakeasy.generateSecret` and persists to user record.
  4. Builds TOTP URI using `speakeasy.otpauthURL`.
  5. Generates QR code using `qrcode.toDataURL`.
  6. Returns `{ secret, qrImageUrl }` to the frontend.

**Frontend**
- **Next:** `apps/next-web/src/app/(main)/_components/EnableMfa.tsx`
- **React:** `apps/react-web/src/components/EnableMfa.tsx`
- The UI shows QR + secret. User submits a 6‑digit code to verify.

---

## 1.2 Enrollment Verification
**Backend**
- **POST `/api/v1/mfa/verify`** (protected by JWT)  
  **File:** `apps/api/src/modules/mfa/mfa.controller.ts` → `verifyMFASetup`  
  **Service:** `apps/api/src/modules/mfa/mfa.service.ts`

**Current logic (core snippet):**
```ts
const isValid = speakeasy.totp.verify({
  secret: secretKey,          // <-- comes from client
  encoding: "base32",
  token: code,
});
if (!isValid) throw new BadRequestException(...)
user.userPreferences.enable2FA = true;
await user.save();
```

**State Management:**  
Enrollment is purely server-side (user must already be authenticated via cookie‑based JWT).

---

## 1.3 Login + MFA Challenge
**Backend**
- **POST `/api/v1/auth/login`**  
  **File:** `apps/api/src/modules/auth/auth.service.ts`  
  If `user.userPreferences.enable2FA === true`, backend returns:
```ts
return {
  user: null,
  mfaRequired: true,
  accessToken: '',
  refreshToken: '',
}
```
No session is created until MFA completes.

- **POST `/api/v1/mfa/verify-login`** (no auth required)  
  **File:** `apps/api/src/modules/mfa/mfa.service.ts`  
  This verifies TOTP against the stored secret and then creates a session + tokens.

**Frontend**
- **Next:** `apps/next-web/src/app/(auth)/page.tsx`  
- **React:** `apps/react-web/src/pages/auth/login.tsx`

Both frontends:
1. Call `/auth/login`.
2. If `mfaRequired`, redirect to `/verify-mfa?email=...`.
3. `/verify-mfa` submits `{ email, code }` to `/mfa/verify-login`.

**State Management between login → MFA challenge**
- State is **client‑only**.  
- The “challenge context” is essentially the user’s **email in query string**.
- There is **no temporary MFA transaction ID** or server‑side pending login session.

---

# 2) Token Lifecycle (JWT / OAuth2)

There is no OAuth2 provider usage here; it’s custom JWT auth.

## 2.1 Access Token
**Sign**
- **File:** `apps/api/src/common/utils/jwt.ts`
```ts
export const accessTokenSignOptions = {
  expiresIn: config.JWT.EXPIRES_IN,  // default 15m
  secret: config.JWT.SECRET,
};

signJwtToken({ userId, sessionId })
```

**Payload Structure**
```json
{
  "userId": "<Mongo ObjectId>",
  "sessionId": "<Mongo ObjectId>",
  "aud": ["user"]
}
```

**Algorithm**
- Uses jsonwebtoken default → **HS256**  
- JWT strategy explicitly enforces **HS256**:
  `algorithms: ['HS256']`  
  (`apps/api/src/common/strategies/jwt.strategy.ts`)

---

## 2.2 Refresh Token
**Sign**
- **File:** `apps/api/src/common/utils/jwt.ts`
```ts
export const refreshTokenSignOptions = {
  expiresIn: config.JWT.REFRESH_EXPIRES_IN, // default 30d
  secret: config.JWT.REFRESH_SECRET,
};
```

**Payload**
```json
{
  "sessionId": "<Mongo ObjectId>",
  "aud": ["user"]
}
```

**Refresh Flow**
- **GET `/api/v1/auth/refresh`**  
  **File:** `apps/api/src/modules/auth/auth.controller.ts`
- Validates refresh token signature
- Finds session by `sessionId`
- If session nearing expiry (≤ 1 day), extends it and rotates refresh token
- Always issues a **new access token**

---

# 3) Transport Layer (Cookies vs Headers)

**Tokens are transported via HttpOnly cookies**, not Authorization headers.

**Backend sets cookies:**
- `setAuthenticationCookies()`  
  **File:** `apps/api/src/common/utils/cookie.ts`

```ts
res.cookie('accessToken', accessToken, { httpOnly: true, sameSite, secure, path: '/' })
res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite, secure, path: '/api/v1/auth/refresh' })
```

**Frontend sends cookies**
- Axios uses `withCredentials: true`  
  **Files:**  
  `apps/next-web/src/lib/axios-client.ts`  
  `apps/react-web/src/lib/axios-client.ts`

No Authorization header flow is present.

---

# 4) Parsing + Validation (Backend Middleware)

**Middleware**
- `passport-jwt` strategy  
  **File:** `apps/api/src/common/strategies/jwt.strategy.ts`

**Extractor**
- Uses `ExtractJwt.fromExtractors` to read `req.cookies.accessToken`.

**Validation**
- Verifies JWT signature with `config.JWT.SECRET`
- Enforces `audience: ['user']` and `algorithms: ['HS256']`
- Loads user from DB using `payload.userId`
- Attaches `sessionId` to `req`

**Important comment in code**
```ts
// FIXME: We maybe need to check if the sessionId is valid and if it is expired
```
This is currently **not enforced**, which allows a valid access token to remain usable even if its session is deleted.

---

# 5) Silent Refresh Mechanism (Frontend)

## 5.1 Next‑Web (Next.js)
**File:** `apps/next-web/src/lib/axios-client.ts`

- On 401 with `errorCode === 'AUTH_TOKEN_NOT_FOUND'`:
  1. calls `/auth/refresh`
  2. retries original request
  3. redirects to `/` if refresh fails

**Limitations**
- Only triggers on **AUTH_TOKEN_NOT_FOUND**.  
  If access token is expired/invalid but still present, backend may return a different error code → refresh won’t happen.

- **No request queue / lock**.  
  Multiple simultaneous 401s can trigger multiple refresh requests.

---

## 5.2 React‑Web (Vite)
**File:** `apps/react-web/src/lib/axios-client.ts`

- Similar refresh attempt
- Uses a `_retry` flag to prevent infinite loops
- Does **not** redirect (avoids refresh loop)

**Still missing**
- No centralized queue while refresh is in progress.
- Only handles `AUTH_TOKEN_NOT_FOUND`.

---

# 6) Findings & Corrections (Security / Code Smells)

## Finding A — MFA Setup Verification trusts client‑provided secret  
**Risk:** Attacker who already has session can enable MFA using a secret that is **not** the one stored in DB. This can lock out users or mis‑bind the second factor.

**Current (file: `mfa.service.ts`)**
```ts
const isValid = speakeasy.totp.verify({
  secret: secretKey, // from client
  token: code,
});
```

**Corrected Approach**
```ts
const secretKey = user.userPreferences.twoFactorSecret;
if (!secretKey) throw new BadRequestException("MFA secret not initialized");

const isValid = speakeasy.totp.verify({
  secret: secretKey,
  encoding: "base32",
  token: code,
  window: 1,
});
```

**Security Principle:**  
**Never trust client‑provided cryptographic material**. Always verify using server‑stored secrets.

---

## Finding B — Session not validated during JWT auth  
**Risk:** A stolen access token remains valid even if session is revoked (logout) or expired.

**Current (file: `jwt.strategy.ts`)**
```ts
// FIXME: We maybe need to check if the sessionId is valid and if it is expired
return done(null, user)
```

**Corrected Approach**
```ts
const session = await SessionModel.findById(payload.sessionId);
if (!session || session.expiredAt.getTime() <= Date.now()) {
  return done(null, false);
}
req.sessionId = session._id;
return done(null, user);
```

**Security Principle:**  
**JWT validation must include server‑side session validity** when you support logout/session revocation.

---

## Finding C — Refresh endpoint uses GET + no CSRF protection  
**Risk:** Cookie‑based auth endpoints that mutate state should be protected from CSRF.

**Current**
- `GET /auth/refresh`

**Recommended**
- Change to **POST** and add CSRF defense (double‑submit token or sameSite+CSRF header).

**Security Principle:**  
**State‑changing actions should not be GET** and should be CSRF‑protected when using cookies.

---

## Finding D — Silent refresh handles only `AUTH_TOKEN_NOT_FOUND`  
**Risk:** Expired/invalid access tokens may not trigger refresh, leading to user‑visible failures.

**Suggested**
- Refresh on any 401 from protected endpoints **unless** refresh itself fails or request is already retried.

---

## Finding E — No refresh‑token rotation / reuse detection  
**Risk:** Stolen refresh token remains valid until expiry; no replay detection.

**Recommended (token rotation + reuse detection):**
1. Add `jti` to refresh token payload.
2. Store hash of latest refresh token (or `jti`) in session.
3. On refresh, check hash, rotate token each time.
4. On mismatch, revoke session.

Example:
```ts
const jti = crypto.randomUUID();
const refreshToken = signJwtToken({ sessionId: session._id, jti }, refreshTokenSignOptions);
session.refreshTokenHash = hash(refreshToken);
await session.save();
```

---

# 7) Advanced Concepts (PKCE / Rotation / Blacklisting)

## PKCE
Not present.  
Only applicable if you add OAuth 2.0 (Authorization Code flow).  
If you implement OAuth later, use PKCE like:
- Generate code_verifier + code_challenge on client
- Send challenge in auth request
- Send verifier in token exchange

---

## Token Rotation (Recommended)
Rotation is **partial** (only when session nears expiry).  
For best security, rotate refresh token **every** refresh.

---

## Token Blacklisting
Not implemented.

**Example approach (revocation list):**
```ts
// On logout:
await SessionModel.findByIdAndDelete(sessionId);

// In JWT strategy:
if (!session) return done(null, false);
```

For stricter security, store `tokenVersion` in user/session and invalidate tokens when version changes.

---

# 8) Additional Observations

- **Cookies are HttpOnly + sameSite + secure (prod)** — good baseline.
- **Refresh cookie is path‑scoped** to `/api/v1/auth/refresh` — good.
- **No rate limiting on MFA verification** — could allow brute forcing 6‑digit TOTP.  
  Suggest rate‑limit `/mfa/verify-login` per email + IP.

---

# 9) Summary of Core Logic (Snippets)

## Login + MFA Gate (AuthService)
```ts
if (user.userPreferences.enable2FA) {
  return { user: null, mfaRequired: true, accessToken: '', refreshToken: '' };
}
```

## MFA Login Verification (MfaService)
```ts
const isValid = speakeasy.totp.verify({ secret: user.userPreferences.twoFactorSecret!, token: code });
if (!isValid) throw new BadRequestException(...);

const session = await SessionModel.create({ userId: user._id, userAgent });
const accessToken = signJwtToken({ userId: user._id, sessionId: session._id });
const refreshToken = signJwtToken({ sessionId: session._id }, refreshTokenSignOptions);
```

## Refresh Token Flow (AuthService)
```ts
const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, { secret: refreshTokenSignOptions.secret });
const session = await SessionModel.findById(payload.sessionId);
if (session.expiredAt <= now) throw UnauthorizedException("Session expired");
// Maybe rotate refresh token if near expiry
```

---
Below is a deeper, low‑level architectural teardown focused on *why* the system is built this way, how it behaves under stress, and where the design assumptions create gaps. I’ll reference concrete files and then explain the architectural rationale and consequences.

---

# 0) Architecture Overview (Why it’s structured this way)
**Intent:**  
This system blends *stateless* access tokens (JWT) with a *stateful* session record to get the best of both worlds:

- **JWT access token** → fast request auth without DB lookups on every request (stateless).
- **Refresh token + Session DB** → long‑lived sessions, device listing, and server‑side revocation (stateful).
- **HttpOnly cookies** → avoid token exposure to XSS and centralize transport.

This is a common hybrid design: JWT for speed, session DB for control.

---

# 1) Token Entropy (How unpredictable are tokens?)
**Files:**  
- `apps/api/src/common/utils/jwt.ts`

### What actually provides entropy?
JWTs here are **deterministic** given:
- Header (fixed: HS256)
- Payload (`userId`, `sessionId`, plus default `iat`)
- HMAC secret

**Payload fields (userId/sessionId) are not secret:**
- `userId` is a MongoDB ObjectId (partially timestamp‑based).
- `sessionId` is also an ObjectId.

**Conclusion:**  
**Token unpredictability is almost entirely dependent on the HMAC secret.**  
If `JWT_SECRET` is weak or reused across environments, tokens are forgeable.

**Recommended baseline:**  
- 256‑bit (32+ bytes) cryptographically random secret  
- Rotation strategy via `kid` header (not implemented)

---

# 2) Token TTL / Expiration Strategy (Why these numbers?)
**Files:**  
- `apps/api/src/config/app.config.ts`  
- `apps/api/src/common/utils/date-time.ts`  
- `apps/api/src/modules/auth/auth.service.ts`  
- `apps/api/src/database/models/session.model.ts`

### Access Token TTL
- `JWT_EXPIRES_IN` default **15 minutes**
- Short TTL reduces blast radius if stolen.

### Refresh Token TTL
- `JWT_REFRESH_EXPIRES_IN` default **30 days**
- Long TTL for “stay logged in” UX.

### Session TTL
- `SessionModel.expiredAt` default **30 days**
- Session is the *server‑side anchor* for refresh tokens.

### Sliding Refresh Window (Why?)
In `auth.service.ts`, refresh will **extend** the session only if it’s within **1 day** of expiry:

```ts
session.expiredAt.getTime() - now <= ONE_DAY_IN_MS
```

**Why:**  
- Avoids rewriting session on every refresh
- Reduces DB writes
- Keeps long‑term sessions alive with “active use” pattern

**Downside:**  
Refresh token rotation is *not enforced every time*. This makes replay attacks possible if a refresh token is stolen.

---

# 3) Signature Verification & Claims Validation
**Files:**  
- `apps/api/src/common/utils/jwt.ts`  
- `apps/api/src/common/strategies/jwt.strategy.ts`

### Signature
- **Algorithm:** HS256 (symmetric)
- Verified via `jsonwebtoken.verify` using `JWT_SECRET`

### Claims Validation
**What’s validated:**
- `aud` = `["user"]`  
  (set in `defaults` and checked in verification)
- `algorithms: ['HS256']` in passport strategy

**What’s NOT validated:**
- `iss` (issuer)  
- `sub` (subject)  
- `scope` / role claims  
- `jti` (token ID)

**Architecture implication:**  
The system assumes **“any token signed by our secret and marked `aud=user` is valid.”**  
This is acceptable for a single‑tenant app, but becomes risky with multi‑audience or multi‑service architectures.

---

# 4) How Identity is Hydrated & Propagated (API “Gateway” Flow)

There is **no separate API Gateway**. The Express app itself is the gatekeeper.

### JWT Strategy (Middleware Layer)
**File:** `apps/api/src/common/strategies/jwt.strategy.ts`

Flow:
1. Access token extracted from **cookie** (`req.cookies.accessToken`).
2. JWT verified (signature + `aud`).
3. `payload.userId` is used to query DB:
   ```ts
   const user = await userService.findUserById(payload.userId)
   ```
4. `req.user` becomes this user.
5. `req.sessionId` is set from token payload.

### Downstream Services
- Controllers read `req.user` and `req.sessionId`
- Example: `SessionController.getAllSession` uses `req.user?.id`
- `SessionService.getSessionById` uses sessionId to populate user

**Architectural “why”:**
- Keeps controllers free of auth parsing logic
- Centralizes identity hydration in one middleware (passport‑jwt)

**Critical gap:**
There is **no DB validation that the session is still valid** inside JWT strategy (it’s noted as FIXME).  
This weakens server‑side revocation.

---

# 5) MFA Architecture (Low‑Level Why)
**Files:**  
- `apps/api/src/modules/mfa/mfa.service.ts`  
- `apps/api/src/modules/auth/auth.service.ts`

### Why TOTP?
- Offline (no SMS dependency)
- Works with standard authenticators
- Low operational cost

### How the flow works
1. Login → if `enable2FA`, server returns `mfaRequired: true`.
2. Frontend redirects to `/verify-mfa?email=...`.
3. `/mfa/verify-login` checks TOTP and issues session + tokens.

**Architectural flaw:**  
The MFA step **is not tied to the original password login**.  
Anyone with **email + valid TOTP** can log in *without* password.  
This breaks the “second factor” model.

**Correct pattern:**  
- Issue a temporary `mfa_token` after password validation  
- Require it in `/mfa/verify-login`  
- Expire it after short TTL

---

# 6) Frontend Interceptor — Race Conditions & Double Refresh
**Files:**  
- `apps/next-web/src/lib/axios-client.ts`  
- `apps/react-web/src/lib/axios-client.ts`

### Current Behavior (Both Frontends)
- On 401 + `AUTH_TOKEN_NOT_FOUND`, call `/auth/refresh`
- Retry original request after refresh
- If refresh fails → reject or redirect

### What happens on **simultaneous 401s**?
**There is no global lock or request queue.**  
Each request independently calls refresh.

#### “Double refresh” scenario:
- 5 requests fail at once → 5 refresh calls
- If refresh token rotation were strict, this would cause invalidation races
- Current code rotates refresh token only **sometimes**, so it “works” but wastes requests

### No Request Queue
There is **no mechanism** like:
- `isRefreshing` flag
- subscriber queue for pending requests
- waiting for refresh to finish before retrying all failed requests

**Result:**  
- Thundering‑herd refresh calls  
- Possible state inconsistency if refresh token rotation is added later

---

# 7) Token Leakage Risk (Storage & Transport)
**Good Practices Present**
- Tokens stored in **HttpOnly cookies**
- `sameSite` + `secure` configured
- No localStorage usage

**Risks / Gaps**
- **Access token cookie** is path `/` → sent on all requests
- **Refresh token cookie** uses path `/auth/refresh` (good)
- **CSRF risk** remains for state‑changing routes because cookies are auto‑sent  
  (mitigated partially by SameSite strict in prod)

**MFA leakage**  
- MFA secret is returned to frontend and shown in UI → expected but sensitive  
- Stored in DB in plaintext (base32) — if DB leaks, MFA secret leaks

---

# 8) Refresh Token Rotation / Revocation / Blacklist
**Files:**  
- `apps/api/src/modules/auth/auth.service.ts`

### Rotation
- **Only rotates** refresh token **when session is near expiry**
- Otherwise refresh token persists for full 30 days

### Revocation
- Logout deletes `SessionModel`
- BUT **JWT middleware does not check session** → access token remains valid until it expires

### Blacklist
- **Not implemented**
- No `jti`, no token version, no denylist in DB/Redis

**Impact:**  
The system **cannot instantly revoke access tokens** after logout or compromise.

---

# 9) Claims Handling for User Lookup
There is no `sub` claim. Instead:
```ts
payload.userId  // custom field
```

This is used to query MongoDB:
```ts
UserModel.findById(userId)
```

**Why:**  
Simpler than standardized OIDC claims.

**Downside:**  
No interoperability with external identity providers, and no clean migration to OAuth/OIDC without refactor.

---

# 10) Additional Notable Architectural Gaps

### MFA verification trusts client secret
**File:** `mfa.service.ts`
- Client sends `secretKey`
- Server verifies against that secret instead of server‑stored secret

**Risk:**  
User can “enable” MFA with a secret that does not match server storage, locking themselves out.

---

### Next.js middleware logic
**File:** `apps/next-web/middleware.ts`

- Only checks *presence* of access token in cookie
- Doesn’t validate expiry
- Will allow navigation even if token is expired

**Result:**  
User sees protected pages until API calls fail → inconsistent UX

---

### Session cleanup
Session model has no TTL index → expired sessions remain in DB.

---

# 11) Summary of Architectural “Why” + Consequences

| Design Choice | Why It Exists | Consequence |
|---|---|---|
| JWT access tokens | Stateless fast auth | Hard to revoke immediately |
| Refresh token + sessions | Long‑lived login + device list | Needs strong session validation |
| HttpOnly cookies | Prevent XSS token theft | CSRF risk unless properly mitigated |
| TOTP MFA | Low cost, offline | Must be bound to login attempt |
| Partial refresh rotation | Reduce DB writes | Replay risk if token stolen |
| No queue in interceptor | Simpler client | Race conditions + multiple refreshes |

---

# 12) What’s Missing (for strong security posture)

**1) MFA step should be bound to password login**
- Temporary MFA token or pending login session

**2) Session validation in JWT strategy**
- Reject access tokens tied to deleted/expired sessions

**3) Proper refresh rotation every refresh**
- Store refresh token hash or `jti` in session

**4) Refresh token reuse detection**
- If reuse detected → revoke session

**5) Anti‑CSRF strategy**
- Switch refresh to POST + CSRF token check

**6) Request queue in interceptor**
- `isRefreshing` + subscriber queue

---

Below are **detailed, low‑level code snippets** for **every topic** we discussed, with **explicit comments** explaining the “why,” trade‑offs, and how it addresses each architectural gap. These are **illustrative patches** you can apply to the repo (file references included).

---

# 1) Strong Token Entropy (Secrets & Guardrails)
**Why:** JWTs are only as strong as your signing secrets.

**File:** `apps/api/src/config/app.config.ts`  
**Add a runtime check (example):**
```ts
// app.config.ts
const requireStrongSecret = (value: string, name: string) => {
  // 32 bytes = 256 bits is a good minimum for HS256
  if (!value || value.length < 32) {
    throw new Error(`${name} must be at least 32 chars (256-bit) for HS256`);
  }
  return value;
};

JWT: {
  SECRET: requireStrongSecret(getEnv('JWT_SECRET'), 'JWT_SECRET'),
  REFRESH_SECRET: requireStrongSecret(getEnv('JWT_REFRESH_SECRET'), 'JWT_REFRESH_SECRET'),
  EXPIRES_IN: getEnv('JWT_EXPIRES_IN', '15m'),
  REFRESH_EXPIRES_IN: getEnv('JWT_REFRESH_EXPIRES_IN', '30d'),
},
```

---

# 2) Access + Refresh Tokens with Issuer / Audience / Subject / Scopes
**Why:** Standard claims enable strict validation and future interoperability.

**File:** `apps/api/src/common/utils/jwt.ts`
```ts
import jwt, { SignOptions, VerifyOptions } from "jsonwebtoken";

// ✅ Standardized token payload
export type AccessTPayload = {
  sub: string;            // subject (user id)
  sessionId: string;      // session id for server-side revocation
  scope: string[];        // custom scopes/roles (optional)
};

export type RefreshTPayload = {
  sub: string;
  sessionId: string;
  jti: string;            // unique token id to detect reuse
};

// ✅ Shared defaults for all tokens
const defaults: SignOptions = {
  audience: ["user"],
  issuer: "gainometer-api", // add an issuer for validation
};

export const signAccessToken = (payload: AccessTPayload) => {
  return jwt.sign(payload, config.JWT.SECRET, {
    ...defaults,
    expiresIn: config.JWT.EXPIRES_IN,
  });
};

export const signRefreshToken = (payload: RefreshTPayload) => {
  return jwt.sign(payload, config.JWT.REFRESH_SECRET, {
    ...defaults,
    expiresIn: config.JWT.REFRESH_EXPIRES_IN,
  });
};

// ✅ Strict verification with issuer + audience + algorithm
export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, config.JWT.SECRET, {
    audience: ["user"],
    issuer: "gainometer-api",
    algorithms: ["HS256"],
  }) as AccessTPayload;
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, config.JWT.REFRESH_SECRET, {
    audience: ["user"],
    issuer: "gainometer-api",
    algorithms: ["HS256"],
  }) as RefreshTPayload;
};
```

---

# 3) Session Model w/ Refresh Rotation & TTL Index
**Why:** Enforce rotation and auto‑cleanup of expired sessions.

**File:** `apps/api/src/database/models/session.model.ts`
```ts
const sessionSchema = new Schema<SessionDocument>({
  userId: { type: Schema.Types.ObjectId, ref: "User", index: true, required: true },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now },
  expiredAt: { type: Date, required: true, default: thirtyDaysFromNow },

  // ✅ store refresh token hash (for rotation / reuse detection)
  refreshTokenHash: { type: String, required: false },
});

// ✅ TTL index: Mongo auto‑deletes expired sessions
sessionSchema.index({ expiredAt: 1 }, { expireAfterSeconds: 0 });
```

---

# 4) JWT Strategy: Validate Session + Scopes
**Why:** Access tokens must be rejected if session is revoked or expired.

**File:** `apps/api/src/common/strategies/jwt.strategy.ts`
```ts
passport.use(
  new JwtStrategy(options, async (req, payload: JwtPayload, done) => {
    try {
      // ✅ Ensure user exists
      const user = await userService.findUserById(payload.sub);
      if (!user) return done(null, false);

      // ✅ Validate session still active
      const session = await SessionModel.findById(payload.sessionId);
      if (!session || session.expiredAt.getTime() <= Date.now()) {
        return done(null, false);
      }

      // ✅ Optional: enforce scope/role here
      // if (!payload.scope?.includes("read:session")) return done(null, false);

      req.sessionId = payload.sessionId;
      return done(null, user);
    } catch (error) {
      return done(error, false);
    }
  })
);
```

---

# 5) MFA Setup — Verify Using Server Secret Only
**Why:** Never trust client‑provided secret during TOTP verification.

**File:** `apps/api/src/modules/mfa/mfa.service.ts`
```ts
public async verifyMFASetup(req: Request, code: string) {
  const user = req.user;
  if (!user) throw new UnauthorizedException("User not authorized");

  const secretKey = user.userPreferences.twoFactorSecret;
  if (!secretKey) throw new BadRequestException("MFA secret not initialized");

  // ✅ Verify against server‑stored secret (not client input)
  const isValid = speakeasy.totp.verify({
    secret: secretKey,
    encoding: "base32",
    token: code,
    window: 1, // allow slight clock drift
  });

  if (!isValid) throw new BadRequestException("Invalid MFA code");

  user.userPreferences.enable2FA = true;
  await user.save();
  return { message: "MFA enabled", userPreferences: { enable2FA: true } };
}
```

---

# 6) MFA Login: Bind MFA to Password Login
**Why:** Prevent “email + OTP only” bypass.

### Step A: Password login returns a temporary MFA token
**File:** `apps/api/src/modules/auth/auth.service.ts`
```ts
if (user.userPreferences.enable2FA) {
  // ✅ Create a temporary MFA token (short TTL)
  const mfaToken = jwt.sign(
    { sub: user._id, purpose: "mfa", exp: Math.floor(Date.now() / 1000) + 300 },
    config.JWT.SECRET
  );

  return { mfaRequired: true, mfaToken, user: null };
}
```

### Step B: MFA verify requires that token
**File:** `apps/api/src/modules/mfa/mfa.service.ts`
```ts
public async verifyMFAForLogin(code: string, email: string, mfaToken: string, userAgent?: string) {
  // ✅ Verify MFA token first (binds to password step)
  const decoded = jwt.verify(mfaToken, config.JWT.SECRET) as any;
  if (decoded.purpose !== "mfa") throw new UnauthorizedException("Invalid MFA token");

  // ✅ Then validate TOTP
  const user = await UserModel.findOne({ email });
  if (!user) throw new NotFoundException("User not found");

  const isValid = speakeasy.totp.verify({
    secret: user.userPreferences.twoFactorSecret!,
    encoding: "base32",
    token: code,
    window: 1,
  });

  if (!isValid) throw new BadRequestException("Invalid MFA code");

  // ✅ Issue access/refresh tokens after successful MFA
  ...
}
```

---

# 7) Refresh Token Rotation + Reuse Detection
**Why:** Stops replay attacks with stolen refresh tokens.

**File:** `apps/api/src/modules/auth/auth.service.ts`
```ts
import crypto from "crypto";
import { hashValue, compareValue } from "../common/utils/bcrypt";

public async refreshToken(refreshToken: string) {
  const payload = verifyRefreshToken(refreshToken);

  const session = await SessionModel.findById(payload.sessionId);
  if (!session) throw new UnauthorizedException("Session not found");

  // ✅ Reuse detection: compare stored hash with incoming token
  const isValid = await compareValue(refreshToken, session.refreshTokenHash || "");
  if (!isValid) {
    // token reuse detected → revoke session
    await SessionModel.findByIdAndDelete(session._id);
    throw new UnauthorizedException("Refresh token reuse detected");
  }

  // ✅ Rotate refresh token every time
  const newJti = crypto.randomUUID();
  const newRefreshToken = signRefreshToken({
    sub: payload.sub,
    sessionId: session._id.toString(),
    jti: newJti,
  });

  session.refreshTokenHash = await hashValue(newRefreshToken);
  await session.save();

  const accessToken = signAccessToken({
    sub: payload.sub,
    sessionId: session._id.toString(),
    scope: ["user:read"],
  });

  return { accessToken, newRefreshToken };
}
```

---

# 8) CSRF Protection on Refresh
**Why:** Cookies are auto‑sent, so refresh needs CSRF protection.

**Backend:**
```ts
// Require a custom header set by client
if (req.headers["x-csrf-token"] !== req.cookies["csrfToken"]) {
  throw new UnauthorizedException("CSRF token mismatch");
}
```

**Frontend:**
```ts
APIRefresh.get("/auth/refresh", {
  headers: {
    "x-csrf-token": getCookie("csrfToken"), // from non-HttpOnly cookie
  },
});
```

---

# 9) Axios Interceptor — Single Refresh + Request Queue
**Why:** Prevent double‑refresh and race conditions.

**File:** `apps/react-web/src/lib/axios-client.ts` (same for Next)
```ts
let isRefreshing = false;
let refreshQueue: ((tokenRefreshed: boolean) => void)[] = [];

const processQueue = (success: boolean) => {
  refreshQueue.forEach((cb) => cb(success));
  refreshQueue = [];
};

API.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { data, status, config } = error.response;

    if (status === 401 && data.errorCode === "AUTH_TOKEN_NOT_FOUND") {
      if (isRefreshing) {
        // ✅ Queue the request until refresh completes
        return new Promise((resolve, reject) => {
          refreshQueue.push((success) => {
            if (success) resolve(API(config));
            else reject(error);
          });
        });
      }

      isRefreshing = true;

      try {
        await APIRefresh.post("/auth/refresh"); // refresh endpoint
        processQueue(true);
        return API(config);
      } catch (e) {
        processQueue(false);
        return Promise.reject(e);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(data);
  }
);
```

---

# 10) Revocation List (Token Blacklist Alternative)
**Why:** Enforce immediate invalidation.

**Approach A — token version**
```ts
// In user model
tokenVersion: { type: Number, default: 0 }

// In JWT payload
{ sub, sessionId, tokenVersion }

// In JWT strategy
if (payload.tokenVersion !== user.tokenVersion) return done(null, false);

// On logout all devices
await UserModel.updateOne({ _id: userId }, { $inc: { tokenVersion: 1 } });
```

---

# 11) Identity Hydration (sub/uid claim → DB lookup)
**Why:** Clean, standardized claim usage.

```ts
// token payload uses sub
const payload = verifyAccessToken(token);
const user = await UserModel.findById(payload.sub, { password: 0 });
req.user = user;
```

---

# 12) Cookie Settings (Prevent Leakage)
**Why:** Prevent XSS + restrict cookie scope.

```ts
res.cookie("accessToken", accessToken, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",                 // access token for all routes
  maxAge: 15 * 60 * 1000,    // 15 min
});

res.cookie("refreshToken", refreshToken, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/api/v1/auth/refresh",
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
});
```

---

# 13) MFA Rate Limiting (Brute‑Force Mitigation)
**Why:** TOTP is only 6 digits.

```ts
// Example: simple per-email limit within 5 minutes
const attempts = await LoginAttempt.countDocuments({
  email,
  createdAt: { $gt: fiveMinutesAgo() },
});
if (attempts > 5) throw new HttpException("Too many MFA attempts", 429);
```

---
