# @startino/better-auth-oidc

OIDC-only SSO plugin for [Better Auth](https://www.better-auth.com/). Runs on any JavaScript runtime without Node.js-specific APIs.

## Why this exists

The official [`@better-auth/sso`](https://www.better-auth.com/docs/plugins/sso) plugin imports `samlify` at module load, which requires Node.js-only APIs (`node:crypto`, `node:buffer`). This breaks in edge runtimes, serverless environments, or any platform without full Node.js compatibility, even if you only need OIDC.

This package extracts the OIDC code paths into a standalone plugin. SAML code and Node.js dependencies are removed entirely.

## Runtime compatibility

| Runtime | `@better-auth/sso` | `@startino/better-auth-oidc` |
|---|---|---|
| Node.js | Yes | Yes |
| Convex | No | Yes |
| Cloudflare Workers | No | Yes |
| Deno | No | Yes |
| Bun | Yes | Yes |
| Vercel Edge | No | Yes |

## Install

```bash
# bun
bun add @startino/better-auth-oidc

# npm
npm install @startino/better-auth-oidc

# pnpm
pnpm add @startino/better-auth-oidc
```

Peer dependencies: `better-auth` (>=1.4.0), `better-call` (>=1.0.0).

## Quick start

### Server

```ts
import { betterAuth } from "better-auth";
import { oidcSso } from "@startino/better-auth-oidc";

export const auth = betterAuth({
  // ... your config
  plugins: [
    oidcSso({
      // Optional: provision users into orgs on first sign-in
      organizationProvisioning: {
        defaultRole: "member",
      },
      // Optional: verify domain ownership via DNS TXT records
      domainVerification: {
        enabled: true,
      },
    }),
  ],
});
```

### Client

```ts
import { createAuthClient } from "better-auth/client";
import { oidcSsoClient } from "@startino/better-auth-oidc/client";

const client = createAuthClient({
  plugins: [
    oidcSsoClient({
      // Must match server config
      domainVerification: { enabled: true },
    }),
  ],
});

// Register an OIDC provider
await client.sso.register({
  providerId: "okta-acme",
  issuer: "https://acme.okta.com",
  domain: "acme.com",
  oidcConfig: {
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
  },
});

// Sign in with SSO
await client.signIn.sso({
  email: "user@acme.com",
  callbackURL: "/dashboard",
});
```

## SSO flow overview

Here is what happens during an SSO sign-in:

```
┌────────┐            ┌─────────────┐            ┌─────┐            ┌─────┐
│ Client │            │ Auth Server │            │ IdP │            │ App │
└───┬────┘            └──────┬──────┘            └──┬──┘            └──┬──┘
    │                        │                      │                  │
    │  POST /sign-in/sso     │                      │                  │
    │───────────────────────>│                      │                  │
    │                        │                      │                  │
    │                        │  302 → authorize     │                  │
    │                        │─────────────────────>│                  │
    │                        │                      │                  │
    │                        │  User logs in        │                  │
    │                        │                      │                  │
    │                        │  GET /sso/callback   │                  │
    │                        │<─────────────────────│                  │
    │                        │                      │                  │
    │                        │  Exchange code       │                  │
    │                        │  for tokens          │                  │
    │                        │─────────────────────>│                  │
    │                        │<─────────────────────│                  │
    │                        │                      │                  │
    │                        │  Create/link user    │                  │
    │                        │  Create session      │                  │
    │                        │  Generate OTT        │                  │
    │                        │                      │                  │
    │                        │       302 → callbackURL?ott=TOKEN       │
    │                        │────────────────────────────────────────>│
    │                        │                      │                  │
    │                        │       GET /sso/verify-ott?token=…       │
    │                        │<────────────────────────────────────────│
    │                        │                      │                  │
    │                        │    Set session cookie on app domain     │
    │                        │────────────────────────────────────────>│
    │                        │                      │                  │
    ▼                        ▼                      ▼                  ▼
```

1. **Sign-in request.** The client calls `POST /sign-in/sso` with an email, domain, or provider ID. The plugin finds the matching SSO provider and builds the OIDC authorization URL.
2. **Redirect to IdP.** The user is redirected to the identity provider (Okta, Entra ID, Google Workspace, etc.) to authenticate.
3. **Callback.** The IdP redirects back to `GET /sso/callback/:providerId` with an authorization code.
4. **Token exchange.** The plugin exchanges the code for an ID token and (optionally) access token. The ID token is verified against the provider's JWKS.
5. **User creation/linking.** A user account is created or linked. Organization membership is assigned if configured.
6. **OTT generation.** A one-time token is created (32 random characters, 60-second TTL) and appended to the callback URL as `?ott=TOKEN`.
7. **OTT verification.** The app calls `GET /sso/verify-ott?token=TOKEN` through its proxy to the auth server. This sets the session cookie on the app's domain.

## Cross-domain session transfer (OTT)

### The problem

In proxy-based architectures (SvelteKit + Convex, Next.js + external auth server, etc.), the auth server runs on a different domain than your app. The SSO callback hits the auth server's domain, so the session cookie is set there, not on the app's domain.

Without OTT, the user would be redirected back to the app with no session.

### How it works

After the SSO callback processes the sign-in, the plugin:

1. Creates a session and sets the cookie on the auth server's domain
2. Generates a one-time token (32 characters, stored in the `verification` table, expires in 60 seconds)
3. Redirects to your `callbackURL` with `?ott=TOKEN` appended

Your app then verifies the OTT through its auth proxy, which sets the session cookie on the correct domain.

### Client-side implementation

On whichever page your `callbackURL` points to, check for the `ott` query parameter and verify it:

```ts
// Example: SvelteKit +page.ts or +page.server.ts
import { redirect } from "@sveltejs/kit";

export const load = async ({ url, fetch }) => {
  const ott = url.searchParams.get("ott");
  if (ott) {
    // Call through your proxy so the cookie is set on your domain
    const res = await fetch(`/api/auth/sso/verify-ott?token=${ott}`);
    if (!res.ok) {
      throw redirect(303, "/signin?error=sso-verification-failed");
    }
    // Remove the ott param from the URL
    throw redirect(303, url.pathname);
  }
};
```

```ts
// Example: Next.js middleware or page
const ott = searchParams.get("ott");
if (ott) {
  await fetch(`${process.env.NEXT_PUBLIC_URL}/api/auth/sso/verify-ott?token=${ott}`, {
    credentials: "include",
  });
  redirect("/dashboard");
}
```

The key requirement: the `verify-ott` call must go through your app's proxy to the auth server so the `Set-Cookie` header lands on your app's domain.

### Avoiding `ott` param conflicts

Some auth libraries (notably `convex-better-auth-svelte`) auto-intercept `?ott=` in the URL and try to verify it through Better Auth's built-in cross-domain plugin. This is a different endpoint and token format than this plugin's `/sso/verify-ott`. If the cross-domain plugin isn't installed, this causes an unhandled error.

**Fix:** Strip or rename the `ott` param server-side before it reaches the client. In SvelteKit, use a `+page.server.ts` on your callback page:

```ts
// +page.server.ts on your SSO callback page
import { redirect } from "@sveltejs/kit";

export const load = async ({ url, params }) => {
  const ott = url.searchParams.get("ott");
  if (!ott) return {};

  // Rename ott to sso_ott so other libraries don't intercept it.
  // Your client-side code reads sso_ott instead.
  throw redirect(302, `/${params.org}/signin?sso_callback=true&sso_ott=${encodeURIComponent(ott)}`);
};
```

Then read `sso_ott` in your client-side callback handler instead of `ott`.

If your callback page doesn't need OTT verification at all (e.g. the user is already authenticated and you're only re-verifying their identity), strip the `ott` entirely:

```ts
// +page.server.ts — just drop the ott param
import { redirect } from "@sveltejs/kit";

export const load = async ({ url, params }) => {
  if (url.searchParams.get("callback") === "true" && url.searchParams.get("ott")) {
    throw redirect(302, `/${params.org}/sso-verify?callback=true`);
  }
  return {};
};
```

### Configuring error redirects for cross-domain setups

When the auth server runs on a different domain than your app, Better Auth's OAuth error handling (expired state, state mismatch, PKCE failures) redirects to `${baseURL}/error`. If `baseURL` points to the auth server, users see a raw error page with no UI.

Set `onAPIError.errorURL` in your Better Auth config to redirect errors to your app instead:

```ts
const auth = betterAuth({
  baseURL: process.env.AUTH_SERVER_URL,
  onAPIError: {
    errorURL: process.env.APP_URL, // e.g. "https://myapp.com"
  },
  plugins: [oidcSso()],
});
```

Then handle the `?error=` query param on your app:

```ts
// In your root layout or error handler
const error = new URL(window.location.href).searchParams.get("error");
if (error) {
  // Show a user-friendly message. Common errors:
  // - please_restart_the_process (expired OAuth state)
  // - state_mismatch (state verification failed)
  // - invalid_state (corrupted state data)
  showError("Sign-in session expired. Please try again.");
}
```

## Configuration options

### `SSOOptions`

| Option | Type | Default | Description |
|---|---|---|---|
| `provisionUser` | `(data) => void` | - | Called after a user signs in or signs up via SSO. Receives `{ user, userInfo, token, provider }`. Use for custom role assignment, feature flags, syncing to external systems, etc. |
| `organizationProvisioning` | `object` | - | Auto-assign users to organizations based on SSO provider. See [Organization provisioning](#organization-provisioning). |
| `defaultSSO` | `Array<{ domain, providerId, oidcConfig? }>` | - | Default provider configs (takes precedence over DB). Useful for development/testing without storing providers in the database. |
| `defaultOverrideUserInfo` | `boolean` | `false` | Override user name/image with provider data on every sign-in, not just the first. |
| `disableImplicitSignUp` | `boolean` | `false` | Reject new users unless `requestSignUp: true` is passed in the sign-in call. |
| `modelName` | `string` | `"ssoProvider"` | Custom table name for SSO providers in the database. |
| `fields` | `object` | - | Remap column names: `{ issuer?, oidcConfig?, userId?, providerId?, organizationId?, domain? }`. |
| `providersLimit` | `number \| (user) => number` | `10` | Max providers a user can register. Set to `0` to disable registration entirely. |
| `trustEmailVerified` | `boolean` | `false` | Trust the `email_verified` claim from the IdP. **Deprecated.** See [Account linking](#account-linking-and-trustemailverified). |
| `domainVerification` | `object` | - | DNS-based domain ownership verification. See [Domain verification](#domain-verification). |
| `domainVerification.enabled` | `boolean` | `false` | Enable/disable domain verification. |
| `domainVerification.tokenPrefix` | `string` | `"better-auth-token"` | Prefix for the DNS TXT record. |

## OIDC configuration

When registering or updating a provider, the `oidcConfig` object controls how the plugin communicates with the identity provider.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `clientId` | `string` | Yes | - | OAuth client ID from your IdP. |
| `clientSecret` | `string` | Yes | - | OAuth client secret from your IdP. |
| `issuer` | `string` | - | Parent `issuer` | The OIDC issuer URL. Usually set on the provider, not inside `oidcConfig`. |
| `discoveryEndpoint` | `string` | No | `{issuer}/.well-known/openid-configuration` | Override the discovery URL if your IdP uses a non-standard path. |
| `skipDiscovery` | `boolean` | No | `false` | Skip automatic OIDC discovery. When `true`, you must provide `authorizationEndpoint`, `tokenEndpoint`, and `jwksEndpoint` manually. |
| `authorizationEndpoint` | `string` | If `skipDiscovery` | Discovered | OAuth authorization URL. |
| `tokenEndpoint` | `string` | If `skipDiscovery` | Discovered | OAuth token exchange URL. |
| `jwksEndpoint` | `string` | If `skipDiscovery` | Discovered | JWKS URL for ID token signature verification. |
| `userInfoEndpoint` | `string` | No | Discovered | UserInfo endpoint. Only needed if ID token claims are insufficient. |
| `tokenEndpointAuthentication` | `"client_secret_basic" \| "client_secret_post"` | No | Auto-detected | How to authenticate at the token endpoint. `client_secret_basic` sends credentials in the Authorization header. `client_secret_post` sends them in the request body. The plugin auto-selects based on IdP discovery, preferring `client_secret_basic`. |
| `pkce` | `boolean` | No | `true` | Use PKCE (Proof Key for Code Exchange) with S256 challenge method. Recommended to leave enabled. |
| `scopes` | `string[]` | No | `["openid", "email", "profile"]` | OAuth scopes to request. |
| `overrideUserInfo` | `boolean` | No | `false` | Override stored user info with provider data on this specific provider. |
| `mapping` | `OIDCMapping` | No | See below | Map non-standard claim names to expected fields. |

### Field mapping

If your IdP returns claims with non-standard names, use the `mapping` object to tell the plugin where to find each field.

```ts
oidcConfig: {
  clientId: "...",
  clientSecret: "...",
  mapping: {
    id: "sub",                // Default: "sub"
    email: "email",           // Default: "email"
    emailVerified: "email_verified", // Default: "email_verified"
    name: "name",             // Default: "name"
    image: "picture",         // Default: "picture"
    extraFields: {            // Map additional claims
      department: "custom:department",
      employeeId: "custom:employee_id",
    },
  },
}
```

The `extraFields` values are passed through to the `provisionUser` callback in `userInfo`.

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/sso/register` | POST | Yes | Register a new OIDC provider. |
| `/sign-in/sso` | POST | No | Initiate SSO sign-in. Accepts `email`, `providerId`, `domain`, or `organizationSlug` to find the provider. Returns `{ url, redirect: true }`. |
| `/sso/callback/:providerId` | GET | No | OAuth2 callback handler. Exchanges code for tokens, creates/links user, generates OTT, redirects to `callbackURL`. |
| `/sso/verify-ott` | GET | No | Exchange a one-time token for a session cookie. Query: `?token=TOKEN`. |
| `/sso/providers` | GET | Yes | List providers the authenticated user has access to. |
| `/sso/get-provider` | GET | Yes | Get a single provider. Query: `?providerId=ID`. |
| `/sso/update-provider` | POST | Yes | Update provider fields (partial update). Changing `domain` resets `domainVerified`. |
| `/sso/delete-provider` | POST | Yes | Delete a provider. Body: `{ providerId }`. |
| `/sso/request-domain-verification` | POST | Yes | Request a domain verification token (if enabled). |
| `/sso/verify-domain` | POST | Yes | Verify domain via DNS TXT record lookup (if enabled). |

### Sign-in options

The `POST /sign-in/sso` endpoint accepts these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | `string` | One of these | Extracts the domain to find a matching provider. |
| `providerId` | `string` | | Direct provider reference. |
| `domain` | `string` | | Direct domain reference. |
| `organizationSlug` | `string` | | Finds the org, then finds a provider linked to it. |
| `callbackURL` | `string` | Yes | Where to redirect after sign-in. The OTT is appended here. |
| `errorCallbackURL` | `string` | No | Redirect on error. Falls back to `callbackURL`. |
| `newUserCallbackURL` | `string` | No | Redirect for first-time users. Falls back to `callbackURL`. |
| `scopes` | `string[]` | No | Override the provider's default scopes for this sign-in. |
| `loginHint` | `string` | No | Pre-fill the email/username at the IdP login screen. |
| `requestSignUp` | `boolean` | No | Required when `disableImplicitSignUp` is `true`. |

## Organization provisioning

If you use Better Auth's [organization plugin](https://www.better-auth.com/docs/plugins/organization), you can auto-assign users to organizations when they sign in via SSO.

```ts
oidcSso({
  organizationProvisioning: {
    defaultRole: "member",         // "member" or "admin"
    getRole: async ({ user, userInfo, token, provider }) => {
      // Custom logic, e.g. check a group claim
      const groups = userInfo["groups"] || [];
      return groups.includes("admins") ? "admin" : "member";
    },
  },
});
```

How it works:

1. When registering a provider, pass `organizationId` to link it to an org.
2. On sign-in, after the user account is created or linked, the plugin checks if the provider has an `organizationId`.
3. If the user is not already a member of that org, they are added with the role from `getRole()` (or `defaultRole` if no function provided).

Set `organizationProvisioning.disabled: true` to turn off auto-provisioning while keeping the config.

### `provisionUser` callback

For more control beyond org assignment, use `provisionUser`. It runs after the user is created/linked and after org assignment.

```ts
oidcSso({
  provisionUser: async ({ user, userInfo, token, provider }) => {
    // Sync to your own database, assign feature flags, send a welcome email, etc.
    await myDb.upsertUser({
      id: user.id,
      department: userInfo.department,
      ssoProvider: provider.providerId,
    });
  },
});
```

The `token` parameter contains the OAuth2 tokens (access token, refresh token, ID token) from the provider if you need to make further API calls.

## Multi-domain SSO

A single SSO provider can serve multiple email domains. Pass a comma-separated string:

```ts
await client.sso.register({
  providerId: "acme-corp",
  issuer: "https://acme.okta.com",
  domain: "acme.com,subsidiary.com,acquired-co.com",
  oidcConfig: { clientId: "...", clientSecret: "..." },
});
```

When a user signs in with `user@subsidiary.com`, the plugin finds the provider by checking each domain in the list. Subdomain matching is also supported: `user@eng.acme.com` matches `acme.com`.

The `domainMatches(searchDomain, domainList)` utility function handles this logic. It splits on commas, trims whitespace, and checks for exact or subdomain matches (case-insensitive).

## Domain verification

When `domainVerification.enabled` is `true`, new providers require DNS-based domain ownership proof before sign-ins are allowed.

### Setup flow

1. **Register a provider.** The response includes `domainVerificationToken` and `domainVerified: false`.

2. **Create a DNS TXT record:**
   ```
   Name:  _better-auth-token-<providerId>.<domain>
   Value: _better-auth-token-<providerId>=<token>
   ```
   Example for provider `okta-acme` on `acme.com`:
   ```
   _better-auth-token-okta-acme.acme.com  TXT  "_better-auth-token-okta-acme=abc123xyz..."
   ```

3. **Call the verify endpoint.** The plugin resolves the TXT record via DNS-over-HTTPS (Cloudflare) and confirms ownership.

No `node:dns` required. Verification works on any runtime with `fetch`.

### How DNS verification works

- The plugin queries `https://cloudflare-dns.com/dns-query` with the TXT record name.
- The record name follows RFC 8552 (underscore-prefixed labels): `_{tokenPrefix}-{providerId}.{domain}`.
- The token prefix defaults to `better-auth-token`. You can change it in the config.
- Verification tokens last 7 days. You can re-request them if expired.
- If the domain changes on a provider, `domainVerified` resets to `false`.
- DNS labels are capped at 63 characters. The plugin validates this before lookup.

## OIDC discovery

By default, the plugin fetches the provider's `/.well-known/openid-configuration` document when you register a provider. This auto-fills:

- `authorizationEndpoint`
- `tokenEndpoint`
- `jwksEndpoint`
- `userInfoEndpoint`
- `tokenEndpointAuthentication` (selected from `token_endpoint_auth_methods_supported`)

If the provider's discovery document is missing required fields (`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`), registration fails with a descriptive error.

### Skipping discovery

Some providers don't support standard OIDC discovery. Set `skipDiscovery: true` and provide endpoints manually:

```ts
oidcConfig: {
  clientId: "...",
  clientSecret: "...",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.example.com/authorize",
  tokenEndpoint: "https://idp.example.com/token",
  jwksEndpoint: "https://idp.example.com/.well-known/jwks.json",
}
```

### Custom discovery endpoint

If your IdP uses a non-standard discovery path:

```ts
oidcConfig: {
  clientId: "...",
  clientSecret: "...",
  discoveryEndpoint: "https://idp.example.com/custom/.well-known/openid-configuration",
}
```

### Runtime discovery

If the stored config is missing `tokenEndpoint` or `jwksEndpoint` at sign-in time, the plugin re-runs discovery to fill them in. This handles cases where you registered a provider before certain fields were required.

## Account linking and `trustEmailVerified`

When a user signs in via SSO with an email that already exists in your database, Better Auth's [account linking](https://www.better-auth.com/docs/concepts/users-accounts#account-linking) determines what happens.

The `trustEmailVerified` option on this plugin controls whether the `email_verified` claim from the IdP is passed to Better Auth as the user's `emailVerified` field. If `true`, and the IdP says the email is verified, Better Auth may auto-link the account (depending on your `accountLinking` config).

**This option is deprecated.** The IdP's `email_verified` claim is a weak trust signal. Instead:

- Use `domainVerification: { enabled: true }` to verify that the SSO provider actually owns the domain.
- Configure Better Auth's `accountLinking.trustedProviders` to trust specific providers.
- Or set up `accountLinking.allowDifferentEmails` per your needs.

## Migration from `@better-auth/sso`

| `@better-auth/sso` | `@startino/better-auth-oidc` |
|---|---|
| `import { sso } from "@better-auth/sso"` | `import { oidcSso } from "@startino/better-auth-oidc"` |
| `import { ssoClient } from "@better-auth/sso/client"` | `import { oidcSsoClient } from "@startino/better-auth-oidc/client"` |
| `sso({ ... })` | `oidcSso({ ... })` |
| `ssoClient({ ... })` | `oidcSsoClient({ ... })` |
| Plugin ID: `"sso"` | Plugin ID: `"oidc-sso"` |
| `samlConfig` in options/schema | Removed (OIDC only) |
| `saml` options block | Removed |
| `defaultSSO[].samlConfig` | Removed |
| `fields.samlConfig` | Removed |

The database schema is the same minus the `samlConfig` column. If migrating from `@better-auth/sso`, you can drop the `samlConfig` column from your `ssoProvider` table, or leave it (it will be ignored).

## Exported utilities

The package exports OIDC discovery functions and types for advanced use cases:

### Discovery functions

| Export | Description |
|---|---|
| `discoverOIDCConfig(params)` | Main entry point. Fetches and hydrates OIDC config from an issuer URL. |
| `computeDiscoveryUrl(issuer)` | Returns `{issuer}/.well-known/openid-configuration`. |
| `fetchDiscoveryDocument(url, timeout?)` | Fetches and parses a discovery document. Default timeout: 10 seconds. |
| `validateDiscoveryUrl(url, isTrustedOrigin)` | Validates that a discovery URL is trusted. |
| `validateDiscoveryDocument(doc, issuer)` | Checks required fields and issuer match. |
| `normalizeDiscoveryUrls(doc, issuer, isTrustedOrigin)` | Validates and normalizes all endpoint URLs in a discovery document. |
| `normalizeUrl(name, endpoint, issuer)` | Normalizes a single URL, resolving relative paths against the issuer. |
| `selectTokenEndpointAuthMethod(doc, existing?)` | Picks the best token endpoint auth method from a discovery document. |
| `needsRuntimeDiscovery(config)` | Returns `true` if the config is missing `tokenEndpoint` or `jwksEndpoint`. |
| `mapDiscoveryErrorToAPIError(error)` | Converts a `DiscoveryError` to a Better Auth `APIError`. |
| `REQUIRED_DISCOVERY_FIELDS` | Array of required fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`. |

### Types

| Export | Description |
|---|---|
| `OIDCConfig` | Full OIDC provider configuration object. |
| `SSOOptions` | Plugin configuration options. |
| `SSOProvider` | SSO provider record (conditional on `domainVerification`). |
| `OIDCDiscoveryDocument` | OpenID Connect Discovery 1.0 document shape. |
| `HydratedOIDCConfig` | Discovery-resolved config with all endpoints filled in. |
| `DiscoverOIDCConfigParams` | Parameters for `discoverOIDCConfig()`. |
| `DiscoveryErrorCode` | Union of discovery error codes. |
| `DiscoveryError` | Error class with `code` and `details`. |
| `RequiredDiscoveryField` | Union type of required discovery field names. |
| `OIDCSSOPlugin` | Plugin type for type inference. |

## Credits

This package is an OIDC-only extraction of [`@better-auth/sso`](https://github.com/better-auth/better-auth/tree/main/packages/sso) by [Bereket Engida](https://github.com/bereketa). All OIDC logic, discovery pipeline, organization linking, and provider management code originates from that package.

## License

MIT
