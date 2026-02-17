# @startino/better-auth-oidc

OIDC-only SSO plugin for [Better Auth](https://www.better-auth.com/). Runs on any JavaScript runtime without Node.js-specific APIs.

## Why

The official [`@better-auth/sso`](https://www.better-auth.com/docs/plugins/sso) plugin imports `samlify` at module load, which requires Node.js-only APIs (`node:crypto`, `node:buffer`). This breaks in edge runtimes, serverless environments, or any platform without full Node.js compatibility, even if you only need OIDC.

This package extracts the OIDC code paths into a standalone package. SAML code and Node.js dependencies are removed entirely.

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

Peer dependencies: `better-auth` (>=1.4.0) and `better-call` (>=1.0.0).

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

## Configuration options

| Option | Type | Default | Description |
|---|---|---|---|
| `provisionUser` | `function` | - | Custom function called when a new user signs in via SSO |
| `organizationProvisioning` | `object` | - | Auto-assign users to orgs based on SSO provider |
| `organizationProvisioning.defaultRole` | `"member" \| "admin"` | `"member"` | Default role for auto-provisioned members |
| `organizationProvisioning.getRole` | `function` | - | Dynamic role assignment function |
| `defaultSSO` | `array` | - | Default provider configs for testing (takes precedence over DB) |
| `defaultOverrideUserInfo` | `boolean` | `false` | Override user info with provider data on each sign-in |
| `disableImplicitSignUp` | `boolean` | `false` | Require explicit `requestSignUp: true` to create new users |
| `modelName` | `string` | `"ssoProvider"` | Custom table name for SSO providers |
| `fields` | `object` | - | Custom field name mappings for the provider table |
| `providersLimit` | `number \| function` | `10` | Max providers per user (0 to disable registration) |
| `trustEmailVerified` | `boolean` | `false` | Trust the `email_verified` claim from the IdP (deprecated) |
| `domainVerification` | `object` | - | Enable DNS-based domain ownership verification |
| `domainVerification.enabled` | `boolean` | `false` | Enable/disable the feature |
| `domainVerification.tokenPrefix` | `string` | `"better-auth-token"` | Prefix for the DNS TXT record identifier |

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/sso/register` | POST | Register a new OIDC provider |
| `/sign-in/sso` | POST | Initiate SSO sign-in (redirects to IdP) |
| `/sso/callback/:providerId` | GET | OAuth2 callback handler |
| `/sso/providers` | GET | List providers the user has access to |
| `/sso/get-provider` | GET | Get details for a specific provider |
| `/sso/update-provider` | POST | Update an existing provider |
| `/sso/delete-provider` | POST | Delete a provider |
| `/sso/request-domain-verification` | POST | Request domain verification (if enabled) |
| `/sso/verify-domain` | POST | Verify domain via DNS TXT record (if enabled) |

## Domain verification

When `domainVerification.enabled` is `true`, new providers require DNS-based domain ownership verification before sign-ins are allowed.

1. Register a provider. The response includes a `domainVerificationToken`.
2. Create a DNS TXT record: `_better-auth-token-<providerId>.<domain>` with value `_better-auth-token-<providerId>=<token>`.
3. Call the verify endpoint. The plugin resolves the TXT record via DNS-over-HTTPS (Cloudflare) and confirms ownership.

No `node:dns` required. Verification works on any runtime with `fetch`.

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

## Credits

This package is an OIDC-only extraction of [`@better-auth/sso`](https://github.com/better-auth/better-auth/tree/main/packages/sso) by [Bereket Engida](https://github.com/bereketa). All OIDC logic, discovery pipeline, organization linking, and provider management code originates from that package.

## License

MIT
