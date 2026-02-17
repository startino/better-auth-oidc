import { getTestInstance } from "better-auth/test";
import type { SSOOptions } from "../index";
import { oidcSso } from "../index";

/**
 * Minimal OIDC config that skips discovery — no network calls needed.
 */
export const SKIP_DISCOVERY_OIDC_CONFIG = {
	clientId: "test-client-id",
	clientSecret: "test-client-secret",
	skipDiscovery: true,
	authorizationEndpoint: "https://idp.example.com/authorize",
	tokenEndpoint: "https://idp.example.com/token",
	jwksEndpoint: "https://idp.example.com/.well-known/jwks.json",
} as const;

/**
 * Creates a better-auth test instance WITHOUT the organization plugin.
 * Since `member` and `organization` tables don't exist in the DB,
 * any missing hasPlugin guard will crash with "Model member not found in schema".
 */
export async function createTestInstanceWithoutOrg(
	ssoOptions?: SSOOptions,
) {
	return getTestInstance({
		plugins: [oidcSso(ssoOptions)],
	});
}

/**
 * Shorthand for registering an SSO provider with skipDiscovery.
 */
export async function registerProvider(
	auth: Awaited<ReturnType<typeof getTestInstance>>["auth"],
	headers: Headers,
	overrides?: Partial<{
		providerId: string;
		issuer: string;
		domain: string;
		organizationId: string;
		oidcConfig: Record<string, unknown>;
	}>,
) {
	return auth.api.registerSSOProvider({
		headers,
		body: {
			providerId: overrides?.providerId ?? "test-provider",
			issuer: overrides?.issuer ?? "https://idp.example.com",
			domain: overrides?.domain ?? "example.com",
			organizationId: overrides?.organizationId,
			oidcConfig: {
				...SKIP_DISCOVERY_OIDC_CONFIG,
				...overrides?.oidcConfig,
			},
		},
	});
}
