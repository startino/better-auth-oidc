import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { assignOrganizationByDomain } from "./linking";
import {
	requestDomainVerification,
	verifyDomain,
} from "./routes/domain-verification";
import {
	deleteSSOProvider,
	getSSOProvider,
	listSSOProviders,
	updateSSOProvider,
} from "./routes/providers";
import {
	callbackSSO,
	registerSSOProvider,
	signInSSO,
	verifyOtt,
} from "./routes/sso";

import type { OIDCConfig, SSOOptions, SSOProvider } from "./types";

export type { OIDCConfig, SSOOptions, SSOProvider };

export {
	computeDiscoveryUrl,
	type DiscoverOIDCConfigParams,
	DiscoveryError,
	type DiscoveryErrorCode,
	discoverOIDCConfig,
	fetchDiscoveryDocument,
	type HydratedOIDCConfig,
	needsRuntimeDiscovery,
	normalizeDiscoveryUrls,
	normalizeUrl,
	type OIDCDiscoveryDocument,
	REQUIRED_DISCOVERY_FIELDS,
	type RequiredDiscoveryField,
	selectTokenEndpointAuthMethod,
	validateDiscoveryDocument,
	validateDiscoveryUrl,
} from "./oidc";

type DomainVerificationEndpoints = {
	requestDomainVerification: ReturnType<typeof requestDomainVerification>;
	verifyDomain: ReturnType<typeof verifyDomain>;
};

type OIDCSSOEndpoints<O extends SSOOptions> = {
	registerSSOProvider: ReturnType<typeof registerSSOProvider<O>>;
	signInSSO: ReturnType<typeof signInSSO>;
	callbackSSO: ReturnType<typeof callbackSSO>;
	verifyOtt: ReturnType<typeof verifyOtt>;
	listSSOProviders: ReturnType<typeof listSSOProviders>;
	getSSOProvider: ReturnType<typeof getSSOProvider>;
	updateSSOProvider: ReturnType<typeof updateSSOProvider>;
	deleteSSOProvider: ReturnType<typeof deleteSSOProvider>;
};

export type OIDCSSOPlugin<O extends SSOOptions> = {
	id: "oidc-sso";
	endpoints: OIDCSSOEndpoints<O> &
		(O extends { domainVerification: { enabled: true } }
			? DomainVerificationEndpoints
			: {});
};

export function oidcSso<
	O extends SSOOptions & {
		domainVerification?: { enabled: true };
	},
>(
	options?: O | undefined,
): {
	id: "oidc-sso";
	endpoints: OIDCSSOEndpoints<O> & DomainVerificationEndpoints;
	schema: NonNullable<BetterAuthPlugin["schema"]>;
	options: O;
};
export function oidcSso<O extends SSOOptions>(
	options?: O | undefined,
): {
	id: "oidc-sso";
	endpoints: OIDCSSOEndpoints<O>;
};

export function oidcSso<O extends SSOOptions>(
	options?: O | undefined,
): BetterAuthPlugin {
	const optionsWithStore = options as O;

	let endpoints = {
		registerSSOProvider: registerSSOProvider(optionsWithStore),
		signInSSO: signInSSO(optionsWithStore),
		callbackSSO: callbackSSO(optionsWithStore),
		verifyOtt: verifyOtt(),
		listSSOProviders: listSSOProviders(),
		getSSOProvider: getSSOProvider(),
		updateSSOProvider: updateSSOProvider(optionsWithStore),
		deleteSSOProvider: deleteSSOProvider(),
	};

	if (options?.domainVerification?.enabled) {
		const domainVerificationEndpoints = {
			requestDomainVerification: requestDomainVerification(optionsWithStore),
			verifyDomain: verifyDomain(optionsWithStore),
		};

		endpoints = {
			...endpoints,
			...domainVerificationEndpoints,
		};
	}

	return {
		id: "oidc-sso",
		endpoints,
		hooks: {
			after: [
				{
					matcher(context) {
						return context.path?.startsWith("/callback/") ?? false;
					},
					handler: createAuthMiddleware(async (ctx) => {
						const newSession = ctx.context.newSession;
						if (!newSession?.user) {
							return;
						}

						if (!(ctx.context as any).hasPlugin?.("organization")) {
							return;
						}

						await assignOrganizationByDomain(ctx, {
							user: newSession.user,
							provisioningOptions: options?.organizationProvisioning,
							domainVerification: options?.domainVerification,
						});
					}),
				},
			],
		},
		schema: {
			ssoProvider: {
				modelName: options?.modelName ?? "ssoProvider",
				fields: {
					issuer: {
						type: "string",
						required: true,
						fieldName: options?.fields?.issuer ?? "issuer",
					},
					oidcConfig: {
						type: "string",
						required: false,
						fieldName: options?.fields?.oidcConfig ?? "oidcConfig",
					},
					userId: {
						type: "string",
						references: {
							model: "user",
							field: "id",
						},
						fieldName: options?.fields?.userId ?? "userId",
					},
					providerId: {
						type: "string",
						required: true,
						unique: true,
						fieldName: options?.fields?.providerId ?? "providerId",
					},
					organizationId: {
						type: "string",
						required: false,
						fieldName: options?.fields?.organizationId ?? "organizationId",
					},
					domain: {
						type: "string",
						required: true,
						fieldName: options?.fields?.domain ?? "domain",
					},
					...(options?.domainVerification?.enabled
						? { domainVerified: { type: "boolean", required: false } }
						: {}),
				},
			},
		},
		options: options as NoInfer<O>,
	} satisfies BetterAuthPlugin;
}
