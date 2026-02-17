import { BetterFetchError, betterFetch } from "@better-fetch/fetch";
import type { Verification } from "better-auth";
import {
	createAuthorizationURL,
	generateState,
	HIDE_METADATA,
	parseState,
	validateAuthorizationCode,
	validateToken,
} from "better-auth";
import {
	APIError,
	createAuthEndpoint,
	sessionMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { handleOAuthUserInfo } from "better-auth/oauth2";
import { decodeJwt } from "jose";
import z from "zod/v4";
import { getVerificationIdentifier } from "./domain-verification";

import { assignOrganizationFromProvider } from "../linking";
import type { HydratedOIDCConfig } from "../oidc";
import {
	DiscoveryError,
	discoverOIDCConfig,
	mapDiscoveryErrorToAPIError,
} from "../oidc";
import type {
	OIDCConfig,
	SSOOptions,
	SSOProvider,
} from "../types";
import { domainMatches, safeJsonParse, validateEmailDomain } from "../utils";

const ssoProviderBodySchema = z.object({
	providerId: z.string({}).meta({
		description:
			"The ID of the provider. This is used to identify the provider during login and callback",
	}),
	issuer: z.string({}).meta({
		description: "The issuer of the provider",
	}),
	domain: z.string({}).meta({
		description:
			"The domain(s) of the provider. For enterprise multi-domain SSO where a single IdP serves multiple email domains, use comma-separated values (e.g., 'company.com,subsidiary.com,acquired-company.com')",
	}),
	oidcConfig: z
		.object({
			clientId: z.string({}).meta({
				description: "The client ID",
			}),
			clientSecret: z.string({}).meta({
				description: "The client secret",
			}),
			authorizationEndpoint: z
				.string({})
				.meta({
					description: "The authorization endpoint",
				})
				.optional(),
			tokenEndpoint: z
				.string({})
				.meta({
					description: "The token endpoint",
				})
				.optional(),
			userInfoEndpoint: z
				.string({})
				.meta({
					description: "The user info endpoint",
				})
				.optional(),
			tokenEndpointAuthentication: z
				.enum(["client_secret_post", "client_secret_basic"])
				.optional(),
			jwksEndpoint: z
				.string({})
				.meta({
					description: "The JWKS endpoint",
				})
				.optional(),
			discoveryEndpoint: z.string().optional(),
			skipDiscovery: z
				.boolean()
				.meta({
					description:
						"Skip OIDC discovery during registration. When true, you must provide authorizationEndpoint, tokenEndpoint, and jwksEndpoint manually.",
				})
				.optional(),
			scopes: z
				.array(z.string(), {})
				.meta({
					description:
						"The scopes to request. Defaults to ['openid', 'email', 'profile', 'offline_access']",
				})
				.optional(),
			pkce: z
				.boolean({})
				.meta({
					description: "Whether to use PKCE for the authorization flow",
				})
				.default(true)
				.optional(),
			mapping: z
				.object({
					id: z.string({}).meta({
						description: "Field mapping for user ID (defaults to 'sub')",
					}),
					email: z.string({}).meta({
						description: "Field mapping for email (defaults to 'email')",
					}),
					emailVerified: z
						.string({})
						.meta({
							description:
								"Field mapping for email verification (defaults to 'email_verified')",
						})
						.optional(),
					name: z.string({}).meta({
						description: "Field mapping for name (defaults to 'name')",
					}),
					image: z
						.string({})
						.meta({
							description: "Field mapping for image (defaults to 'picture')",
						})
						.optional(),
					extraFields: z.record(z.string(), z.any()).optional(),
				})
				.optional(),
		}),
	organizationId: z
		.string({})
		.meta({
			description:
				"If organization plugin is enabled, the organization id to link the provider to",
		})
		.optional(),
	overrideUserInfo: z
		.boolean({})
		.meta({
			description:
				"Override user info with the provider info. Defaults to false",
		})
		.default(false)
		.optional(),
});

export const registerSSOProvider = <O extends SSOOptions>(options: O) => {
	return createAuthEndpoint(
		"/sso/register",
		{
			method: "POST",
			body: ssoProviderBodySchema,
			use: [sessionMiddleware],
			metadata: {
				openapi: {
					operationId: "registerSSOProvider",
					summary: "Register an OIDC provider",
					description:
						"This endpoint is used to register an OIDC provider. This is used to configure the provider and link it to an organization",
					responses: {
						"200": {
							description: "OIDC provider created successfully",
						},
					},
				},
			},
		},
		async (ctx) => {
			const user = ctx.context.session?.user;
			if (!user) {
				throw new APIError("UNAUTHORIZED");
			}

			const limit =
				typeof options?.providersLimit === "function"
					? await options.providersLimit(user)
					: (options?.providersLimit ?? 10);

			if (!limit) {
				throw new APIError("FORBIDDEN", {
					message: "SSO provider registration is disabled",
				});
			}

			const providers = await ctx.context.adapter.findMany({
				model: "ssoProvider",
				where: [{ field: "userId", value: user.id }],
			});

			if (providers.length >= limit) {
				throw new APIError("FORBIDDEN", {
					message: "You have reached the maximum number of SSO providers",
				});
			}

			const body = ctx.body;
			const issuerValidator = z.string().url();
			if (issuerValidator.safeParse(body.issuer).error) {
				throw new APIError("BAD_REQUEST", {
					message: "Invalid issuer. Must be a valid URL",
				});
			}

			if (ctx.body.organizationId && (ctx.context as any).hasPlugin?.("organization")) {
				const organization = await ctx.context.adapter.findOne({
					model: "member",
					where: [
						{
							field: "userId",
							value: user.id,
						},
						{
							field: "organizationId",
							value: ctx.body.organizationId,
						},
					],
				});
				if (!organization) {
					throw new APIError("BAD_REQUEST", {
						message: "You are not a member of the organization",
					});
				}
			}

			const existingProvider = await ctx.context.adapter.findOne({
				model: "ssoProvider",
				where: [
					{
						field: "providerId",
						value: body.providerId,
					},
				],
			});

			if (existingProvider) {
				ctx.context.logger.info(
					`SSO provider creation attempt with existing providerId: ${body.providerId}`,
				);
				throw new APIError("UNPROCESSABLE_ENTITY", {
					message: "SSO provider with this providerId already exists",
				});
			}

			let hydratedOIDCConfig: HydratedOIDCConfig | null = null;
			if (!body.oidcConfig.skipDiscovery) {
				try {
					hydratedOIDCConfig = await discoverOIDCConfig({
						issuer: body.issuer,
						existingConfig: {
							discoveryEndpoint: body.oidcConfig.discoveryEndpoint,
							authorizationEndpoint: body.oidcConfig.authorizationEndpoint,
							tokenEndpoint: body.oidcConfig.tokenEndpoint,
							jwksEndpoint: body.oidcConfig.jwksEndpoint,
							userInfoEndpoint: body.oidcConfig.userInfoEndpoint,
							tokenEndpointAuthentication:
								body.oidcConfig.tokenEndpointAuthentication,
						},
						isTrustedOrigin: (url: string) => ctx.context.isTrustedOrigin(url),
					});
				} catch (error) {
					if (error instanceof DiscoveryError) {
						throw mapDiscoveryErrorToAPIError(error);
					}
					throw error;
				}
			}

			const buildOIDCConfig = () => {
				if (body.oidcConfig.skipDiscovery) {
					return JSON.stringify({
						issuer: body.issuer,
						clientId: body.oidcConfig.clientId,
						clientSecret: body.oidcConfig.clientSecret,
						authorizationEndpoint: body.oidcConfig.authorizationEndpoint,
						tokenEndpoint: body.oidcConfig.tokenEndpoint,
						tokenEndpointAuthentication:
							body.oidcConfig.tokenEndpointAuthentication ||
							"client_secret_basic",
						jwksEndpoint: body.oidcConfig.jwksEndpoint,
						pkce: body.oidcConfig.pkce,
						discoveryEndpoint:
							body.oidcConfig.discoveryEndpoint ||
							`${body.issuer}/.well-known/openid-configuration`,
						mapping: body.oidcConfig.mapping,
						scopes: body.oidcConfig.scopes,
						userInfoEndpoint: body.oidcConfig.userInfoEndpoint,
						overrideUserInfo:
							ctx.body.overrideUserInfo ||
							options?.defaultOverrideUserInfo ||
							false,
					});
				}

				if (!hydratedOIDCConfig) return null;

				return JSON.stringify({
					issuer: hydratedOIDCConfig.issuer,
					clientId: body.oidcConfig.clientId,
					clientSecret: body.oidcConfig.clientSecret,
					authorizationEndpoint: hydratedOIDCConfig.authorizationEndpoint,
					tokenEndpoint: hydratedOIDCConfig.tokenEndpoint,
					tokenEndpointAuthentication:
						hydratedOIDCConfig.tokenEndpointAuthentication,
					jwksEndpoint: hydratedOIDCConfig.jwksEndpoint,
					pkce: body.oidcConfig.pkce,
					discoveryEndpoint: hydratedOIDCConfig.discoveryEndpoint,
					mapping: body.oidcConfig.mapping,
					scopes: body.oidcConfig.scopes,
					userInfoEndpoint: hydratedOIDCConfig.userInfoEndpoint,
					overrideUserInfo:
						ctx.body.overrideUserInfo ||
						options?.defaultOverrideUserInfo ||
						false,
				});
			};

			const provider = await ctx.context.adapter.create<
				Record<string, any>,
				SSOProvider<O>
			>({
				model: "ssoProvider",
				data: {
					issuer: body.issuer,
					domain: body.domain,
					domainVerified: false,
					oidcConfig: buildOIDCConfig(),
					organizationId: body.organizationId,
					userId: ctx.context.session.user.id,
					providerId: body.providerId,
				},
			});

			let domainVerificationToken: string | undefined;
			let domainVerified: boolean | undefined;

			if (options?.domainVerification?.enabled) {
				domainVerified = false;
				domainVerificationToken = generateRandomString(24);

				await ctx.context.adapter.create<Verification>({
					model: "verification",
					data: {
						identifier: getVerificationIdentifier(options, provider.providerId),
						createdAt: new Date(),
						updatedAt: new Date(),
						value: domainVerificationToken as string,
						expiresAt: new Date(Date.now() + 3600 * 24 * 7 * 1000), // 1 week
					},
				});
			}

			type SSOProviderResponse = {
				redirectURI: string;
				oidcConfig: OIDCConfig | null;
			} & Omit<SSOProvider<O>, "oidcConfig">;

			type SSOProviderReturn = O["domainVerification"] extends { enabled: true }
				? SSOProviderResponse & {
						domainVerified: boolean;
						domainVerificationToken: string;
					}
				: SSOProviderResponse;

			const result = {
				...provider,
				oidcConfig: safeJsonParse<OIDCConfig>(
					provider.oidcConfig as unknown as string,
				),
				redirectURI: `${ctx.context.baseURL}/sso/callback/${provider.providerId}`,
				...(options?.domainVerification?.enabled ? { domainVerified } : {}),
				...(options?.domainVerification?.enabled
					? { domainVerificationToken }
					: {}),
			};

			return ctx.json(result as SSOProviderReturn);
		},
	);
};

const signInSSOBodySchema = z.object({
	email: z
		.string({})
		.meta({
			description:
				"The email address to sign in with. This is used to identify the issuer to sign in with. It's optional if the issuer is provided",
		})
		.optional(),
	organizationSlug: z
		.string({})
		.meta({
			description: "The slug of the organization to sign in with",
		})
		.optional(),
	providerId: z
		.string({})
		.meta({
			description:
				"The ID of the provider to sign in with. This can be provided instead of email or issuer",
		})
		.optional(),
	domain: z
		.string({})
		.meta({
			description: "The domain of the provider.",
		})
		.optional(),
	callbackURL: z.string({}).meta({
		description: "The URL to redirect to after login",
	}),
	errorCallbackURL: z
		.string({})
		.meta({
			description: "The URL to redirect to after login",
		})
		.optional(),
	newUserCallbackURL: z
		.string({})
		.meta({
			description: "The URL to redirect to after login if the user is new",
		})
		.optional(),
	scopes: z
		.array(z.string(), {})
		.meta({
			description: "Scopes to request from the provider.",
		})
		.optional(),
	loginHint: z
		.string({})
		.meta({
			description:
				"Login hint to send to the identity provider (e.g., email or identifier). If supported, will be sent as 'login_hint'.",
		})
		.optional(),
	requestSignUp: z
		.boolean({})
		.meta({
			description:
				"Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider",
		})
		.optional(),
});

export const signInSSO = (options?: SSOOptions) => {
	return createAuthEndpoint(
		"/sign-in/sso",
		{
			method: "POST",
			body: signInSSOBodySchema,
			metadata: {
				openapi: {
					operationId: "signInWithSSO",
					summary: "Sign in with SSO provider",
					description:
						"This endpoint is used to sign in with an SSO provider. It redirects to the provider's authorization URL",
					responses: {
						"200": {
							description:
								"Authorization URL generated successfully for SSO sign-in",
						},
					},
				},
			},
		},
		async (ctx) => {
			const body = ctx.body;
			let { email, organizationSlug, providerId, domain } = body;
			if (
				!options?.defaultSSO?.length &&
				!email &&
				!organizationSlug &&
				!domain &&
				!providerId
			) {
				throw new APIError("BAD_REQUEST", {
					message: "email, organizationSlug, domain or providerId is required",
				});
			}
			domain = body.domain || email?.split("@")[1];
			let orgId = "";
			if (organizationSlug) {
				orgId = await ctx.context.adapter
					.findOne<{ id: string }>({
						model: "organization",
						where: [
							{
								field: "slug",
								value: organizationSlug,
							},
						],
					})
					.then((res) => {
						if (!res) {
							return "";
						}
						return res.id;
					});
			}
			let provider: SSOProvider<SSOOptions> | null = null;
			if (options?.defaultSSO?.length) {
				// Find matching default SSO provider by providerId
				const matchingDefault = providerId
					? options.defaultSSO.find(
							(defaultProvider) => defaultProvider.providerId === providerId,
						)
					: options.defaultSSO.find(
							(defaultProvider) => defaultProvider.domain === domain,
						);

				if (matchingDefault) {
					provider = {
						issuer: matchingDefault.oidcConfig?.issuer || "",
						providerId: matchingDefault.providerId,
						userId: "default",
						oidcConfig: matchingDefault.oidcConfig,
						domain: matchingDefault.domain,
						...(options.domainVerification?.enabled
							? { domainVerified: true }
							: {}),
					} as SSOProvider<SSOOptions>;
				}
			}
			if (!providerId && !orgId && !domain) {
				throw new APIError("BAD_REQUEST", {
					message: "providerId, orgId or domain is required",
				});
			}
			// Try to find provider in database
			if (!provider) {
				const parseProvider = (res: SSOProvider<SSOOptions> | null) => {
					if (!res) return null;
					return {
						...res,
						oidcConfig: res.oidcConfig
							? safeJsonParse<OIDCConfig>(
									res.oidcConfig as unknown as string,
								) || undefined
							: undefined,
					};
				};

				if (providerId || orgId) {
					// Exact match for providerId or orgId
					provider = parseProvider(
						await ctx.context.adapter.findOne<SSOProvider<SSOOptions>>({
							model: "ssoProvider",
							where: [
								{
									field: providerId ? "providerId" : "organizationId",
									value: providerId || orgId!,
								},
							],
						}),
					);
				} else if (domain) {
					// For domain lookup, support comma-separated domains
					// First try exact match (fast path)
					provider = parseProvider(
						await ctx.context.adapter.findOne<SSOProvider<SSOOptions>>({
							model: "ssoProvider",
							where: [{ field: "domain", value: domain }],
						}),
					);
					// If not found, search all providers for comma-separated domain match
					if (!provider) {
						const allProviders = await ctx.context.adapter.findMany<
							SSOProvider<SSOOptions>
						>({
							model: "ssoProvider",
						});
						const matchingProvider = allProviders.find((p) =>
							domainMatches(domain, p.domain),
						);
						provider = parseProvider(matchingProvider ?? null);
					}
				}
			}

			if (!provider) {
				throw new APIError("NOT_FOUND", {
					message: "No provider found for the issuer",
				});
			}

			if (!provider.oidcConfig) {
				throw new APIError("BAD_REQUEST", {
					message: "OIDC provider is not configured",
				});
			}

			if (
				options?.domainVerification?.enabled &&
				!("domainVerified" in provider && provider.domainVerified)
			) {
				throw new APIError("UNAUTHORIZED", {
					message: "Provider domain has not been verified",
				});
			}

			let finalAuthUrl = provider.oidcConfig.authorizationEndpoint;
			if (!finalAuthUrl && provider.oidcConfig.discoveryEndpoint) {
				const discovery = await betterFetch<{
					authorization_endpoint: string;
				}>(provider.oidcConfig.discoveryEndpoint, {
					method: "GET",
				});
				if (discovery.data) {
					finalAuthUrl = discovery.data.authorization_endpoint;
				}
			}
			if (!finalAuthUrl) {
				throw new APIError("BAD_REQUEST", {
					message: "Invalid OIDC configuration. Authorization URL not found.",
				});
			}
			const state = await generateState(ctx, undefined, false);
			const redirectURI = `${ctx.context.baseURL}/sso/callback/${provider.providerId}`;
			const authorizationURL = await createAuthorizationURL({
				id: provider.issuer,
				options: {
					clientId: provider.oidcConfig.clientId,
					clientSecret: provider.oidcConfig.clientSecret,
				},
				redirectURI,
				state: state.state,
				codeVerifier: provider.oidcConfig.pkce
					? state.codeVerifier
					: undefined,
				scopes: ctx.body.scopes ||
					provider.oidcConfig.scopes || [
						"openid",
						"email",
						"profile",
						"offline_access",
					],
				loginHint: ctx.body.loginHint || email,
				authorizationEndpoint: finalAuthUrl,
			});
			return ctx.json({
				url: authorizationURL.toString(),
				redirect: true,
			});
		},
	);
};

const callbackSSOQuerySchema = z.object({
	code: z.string().optional(),
	state: z.string(),
	error: z.string().optional(),
	error_description: z.string().optional(),
});

export const callbackSSO = (options?: SSOOptions) => {
	return createAuthEndpoint(
		"/sso/callback/:providerId",
		{
			method: "GET",
			query: callbackSSOQuerySchema,
			allowedMediaTypes: [
				"application/x-www-form-urlencoded",
				"application/json",
			],
			metadata: {
				...HIDE_METADATA,
				openapi: {
					operationId: "handleSSOCallback",
					summary: "Callback URL for SSO provider",
					description:
						"This endpoint is used as the callback URL for SSO providers. It handles the authorization code and exchanges it for an access token",
					responses: {
						"302": {
							description: "Redirects to the callback URL",
						},
					},
				},
			},
		},
		async (ctx) => {
			const { code, error, error_description } = ctx.query;
			const stateData = await parseState(ctx);
			if (!stateData) {
				const errorURL =
					ctx.context.options.onAPIError?.errorURL ||
					`${ctx.context.baseURL}/error`;
				throw ctx.redirect(`${errorURL}?error=invalid_state`);
			}
			const { callbackURL, errorURL, newUserURL, requestSignUp } = stateData;
			if (!code || error) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=${error}&error_description=${error_description}`,
				);
			}
			let provider: SSOProvider<SSOOptions> | null = null;
			if (options?.defaultSSO?.length) {
				const matchingDefault = options.defaultSSO.find(
					(defaultProvider) =>
						defaultProvider.providerId === ctx.params.providerId,
				);
				if (matchingDefault) {
					provider = {
						...matchingDefault,
						issuer: matchingDefault.oidcConfig?.issuer || "",
						userId: "default",
						...(options.domainVerification?.enabled
							? { domainVerified: true }
							: {}),
					} as SSOProvider<SSOOptions>;
				}
			}
			if (!provider) {
				provider = await ctx.context.adapter
					.findOne<{
						oidcConfig: string;
					}>({
						model: "ssoProvider",
						where: [
							{
								field: "providerId",
								value: ctx.params.providerId,
							},
						],
					})
					.then((res) => {
						if (!res) {
							return null;
						}
						return {
							...res,
							oidcConfig:
								safeJsonParse<OIDCConfig>(res.oidcConfig) || undefined,
						} as SSOProvider<SSOOptions>;
					});
			}
			if (!provider) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=invalid_provider&error_description=provider not found`,
				);
			}

			if (
				options?.domainVerification?.enabled &&
				!("domainVerified" in provider && provider.domainVerified)
			) {
				throw new APIError("UNAUTHORIZED", {
					message: "Provider domain has not been verified",
				});
			}

			let config = provider.oidcConfig;

			if (!config) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=invalid_provider&error_description=provider not found`,
				);
			}

			const discovery = await betterFetch<{
				token_endpoint: string;
				userinfo_endpoint: string;
				token_endpoint_auth_method:
					| "client_secret_basic"
					| "client_secret_post";
			}>(config.discoveryEndpoint);

			if (discovery.data) {
				config = {
					tokenEndpoint: discovery.data.token_endpoint,
					tokenEndpointAuthentication:
						discovery.data.token_endpoint_auth_method,
					userInfoEndpoint: discovery.data.userinfo_endpoint,
					scopes: ["openid", "email", "profile", "offline_access"],
					...config,
				};
			}

			if (!config.tokenEndpoint) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=invalid_provider&error_description=token_endpoint_not_found`,
				);
			}

			const tokenResponse = await validateAuthorizationCode({
				code,
				codeVerifier: config.pkce ? stateData.codeVerifier : undefined,
				redirectURI: `${ctx.context.baseURL}/sso/callback/${provider.providerId}`,
				options: {
					clientId: config.clientId,
					clientSecret: config.clientSecret,
				},
				tokenEndpoint: config.tokenEndpoint,
				authentication:
					config.tokenEndpointAuthentication === "client_secret_post"
						? "post"
						: "basic",
			}).catch((e) => {
				if (e instanceof BetterFetchError) {
					throw ctx.redirect(
						`${
							errorURL || callbackURL
						}?error=invalid_provider&error_description=${e.message}`,
					);
				}
				return null;
			});
			if (!tokenResponse) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=invalid_provider&error_description=token_response_not_found`,
				);
			}
			let userInfo: {
				id?: string;
				email?: string;
				name?: string;
				image?: string;
				emailVerified?: boolean;
				[key: string]: any;
			} | null = null;
			if (tokenResponse.idToken) {
				const idToken = decodeJwt(tokenResponse.idToken);
				if (!config.jwksEndpoint) {
					throw ctx.redirect(
						`${
							errorURL || callbackURL
						}?error=invalid_provider&error_description=jwks_endpoint_not_found`,
					);
				}
				const verified = await validateToken(
					tokenResponse.idToken,
					config.jwksEndpoint,
					{
						audience: config.clientId,
						issuer: provider.issuer,
					},
				).catch((e) => {
					ctx.context.logger.error(e);
					return null;
				});
				if (!verified) {
					throw ctx.redirect(
						`${
							errorURL || callbackURL
						}?error=invalid_provider&error_description=token_not_verified`,
					);
				}

				const mapping = config.mapping || {};
				userInfo = {
					...Object.fromEntries(
						Object.entries(mapping.extraFields || {}).map(([key, value]) => [
							key,
							verified.payload[value],
						]),
					),
					id: idToken[mapping.id || "sub"],
					email: idToken[mapping.email || "email"],
					emailVerified: options?.trustEmailVerified
						? idToken[mapping.emailVerified || "email_verified"]
						: false,
					name: idToken[mapping.name || "name"],
					image: idToken[mapping.image || "picture"],
				} as {
					id?: string;
					email?: string;
					name?: string;
					image?: string;
					emailVerified?: boolean;
				};
			}

			if (!userInfo) {
				if (!config.userInfoEndpoint) {
					throw ctx.redirect(
						`${
							errorURL || callbackURL
						}?error=invalid_provider&error_description=user_info_endpoint_not_found`,
					);
				}
				const userInfoResponse = await betterFetch<{
					email?: string;
					name?: string;
					id?: string;
					image?: string;
					emailVerified?: boolean;
				}>(config.userInfoEndpoint, {
					headers: {
						Authorization: `Bearer ${tokenResponse.accessToken}`,
					},
				});
				if (userInfoResponse.error) {
					throw ctx.redirect(
						`${
							errorURL || callbackURL
						}?error=invalid_provider&error_description=${
							userInfoResponse.error.message
						}`,
					);
				}
				userInfo = userInfoResponse.data;
			}

			if (!userInfo.email || !userInfo.id) {
				throw ctx.redirect(
					`${
						errorURL || callbackURL
					}?error=invalid_provider&error_description=missing_user_info`,
				);
			}
			const isTrustedProvider =
				"domainVerified" in provider &&
				(provider as { domainVerified?: boolean }).domainVerified === true &&
				validateEmailDomain(userInfo.email, provider.domain);

			const linked = await handleOAuthUserInfo(ctx, {
				userInfo: {
					email: userInfo.email,
					name: userInfo.name || "",
					id: userInfo.id,
					image: userInfo.image,
					emailVerified: options?.trustEmailVerified
						? userInfo.emailVerified || false
						: false,
				},
				account: {
					idToken: tokenResponse.idToken,
					accessToken: tokenResponse.accessToken,
					refreshToken: tokenResponse.refreshToken,
					accountId: userInfo.id,
					providerId: provider.providerId,
					accessTokenExpiresAt: tokenResponse.accessTokenExpiresAt,
					refreshTokenExpiresAt: tokenResponse.refreshTokenExpiresAt,
					scope: tokenResponse.scopes?.join(","),
				},
				callbackURL,
				disableSignUp: options?.disableImplicitSignUp && !requestSignUp,
				overrideUserInfo: config.overrideUserInfo,
				isTrustedProvider,
			});
			if (linked.error) {
				throw ctx.redirect(`${errorURL || callbackURL}?error=${linked.error}`);
			}
			const { session, user } = linked.data!;

			if (options?.provisionUser && linked.isRegister) {
				await options.provisionUser({
					user,
					userInfo,
					token: tokenResponse,
					provider,
				});
			}

			await assignOrganizationFromProvider(ctx as any, {
				user,
				profile: {
					providerType: "oidc",
					providerId: provider.providerId,
					accountId: userInfo.id,
					email: userInfo.email,
					emailVerified: Boolean(userInfo.emailVerified),
					rawAttributes: userInfo,
				},
				provider,
				token: tokenResponse,
				provisioningOptions: options?.organizationProvisioning,
			});

			await setSessionCookie(ctx, {
				session,
				user,
			});
			let toRedirectTo: string;
			try {
				const url = linked.isRegister ? newUserURL || callbackURL : callbackURL;
				toRedirectTo = url.toString();
			} catch {
				toRedirectTo = linked.isRegister
					? newUserURL || callbackURL
					: callbackURL;
			}
			throw ctx.redirect(toRedirectTo);
		},
	);
};
