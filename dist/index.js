import { APIError, createAuthEndpoint, createAuthMiddleware, sessionMiddleware } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import * as z$1 from "zod/v4";
import z from "zod/v4";
import { BetterFetchError, betterFetch } from "@better-fetch/fetch";
import { HIDE_METADATA, createAuthorizationURL, generateState, parseState, validateAuthorizationCode, validateToken } from "better-auth";
import { setSessionCookie } from "better-auth/cookies";
import { handleOAuthUserInfo } from "better-auth/oauth2";
import { decodeJwt } from "jose";

//#region src/utils.ts
/**
* Safely parses a value that might be a JSON string or already a parsed object.
* This handles cases where ORMs like Drizzle might return already parsed objects
* instead of JSON strings from TEXT/JSON columns.
*
* @param value - The value to parse (string, object, null, or undefined)
* @returns The parsed object or null
* @throws Error if string parsing fails
*/
function safeJsonParse(value) {
	if (!value) return null;
	if (typeof value === "object") return value;
	if (typeof value === "string") try {
		return JSON.parse(value);
	} catch (error) {
		throw new Error(`Failed to parse JSON: ${error instanceof Error ? error.message : "Unknown error"}`);
	}
	return null;
}
/**
* Checks if a domain matches any domain in a comma-separated list.
*/
const domainMatches = (searchDomain, domainList) => {
	const search = searchDomain.toLowerCase();
	return domainList.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean).some((d) => search === d || search.endsWith(`.${d}`));
};
/**
* Validates email domain against allowed domain(s).
* Supports comma-separated domains for multi-domain SSO.
*/
const validateEmailDomain = (email, domain) => {
	const emailDomain = email.split("@")[1]?.toLowerCase();
	if (!emailDomain || !domain) return false;
	return domainMatches(emailDomain, domain);
};
function maskClientId(clientId) {
	if (clientId.length <= 4) return "****";
	return `****${clientId.slice(-4)}`;
}

//#endregion
//#region src/linking/org-assignment.ts
/**
* Assigns a user to an organization based on the SSO provider's organizationId.
* Used in SSO flows (OIDC, SAML) where the provider is already linked to an org.
*/
async function assignOrganizationFromProvider(ctx, options) {
	const { user, profile, provider, token, provisioningOptions } = options;
	if (!provider.organizationId) return;
	if (provisioningOptions?.disabled) return;
	if (!ctx.context.hasPlugin("organization")) return;
	if (await ctx.context.adapter.findOne({
		model: "member",
		where: [{
			field: "organizationId",
			value: provider.organizationId
		}, {
			field: "userId",
			value: user.id
		}]
	})) return;
	const role = provisioningOptions?.getRole ? await provisioningOptions.getRole({
		user,
		userInfo: profile.rawAttributes || {},
		token,
		provider
	}) : provisioningOptions?.defaultRole || "member";
	await ctx.context.adapter.create({
		model: "member",
		data: {
			organizationId: provider.organizationId,
			userId: user.id,
			role,
			createdAt: /* @__PURE__ */ new Date()
		}
	});
}
/**
* Assigns a user to an organization based on their email domain.
* Looks up SSO providers that match the user's email domain and assigns
* the user to the associated organization.
*
* This enables domain-based org assignment for non-SSO sign-in methods
* (e.g., Google OAuth with @acme.com email gets added to Acme's org).
*/
async function assignOrganizationByDomain(ctx, options) {
	const { user, provisioningOptions, domainVerification } = options;
	if (provisioningOptions?.disabled) return;
	if (!ctx.context.hasPlugin("organization")) return;
	const domain = user.email.split("@")[1];
	if (!domain) return;
	const whereClause = [{
		field: "domain",
		value: domain
	}];
	if (domainVerification?.enabled) whereClause.push({
		field: "domainVerified",
		value: true
	});
	let ssoProvider = await ctx.context.adapter.findOne({
		model: "ssoProvider",
		where: whereClause
	});
	if (!ssoProvider) ssoProvider = (await ctx.context.adapter.findMany({
		model: "ssoProvider",
		where: domainVerification?.enabled ? [{
			field: "domainVerified",
			value: true
		}] : []
	})).find((p) => domainMatches(domain, p.domain)) ?? null;
	if (!ssoProvider || !ssoProvider.organizationId) return;
	if (await ctx.context.adapter.findOne({
		model: "member",
		where: [{
			field: "organizationId",
			value: ssoProvider.organizationId
		}, {
			field: "userId",
			value: user.id
		}]
	})) return;
	const role = provisioningOptions?.getRole ? await provisioningOptions.getRole({
		user,
		userInfo: {},
		provider: ssoProvider
	}) : provisioningOptions?.defaultRole || "member";
	await ctx.context.adapter.create({
		model: "member",
		data: {
			organizationId: ssoProvider.organizationId,
			userId: user.id,
			role,
			createdAt: /* @__PURE__ */ new Date()
		}
	});
}

//#endregion
//#region src/routes/domain-verification.ts
const DNS_LABEL_MAX_LENGTH = 63;
const DEFAULT_TOKEN_PREFIX = "better-auth-token";
const domainVerificationBodySchema = z$1.object({ providerId: z$1.string() });
function getVerificationIdentifier(options, providerId) {
	return `_${options.domainVerification?.tokenPrefix || DEFAULT_TOKEN_PREFIX}-${providerId}`;
}
/**
* DNS-over-HTTPS TXT record lookup using Cloudflare's resolver.
* Replaces node:dns/promises for edge/serverless compatibility.
*/
async function resolveTxtDoH(hostname) {
	const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`;
	const response = await fetch(url, { headers: { Accept: "application/dns-json" } });
	if (!response.ok) throw new Error(`DoH request failed with status ${response.status}`);
	const data = await response.json();
	if (!data.Answer) return [];
	return data.Answer.filter((record) => record.type === 16).map((record) => record.data.replace(/^"|"$/g, ""));
}
const requestDomainVerification = (options) => {
	return createAuthEndpoint("/sso/request-domain-verification", {
		method: "POST",
		body: domainVerificationBodySchema,
		metadata: { openapi: {
			summary: "Request a domain verification",
			description: "Request a domain verification for the given SSO provider",
			responses: {
				"404": { description: "Provider not found" },
				"409": { description: "Domain has already been verified" },
				"201": { description: "Domain submitted for verification" }
			}
		} },
		use: [sessionMiddleware]
	}, async (ctx) => {
		const body = ctx.body;
		const provider = await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: body.providerId
			}]
		});
		if (!provider) throw new APIError("NOT_FOUND", {
			message: "Provider not found",
			code: "PROVIDER_NOT_FOUND"
		});
		const userId = ctx.context.session.user.id;
		let isOrgMember = true;
		if (provider.organizationId) isOrgMember = await ctx.context.adapter.count({
			model: "member",
			where: [{
				field: "userId",
				value: userId
			}, {
				field: "organizationId",
				value: provider.organizationId
			}]
		}) > 0;
		if (provider.userId !== userId || !isOrgMember) throw new APIError("FORBIDDEN", {
			message: "User must be owner of or belong to the SSO provider organization",
			code: "INSUFICCIENT_ACCESS"
		});
		if ("domainVerified" in provider && provider.domainVerified) throw new APIError("CONFLICT", {
			message: "Domain has already been verified",
			code: "DOMAIN_VERIFIED"
		});
		const identifier = getVerificationIdentifier(options, provider.providerId);
		const activeVerification = await ctx.context.adapter.findOne({
			model: "verification",
			where: [{
				field: "identifier",
				value: identifier
			}, {
				field: "expiresAt",
				value: /* @__PURE__ */ new Date(),
				operator: "gt"
			}]
		});
		if (activeVerification) {
			ctx.setStatus(201);
			return ctx.json({ domainVerificationToken: activeVerification.value });
		}
		const domainVerificationToken = generateRandomString(24);
		await ctx.context.adapter.create({
			model: "verification",
			data: {
				identifier,
				createdAt: /* @__PURE__ */ new Date(),
				updatedAt: /* @__PURE__ */ new Date(),
				value: domainVerificationToken,
				expiresAt: new Date(Date.now() + 3600 * 24 * 7 * 1e3)
			}
		});
		ctx.setStatus(201);
		return ctx.json({ domainVerificationToken });
	});
};
const verifyDomain = (options) => {
	return createAuthEndpoint("/sso/verify-domain", {
		method: "POST",
		body: domainVerificationBodySchema,
		metadata: { openapi: {
			summary: "Verify the provider domain ownership",
			description: "Verify the provider domain ownership via DNS records",
			responses: {
				"404": { description: "Provider not found" },
				"409": { description: "Domain has already been verified or no pending verification exists" },
				"502": { description: "Unable to verify domain ownership due to upstream validator error" },
				"204": { description: "Domain ownership was verified" }
			}
		} },
		use: [sessionMiddleware]
	}, async (ctx) => {
		const body = ctx.body;
		const provider = await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: body.providerId
			}]
		});
		if (!provider) throw new APIError("NOT_FOUND", {
			message: "Provider not found",
			code: "PROVIDER_NOT_FOUND"
		});
		const userId = ctx.context.session.user.id;
		let isOrgMember = true;
		if (provider.organizationId) isOrgMember = await ctx.context.adapter.count({
			model: "member",
			where: [{
				field: "userId",
				value: userId
			}, {
				field: "organizationId",
				value: provider.organizationId
			}]
		}) > 0;
		if (provider.userId !== userId || !isOrgMember) throw new APIError("FORBIDDEN", {
			message: "User must be owner of or belong to the SSO provider organization",
			code: "INSUFICCIENT_ACCESS"
		});
		if ("domainVerified" in provider && provider.domainVerified) throw new APIError("CONFLICT", {
			message: "Domain has already been verified",
			code: "DOMAIN_VERIFIED"
		});
		const identifier = getVerificationIdentifier(options, provider.providerId);
		if (identifier.length > DNS_LABEL_MAX_LENGTH) throw new APIError("BAD_REQUEST", {
			message: `Verification identifier exceeds the DNS label limit of ${DNS_LABEL_MAX_LENGTH} characters`,
			code: "IDENTIFIER_TOO_LONG"
		});
		const activeVerification = await ctx.context.adapter.findOne({
			model: "verification",
			where: [{
				field: "identifier",
				value: identifier
			}, {
				field: "expiresAt",
				value: /* @__PURE__ */ new Date(),
				operator: "gt"
			}]
		});
		if (!activeVerification) throw new APIError("NOT_FOUND", {
			message: "No pending domain verification exists",
			code: "NO_PENDING_VERIFICATION"
		});
		let records = [];
		try {
			const hostname = new URL(provider.domain).hostname;
			records = await resolveTxtDoH(`${identifier}.${hostname}`);
		} catch (error) {
			ctx.context.logger.warn("DNS resolution failure while validating domain ownership", error);
		}
		if (!records.find((record) => record.includes(`${activeVerification.identifier}=${activeVerification.value}`))) throw new APIError("BAD_GATEWAY", {
			message: "Unable to verify domain ownership. Try again later",
			code: "DOMAIN_VERIFICATION_FAILED"
		});
		await ctx.context.adapter.update({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: provider.providerId
			}],
			update: { domainVerified: true }
		});
		ctx.setStatus(204);
	});
};

//#endregion
//#region src/routes/schemas.ts
const oidcMappingSchema = z.object({
	id: z.string().optional(),
	email: z.string().optional(),
	emailVerified: z.string().optional(),
	name: z.string().optional(),
	image: z.string().optional(),
	extraFields: z.record(z.string(), z.any()).optional()
}).optional();
const oidcConfigSchema = z.object({
	clientId: z.string().optional(),
	clientSecret: z.string().optional(),
	authorizationEndpoint: z.string().url().optional(),
	tokenEndpoint: z.string().url().optional(),
	userInfoEndpoint: z.string().url().optional(),
	tokenEndpointAuthentication: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
	jwksEndpoint: z.string().url().optional(),
	discoveryEndpoint: z.string().url().optional(),
	scopes: z.array(z.string()).optional(),
	pkce: z.boolean().optional(),
	overrideUserInfo: z.boolean().optional(),
	mapping: oidcMappingSchema
});
const updateSSOProviderBodySchema = z.object({
	issuer: z.string().url().optional(),
	domain: z.string().optional(),
	oidcConfig: oidcConfigSchema.optional()
});

//#endregion
//#region src/routes/providers.ts
const ADMIN_ROLES = ["owner", "admin"];
async function isOrgAdmin(ctx, userId, organizationId) {
	const member = await ctx.context.adapter.findOne({
		model: "member",
		where: [{
			field: "userId",
			value: userId
		}, {
			field: "organizationId",
			value: organizationId
		}]
	});
	if (!member) return false;
	return member.role.split(",").some((r) => ADMIN_ROLES.includes(r.trim()));
}
async function batchCheckOrgAdmin(ctx, userId, organizationIds) {
	if (organizationIds.length === 0) return /* @__PURE__ */ new Set();
	const members = await ctx.context.adapter.findMany({
		model: "member",
		where: [{
			field: "userId",
			value: userId
		}, {
			field: "organizationId",
			value: organizationIds,
			operator: "in"
		}]
	});
	const adminOrgIds = /* @__PURE__ */ new Set();
	for (const member of members) if (member.role.split(",").some((r) => ADMIN_ROLES.includes(r.trim()))) adminOrgIds.add(member.organizationId);
	return adminOrgIds;
}
function sanitizeProvider(provider) {
	let oidcConfig = null;
	try {
		oidcConfig = safeJsonParse(provider.oidcConfig);
	} catch {
		oidcConfig = null;
	}
	return {
		providerId: provider.providerId,
		type: "oidc",
		issuer: provider.issuer,
		domain: provider.domain,
		organizationId: provider.organizationId || null,
		domainVerified: provider.domainVerified ?? false,
		oidcConfig: oidcConfig ? {
			discoveryEndpoint: oidcConfig.discoveryEndpoint,
			clientIdLastFour: maskClientId(oidcConfig.clientId),
			pkce: oidcConfig.pkce,
			authorizationEndpoint: oidcConfig.authorizationEndpoint,
			tokenEndpoint: oidcConfig.tokenEndpoint,
			userInfoEndpoint: oidcConfig.userInfoEndpoint,
			jwksEndpoint: oidcConfig.jwksEndpoint,
			scopes: oidcConfig.scopes,
			tokenEndpointAuthentication: oidcConfig.tokenEndpointAuthentication
		} : void 0
	};
}
const listSSOProviders = () => {
	return createAuthEndpoint("/sso/providers", {
		method: "GET",
		use: [sessionMiddleware],
		metadata: { openapi: {
			operationId: "listSSOProviders",
			summary: "List SSO providers",
			description: "Returns a list of SSO providers the user has access to",
			responses: { "200": { description: "List of SSO providers" } }
		} }
	}, async (ctx) => {
		const userId = ctx.context.session.user.id;
		const allProviders = await ctx.context.adapter.findMany({ model: "ssoProvider" });
		const userOwnedProviders = allProviders.filter((p) => p.userId === userId && !p.organizationId);
		const orgProviders = allProviders.filter((p) => p.organizationId !== null && p.organizationId !== void 0);
		const orgPluginEnabled = !!ctx.context.hasPlugin?.("organization");
		let accessibleProviders = [...userOwnedProviders];
		if (orgPluginEnabled && orgProviders.length > 0) {
			const adminOrgIds = await batchCheckOrgAdmin(ctx, userId, [...new Set(orgProviders.map((p) => p.organizationId).filter((id) => id !== null && id !== void 0))]);
			const orgAccessibleProviders = orgProviders.filter((provider) => provider.organizationId && adminOrgIds.has(provider.organizationId));
			accessibleProviders = [...accessibleProviders, ...orgAccessibleProviders];
		} else if (!orgPluginEnabled) {
			const userOwnedOrgProviders = orgProviders.filter((p) => p.userId === userId);
			accessibleProviders = [...accessibleProviders, ...userOwnedOrgProviders];
		}
		const providers = accessibleProviders.map((p) => sanitizeProvider(p));
		return ctx.json({ providers });
	});
};
const getSSOProviderQuerySchema = z.object({ providerId: z.string() });
async function checkProviderAccess(ctx, providerId) {
	const userId = ctx.context.session.user.id;
	const provider = await ctx.context.adapter.findOne({
		model: "ssoProvider",
		where: [{
			field: "providerId",
			value: providerId
		}]
	});
	if (!provider) throw new APIError("NOT_FOUND", { message: "Provider not found" });
	let hasAccess = false;
	if (provider.organizationId) if (ctx.context.hasPlugin?.("organization")) hasAccess = await isOrgAdmin(ctx, userId, provider.organizationId);
	else hasAccess = provider.userId === userId;
	else hasAccess = provider.userId === userId;
	if (!hasAccess) throw new APIError("FORBIDDEN", { message: "You don't have access to this provider" });
	return provider;
}
const getSSOProvider = () => {
	return createAuthEndpoint("/sso/get-provider", {
		method: "GET",
		use: [sessionMiddleware],
		query: getSSOProviderQuerySchema,
		metadata: { openapi: {
			operationId: "getSSOProvider",
			summary: "Get SSO provider details",
			description: "Returns sanitized details for a specific SSO provider",
			responses: {
				"200": { description: "SSO provider details" },
				"404": { description: "Provider not found" },
				"403": { description: "Access denied" }
			}
		} }
	}, async (ctx) => {
		const { providerId } = ctx.query;
		const provider = await checkProviderAccess(ctx, providerId);
		return ctx.json(sanitizeProvider(provider));
	});
};
function parseAndValidateConfig(configString, configType) {
	let config = null;
	try {
		config = safeJsonParse(configString);
	} catch {
		config = null;
	}
	if (!config) throw new APIError("BAD_REQUEST", { message: `Cannot update ${configType} config for a provider that doesn't have ${configType} configured` });
	return config;
}
function mergeOIDCConfig(current, updates, issuer) {
	return {
		...current,
		...updates,
		issuer,
		pkce: updates.pkce ?? current.pkce ?? true,
		clientId: updates.clientId ?? current.clientId,
		clientSecret: updates.clientSecret ?? current.clientSecret,
		discoveryEndpoint: updates.discoveryEndpoint ?? current.discoveryEndpoint,
		mapping: updates.mapping ?? current.mapping,
		scopes: updates.scopes ?? current.scopes,
		authorizationEndpoint: updates.authorizationEndpoint ?? current.authorizationEndpoint,
		tokenEndpoint: updates.tokenEndpoint ?? current.tokenEndpoint,
		userInfoEndpoint: updates.userInfoEndpoint ?? current.userInfoEndpoint,
		jwksEndpoint: updates.jwksEndpoint ?? current.jwksEndpoint,
		tokenEndpointAuthentication: updates.tokenEndpointAuthentication ?? current.tokenEndpointAuthentication
	};
}
const updateSSOProvider = (options) => {
	return createAuthEndpoint("/sso/update-provider", {
		method: "POST",
		use: [sessionMiddleware],
		body: updateSSOProviderBodySchema.extend({ providerId: z.string() }),
		metadata: { openapi: {
			operationId: "updateSSOProvider",
			summary: "Update SSO provider",
			description: "Partially update an SSO provider. Only provided fields are updated. If domain changes, domainVerified is reset to false.",
			responses: {
				"200": { description: "SSO provider updated successfully" },
				"404": { description: "Provider not found" },
				"403": { description: "Access denied" }
			}
		} }
	}, async (ctx) => {
		const { providerId, ...body } = ctx.body;
		const { issuer, domain, oidcConfig } = body;
		if (!issuer && !domain && !oidcConfig) throw new APIError("BAD_REQUEST", { message: "No fields provided for update" });
		const existingProvider = await checkProviderAccess(ctx, providerId);
		const updateData = {};
		if (body.issuer !== void 0) updateData.issuer = body.issuer;
		if (body.domain !== void 0) {
			updateData.domain = body.domain;
			if (body.domain !== existingProvider.domain) updateData.domainVerified = false;
		}
		if (body.oidcConfig) {
			const currentOidcConfig = parseAndValidateConfig(existingProvider.oidcConfig, "OIDC");
			const updatedOidcConfig = mergeOIDCConfig(currentOidcConfig, body.oidcConfig, updateData.issuer || currentOidcConfig.issuer || existingProvider.issuer);
			updateData.oidcConfig = JSON.stringify(updatedOidcConfig);
		}
		await ctx.context.adapter.update({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: providerId
			}],
			update: updateData
		});
		const fullProvider = await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: providerId
			}]
		});
		if (!fullProvider) throw new APIError("NOT_FOUND", { message: "Provider not found after update" });
		return ctx.json(sanitizeProvider(fullProvider));
	});
};
const deleteSSOProvider = () => {
	return createAuthEndpoint("/sso/delete-provider", {
		method: "POST",
		use: [sessionMiddleware],
		body: z.object({ providerId: z.string() }),
		metadata: { openapi: {
			operationId: "deleteSSOProvider",
			summary: "Delete SSO provider",
			description: "Deletes an SSO provider",
			responses: {
				"200": { description: "SSO provider deleted successfully" },
				"404": { description: "Provider not found" },
				"403": { description: "Access denied" }
			}
		} }
	}, async (ctx) => {
		const { providerId } = ctx.body;
		await checkProviderAccess(ctx, providerId);
		await ctx.context.adapter.delete({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: providerId
			}]
		});
		return ctx.json({ success: true });
	});
};

//#endregion
//#region src/oidc/types.ts
/**
* Custom error class for OIDC discovery failures.
* Can be caught and mapped to APIError at the edge.
*/
var DiscoveryError = class DiscoveryError extends Error {
	code;
	details;
	constructor(code, message, details, options) {
		super(message, options);
		this.name = "DiscoveryError";
		this.code = code;
		this.details = details;
		if (Error.captureStackTrace) Error.captureStackTrace(this, DiscoveryError);
	}
};
/**
* Required fields that must be present in a valid discovery document.
*/
const REQUIRED_DISCOVERY_FIELDS = [
	"issuer",
	"authorization_endpoint",
	"token_endpoint",
	"jwks_uri"
];

//#endregion
//#region src/oidc/discovery.ts
/**
* OIDC Discovery Pipeline
*
* Implements OIDC discovery document fetching, validation, and hydration.
* This module is used both at provider registration time (to persist validated config)
* and at runtime (to hydrate legacy providers that are missing metadata).
*
* @see https://openid.net/specs/openid-connect-discovery-1_0.html
*/
/** Default timeout for discovery requests (10 seconds) */
const DEFAULT_DISCOVERY_TIMEOUT = 1e4;
/**
* Main entry point: Discover and hydrate OIDC configuration from an issuer.
*
* This function:
* 1. Computes the discovery URL from the issuer
* 2. Validates the discovery URL
* 3. Fetches the discovery document
* 4. Validates the discovery document (issuer match + required fields)
* 5. Normalizes URLs
* 6. Selects token endpoint auth method
* 7. Merges with existing config (existing values take precedence)
*
* @param params - Discovery parameters
* @param isTrustedOrigin - Origin verification tester function
* @returns Hydrated OIDC configuration ready for persistence
* @throws DiscoveryError on any failure
*/
async function discoverOIDCConfig(params) {
	const { issuer, existingConfig, timeout = DEFAULT_DISCOVERY_TIMEOUT } = params;
	const discoveryUrl = params.discoveryEndpoint || existingConfig?.discoveryEndpoint || computeDiscoveryUrl(issuer);
	validateDiscoveryUrl(discoveryUrl, params.isTrustedOrigin);
	const discoveryDoc = await fetchDiscoveryDocument(discoveryUrl, timeout);
	validateDiscoveryDocument(discoveryDoc, issuer);
	const normalizedDoc = normalizeDiscoveryUrls(discoveryDoc, issuer, params.isTrustedOrigin);
	const tokenEndpointAuth = selectTokenEndpointAuthMethod(normalizedDoc, existingConfig?.tokenEndpointAuthentication);
	return {
		issuer: existingConfig?.issuer ?? normalizedDoc.issuer,
		discoveryEndpoint: existingConfig?.discoveryEndpoint ?? discoveryUrl,
		authorizationEndpoint: existingConfig?.authorizationEndpoint ?? normalizedDoc.authorization_endpoint,
		tokenEndpoint: existingConfig?.tokenEndpoint ?? normalizedDoc.token_endpoint,
		jwksEndpoint: existingConfig?.jwksEndpoint ?? normalizedDoc.jwks_uri,
		userInfoEndpoint: existingConfig?.userInfoEndpoint ?? normalizedDoc.userinfo_endpoint,
		tokenEndpointAuthentication: existingConfig?.tokenEndpointAuthentication ?? tokenEndpointAuth,
		scopesSupported: existingConfig?.scopesSupported ?? normalizedDoc.scopes_supported
	};
}
/**
* Compute the discovery URL from an issuer URL.
*
* Per OIDC Discovery spec, the discovery document is located at:
* <issuer>/.well-known/openid-configuration
*
* Handles trailing slashes correctly.
*/
function computeDiscoveryUrl(issuer) {
	return `${issuer.endsWith("/") ? issuer.slice(0, -1) : issuer}/.well-known/openid-configuration`;
}
/**
* Validate a discovery URL before fetching.
*
* @param url - The discovery URL to validate
* @param isTrustedOrigin - Origin verification tester function
* @throws DiscoveryError if URL is invalid
*/
function validateDiscoveryUrl(url, isTrustedOrigin) {
	const discoveryEndpoint = parseURL("discoveryEndpoint", url).toString();
	if (!isTrustedOrigin(discoveryEndpoint)) throw new DiscoveryError("discovery_untrusted_origin", `The main discovery endpoint "${discoveryEndpoint}" is not trusted by your trusted origins configuration.`, { url: discoveryEndpoint });
}
/**
* Fetch the OIDC discovery document from the IdP.
*
* @param url - The discovery endpoint URL
* @param timeout - Request timeout in milliseconds
* @returns The parsed discovery document
* @throws DiscoveryError on network errors, timeouts, or invalid responses
*/
async function fetchDiscoveryDocument(url, timeout = DEFAULT_DISCOVERY_TIMEOUT) {
	try {
		const response = await betterFetch(url, {
			method: "GET",
			timeout
		});
		if (response.error) {
			const { status } = response.error;
			if (status === 404) throw new DiscoveryError("discovery_not_found", "Discovery endpoint not found", {
				url,
				status
			});
			if (status === 408) throw new DiscoveryError("discovery_timeout", "Discovery request timed out", {
				url,
				timeout
			});
			throw new DiscoveryError("discovery_unexpected_error", `Unexpected discovery error: ${response.error.statusText}`, {
				url,
				...response.error
			});
		}
		if (!response.data) throw new DiscoveryError("discovery_invalid_json", "Discovery endpoint returned an empty response", { url });
		const data = response.data;
		if (typeof data === "string") throw new DiscoveryError("discovery_invalid_json", "Discovery endpoint returned invalid JSON", {
			url,
			bodyPreview: data.slice(0, 200)
		});
		return data;
	} catch (error) {
		if (error instanceof DiscoveryError) throw error;
		if (error instanceof Error && error.name === "AbortError") throw new DiscoveryError("discovery_timeout", "Discovery request timed out", {
			url,
			timeout
		});
		throw new DiscoveryError("discovery_unexpected_error", `Unexpected error during discovery: ${error instanceof Error ? error.message : String(error)}`, { url }, { cause: error });
	}
}
/**
* Validate a discovery document.
*
* Checks:
* 1. All required fields are present
* 2. Issuer matches the configured issuer (case-sensitive, exact match)
*
* Invariant: If this function returns without throwing, the document is safe
* to use for hydrating OIDC config (required fields present, issuer matches
* configured value, basic structural sanity verified).
*
* @param doc - The discovery document to validate
* @param configuredIssuer - The expected issuer value
* @throws DiscoveryError if validation fails
*/
function validateDiscoveryDocument(doc, configuredIssuer) {
	const missingFields = [];
	for (const field of REQUIRED_DISCOVERY_FIELDS) if (!doc[field]) missingFields.push(field);
	if (missingFields.length > 0) throw new DiscoveryError("discovery_incomplete", `Discovery document is missing required fields: ${missingFields.join(", ")}`, { missingFields });
	if ((doc.issuer.endsWith("/") ? doc.issuer.slice(0, -1) : doc.issuer) !== (configuredIssuer.endsWith("/") ? configuredIssuer.slice(0, -1) : configuredIssuer)) throw new DiscoveryError("issuer_mismatch", `Discovered issuer "${doc.issuer}" does not match configured issuer "${configuredIssuer}"`, {
		discovered: doc.issuer,
		configured: configuredIssuer
	});
}
/**
* Normalize URLs in the discovery document.
*
* @param document - The discovery document
* @param issuer - The base issuer URL
* @param isTrustedOrigin - Origin verification tester function
* @returns The normalized discovery document
*/
function normalizeDiscoveryUrls(document, issuer, isTrustedOrigin) {
	const doc = { ...document };
	doc.token_endpoint = normalizeAndValidateUrl("token_endpoint", doc.token_endpoint, issuer, isTrustedOrigin);
	doc.authorization_endpoint = normalizeAndValidateUrl("authorization_endpoint", doc.authorization_endpoint, issuer, isTrustedOrigin);
	doc.jwks_uri = normalizeAndValidateUrl("jwks_uri", doc.jwks_uri, issuer, isTrustedOrigin);
	if (doc.userinfo_endpoint) doc.userinfo_endpoint = normalizeAndValidateUrl("userinfo_endpoint", doc.userinfo_endpoint, issuer, isTrustedOrigin);
	if (doc.revocation_endpoint) doc.revocation_endpoint = normalizeAndValidateUrl("revocation_endpoint", doc.revocation_endpoint, issuer, isTrustedOrigin);
	if (doc.end_session_endpoint) doc.end_session_endpoint = normalizeAndValidateUrl("end_session_endpoint", doc.end_session_endpoint, issuer, isTrustedOrigin);
	if (doc.introspection_endpoint) doc.introspection_endpoint = normalizeAndValidateUrl("introspection_endpoint", doc.introspection_endpoint, issuer, isTrustedOrigin);
	return doc;
}
/**
* Normalizes and validates a single URL endpoint
* @param name The url name
* @param endpoint The url to validate
* @param issuer The issuer base url
* @param isTrustedOrigin - Origin verification tester function
* @returns
*/
function normalizeAndValidateUrl(name, endpoint, issuer, isTrustedOrigin) {
	const url = normalizeUrl(name, endpoint, issuer);
	if (!isTrustedOrigin(url)) throw new DiscoveryError("discovery_untrusted_origin", `The ${name} "${url}" is not trusted by your trusted origins configuration.`, {
		endpoint: name,
		url
	});
	return url;
}
/**
* Normalize a single URL endpoint.
*
* @param name - The endpoint name (e.g token_endpoint)
* @param endpoint - The endpoint URL to normalize
* @param issuer - The base issuer URL
* @returns The normalized endpoint URL
*/
function normalizeUrl(name, endpoint, issuer) {
	try {
		return parseURL(name, endpoint).toString();
	} catch {
		const issuerURL = parseURL(name, issuer);
		const basePath = issuerURL.pathname.replace(/\/+$/, "");
		const endpointPath = endpoint.replace(/^\/+/, "");
		return parseURL(name, basePath + "/" + endpointPath, issuerURL.origin).toString();
	}
}
/**
* Parses the given URL or throws in case of invalid or unsupported protocols
*
* @param name the url name
* @param endpoint the endpoint url
* @param [base] optional base path
* @returns
*/
function parseURL(name, endpoint, base) {
	let endpointURL;
	try {
		endpointURL = new URL(endpoint, base);
		if (endpointURL.protocol === "http:" || endpointURL.protocol === "https:") return endpointURL;
	} catch (error) {
		throw new DiscoveryError("discovery_invalid_url", `The url "${name}" must be valid: ${endpoint}`, { url: endpoint }, { cause: error });
	}
	throw new DiscoveryError("discovery_invalid_url", `The url "${name}" must use the http or https supported protocols: ${endpoint}`, {
		url: endpoint,
		protocol: endpointURL.protocol
	});
}
/**
* Select the token endpoint authentication method.
*
* @param doc - The discovery document
* @param existing - Existing authentication method from config
* @returns The selected authentication method
*/
function selectTokenEndpointAuthMethod(doc, existing) {
	if (existing) return existing;
	const supported = doc.token_endpoint_auth_methods_supported;
	if (!supported || supported.length === 0) return "client_secret_basic";
	if (supported.includes("client_secret_basic")) return "client_secret_basic";
	if (supported.includes("client_secret_post")) return "client_secret_post";
	return "client_secret_basic";
}
/**
* Check if a provider configuration needs runtime discovery.
*
* Returns true if we need discovery at runtime to complete the token exchange
* and validation. Specifically checks for:
* - `tokenEndpoint` - required for exchanging authorization code for tokens
* - `jwksEndpoint` - required for validating ID token signatures
*
* Note: `authorizationEndpoint` is handled separately in the sign-in flow,
* so it's not checked here.
*
* @param config - Partial OIDC config from the provider
* @returns true if runtime discovery should be performed
*/
function needsRuntimeDiscovery(config) {
	if (!config) return true;
	return !config.tokenEndpoint || !config.jwksEndpoint;
}

//#endregion
//#region src/oidc/errors.ts
/**
* OIDC Discovery Error Mapping
*
* Maps DiscoveryError codes to appropriate APIError responses.
* Used at the boundary between the discovery pipeline and HTTP handlers.
*/
/**
* Maps a DiscoveryError to an appropriate APIError for HTTP responses.
*
* Error code mapping:
* - discovery_invalid_url       → 400 BAD_REQUEST
* - discovery_not_found         → 400 BAD_REQUEST
* - discovery_invalid_json      → 400 BAD_REQUEST
* - discovery_incomplete        → 400 BAD_REQUEST
* - issuer_mismatch             → 400 BAD_REQUEST
* - unsupported_token_auth_method → 400 BAD_REQUEST
* - discovery_timeout           → 502 BAD_GATEWAY
* - discovery_unexpected_error  → 502 BAD_GATEWAY
*
* @param error - The DiscoveryError to map
* @returns An APIError with appropriate status and message
*/
function mapDiscoveryErrorToAPIError(error) {
	switch (error.code) {
		case "discovery_timeout": return new APIError("BAD_GATEWAY", {
			message: `OIDC discovery timed out: ${error.message}`,
			code: error.code
		});
		case "discovery_unexpected_error": return new APIError("BAD_GATEWAY", {
			message: `OIDC discovery failed: ${error.message}`,
			code: error.code
		});
		case "discovery_not_found": return new APIError("BAD_REQUEST", {
			message: `OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. ${error.message}`,
			code: error.code
		});
		case "discovery_invalid_url": return new APIError("BAD_REQUEST", {
			message: `Invalid OIDC discovery URL: ${error.message}`,
			code: error.code
		});
		case "discovery_untrusted_origin": return new APIError("BAD_REQUEST", {
			message: `Untrusted OIDC discovery URL: ${error.message}`,
			code: error.code
		});
		case "discovery_invalid_json": return new APIError("BAD_REQUEST", {
			message: `OIDC discovery returned invalid data: ${error.message}`,
			code: error.code
		});
		case "discovery_incomplete": return new APIError("BAD_REQUEST", {
			message: `OIDC discovery document is missing required fields: ${error.message}`,
			code: error.code
		});
		case "issuer_mismatch": return new APIError("BAD_REQUEST", {
			message: `OIDC issuer mismatch: ${error.message}`,
			code: error.code
		});
		case "unsupported_token_auth_method": return new APIError("BAD_REQUEST", {
			message: `Incompatible OIDC provider: ${error.message}`,
			code: error.code
		});
		default:
			error.code;
			return new APIError("INTERNAL_SERVER_ERROR", {
				message: `Unexpected discovery error: ${error.message}`,
				code: "discovery_unexpected_error"
			});
	}
}

//#endregion
//#region src/routes/sso.ts
const ssoProviderBodySchema = z.object({
	providerId: z.string({}).meta({ description: "The ID of the provider. This is used to identify the provider during login and callback" }),
	issuer: z.string({}).meta({ description: "The issuer of the provider" }),
	domain: z.string({}).meta({ description: "The domain(s) of the provider. For enterprise multi-domain SSO where a single IdP serves multiple email domains, use comma-separated values (e.g., 'company.com,subsidiary.com,acquired-company.com')" }),
	oidcConfig: z.object({
		clientId: z.string({}).meta({ description: "The client ID" }),
		clientSecret: z.string({}).meta({ description: "The client secret" }),
		authorizationEndpoint: z.string({}).meta({ description: "The authorization endpoint" }).optional(),
		tokenEndpoint: z.string({}).meta({ description: "The token endpoint" }).optional(),
		userInfoEndpoint: z.string({}).meta({ description: "The user info endpoint" }).optional(),
		tokenEndpointAuthentication: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
		jwksEndpoint: z.string({}).meta({ description: "The JWKS endpoint" }).optional(),
		discoveryEndpoint: z.string().optional(),
		skipDiscovery: z.boolean().meta({ description: "Skip OIDC discovery during registration. When true, you must provide authorizationEndpoint, tokenEndpoint, and jwksEndpoint manually." }).optional(),
		scopes: z.array(z.string(), {}).meta({ description: "The scopes to request. Defaults to ['openid', 'email', 'profile', 'offline_access']" }).optional(),
		pkce: z.boolean({}).meta({ description: "Whether to use PKCE for the authorization flow" }).default(true).optional(),
		mapping: z.object({
			id: z.string({}).meta({ description: "Field mapping for user ID (defaults to 'sub')" }),
			email: z.string({}).meta({ description: "Field mapping for email (defaults to 'email')" }),
			emailVerified: z.string({}).meta({ description: "Field mapping for email verification (defaults to 'email_verified')" }).optional(),
			name: z.string({}).meta({ description: "Field mapping for name (defaults to 'name')" }),
			image: z.string({}).meta({ description: "Field mapping for image (defaults to 'picture')" }).optional(),
			extraFields: z.record(z.string(), z.any()).optional()
		}).optional()
	}),
	organizationId: z.string({}).meta({ description: "If organization plugin is enabled, the organization id to link the provider to" }).optional(),
	overrideUserInfo: z.boolean({}).meta({ description: "Override user info with the provider info. Defaults to false" }).default(false).optional()
});
const registerSSOProvider = (options) => {
	return createAuthEndpoint("/sso/register", {
		method: "POST",
		body: ssoProviderBodySchema,
		use: [sessionMiddleware],
		metadata: { openapi: {
			operationId: "registerSSOProvider",
			summary: "Register an OIDC provider",
			description: "This endpoint is used to register an OIDC provider. This is used to configure the provider and link it to an organization",
			responses: { "200": { description: "OIDC provider created successfully" } }
		} }
	}, async (ctx) => {
		const user = ctx.context.session?.user;
		if (!user) throw new APIError("UNAUTHORIZED");
		const limit = typeof options?.providersLimit === "function" ? await options.providersLimit(user) : options?.providersLimit ?? 10;
		if (!limit) throw new APIError("FORBIDDEN", { message: "SSO provider registration is disabled" });
		if ((await ctx.context.adapter.findMany({
			model: "ssoProvider",
			where: [{
				field: "userId",
				value: user.id
			}]
		})).length >= limit) throw new APIError("FORBIDDEN", { message: "You have reached the maximum number of SSO providers" });
		const body = ctx.body;
		if (z.string().url().safeParse(body.issuer).error) throw new APIError("BAD_REQUEST", { message: "Invalid issuer. Must be a valid URL" });
		if (ctx.body.organizationId) {
			if (!await ctx.context.adapter.findOne({
				model: "member",
				where: [{
					field: "userId",
					value: user.id
				}, {
					field: "organizationId",
					value: ctx.body.organizationId
				}]
			})) throw new APIError("BAD_REQUEST", { message: "You are not a member of the organization" });
		}
		if (await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: body.providerId
			}]
		})) {
			ctx.context.logger.info(`SSO provider creation attempt with existing providerId: ${body.providerId}`);
			throw new APIError("UNPROCESSABLE_ENTITY", { message: "SSO provider with this providerId already exists" });
		}
		let hydratedOIDCConfig = null;
		if (!body.oidcConfig.skipDiscovery) try {
			hydratedOIDCConfig = await discoverOIDCConfig({
				issuer: body.issuer,
				existingConfig: {
					discoveryEndpoint: body.oidcConfig.discoveryEndpoint,
					authorizationEndpoint: body.oidcConfig.authorizationEndpoint,
					tokenEndpoint: body.oidcConfig.tokenEndpoint,
					jwksEndpoint: body.oidcConfig.jwksEndpoint,
					userInfoEndpoint: body.oidcConfig.userInfoEndpoint,
					tokenEndpointAuthentication: body.oidcConfig.tokenEndpointAuthentication
				},
				isTrustedOrigin: (url) => ctx.context.isTrustedOrigin(url)
			});
		} catch (error) {
			if (error instanceof DiscoveryError) throw mapDiscoveryErrorToAPIError(error);
			throw error;
		}
		const buildOIDCConfig = () => {
			if (body.oidcConfig.skipDiscovery) return JSON.stringify({
				issuer: body.issuer,
				clientId: body.oidcConfig.clientId,
				clientSecret: body.oidcConfig.clientSecret,
				authorizationEndpoint: body.oidcConfig.authorizationEndpoint,
				tokenEndpoint: body.oidcConfig.tokenEndpoint,
				tokenEndpointAuthentication: body.oidcConfig.tokenEndpointAuthentication || "client_secret_basic",
				jwksEndpoint: body.oidcConfig.jwksEndpoint,
				pkce: body.oidcConfig.pkce,
				discoveryEndpoint: body.oidcConfig.discoveryEndpoint || `${body.issuer}/.well-known/openid-configuration`,
				mapping: body.oidcConfig.mapping,
				scopes: body.oidcConfig.scopes,
				userInfoEndpoint: body.oidcConfig.userInfoEndpoint,
				overrideUserInfo: ctx.body.overrideUserInfo || options?.defaultOverrideUserInfo || false
			});
			if (!hydratedOIDCConfig) return null;
			return JSON.stringify({
				issuer: hydratedOIDCConfig.issuer,
				clientId: body.oidcConfig.clientId,
				clientSecret: body.oidcConfig.clientSecret,
				authorizationEndpoint: hydratedOIDCConfig.authorizationEndpoint,
				tokenEndpoint: hydratedOIDCConfig.tokenEndpoint,
				tokenEndpointAuthentication: hydratedOIDCConfig.tokenEndpointAuthentication,
				jwksEndpoint: hydratedOIDCConfig.jwksEndpoint,
				pkce: body.oidcConfig.pkce,
				discoveryEndpoint: hydratedOIDCConfig.discoveryEndpoint,
				mapping: body.oidcConfig.mapping,
				scopes: body.oidcConfig.scopes,
				userInfoEndpoint: hydratedOIDCConfig.userInfoEndpoint,
				overrideUserInfo: ctx.body.overrideUserInfo || options?.defaultOverrideUserInfo || false
			});
		};
		const provider = await ctx.context.adapter.create({
			model: "ssoProvider",
			data: {
				issuer: body.issuer,
				domain: body.domain,
				domainVerified: false,
				oidcConfig: buildOIDCConfig(),
				organizationId: body.organizationId,
				userId: ctx.context.session.user.id,
				providerId: body.providerId
			}
		});
		let domainVerificationToken;
		let domainVerified;
		if (options?.domainVerification?.enabled) {
			domainVerified = false;
			domainVerificationToken = generateRandomString(24);
			await ctx.context.adapter.create({
				model: "verification",
				data: {
					identifier: getVerificationIdentifier(options, provider.providerId),
					createdAt: /* @__PURE__ */ new Date(),
					updatedAt: /* @__PURE__ */ new Date(),
					value: domainVerificationToken,
					expiresAt: new Date(Date.now() + 3600 * 24 * 7 * 1e3)
				}
			});
		}
		const result = {
			...provider,
			oidcConfig: safeJsonParse(provider.oidcConfig),
			redirectURI: `${ctx.context.baseURL}/sso/callback/${provider.providerId}`,
			...options?.domainVerification?.enabled ? { domainVerified } : {},
			...options?.domainVerification?.enabled ? { domainVerificationToken } : {}
		};
		return ctx.json(result);
	});
};
const signInSSOBodySchema = z.object({
	email: z.string({}).meta({ description: "The email address to sign in with. This is used to identify the issuer to sign in with. It's optional if the issuer is provided" }).optional(),
	organizationSlug: z.string({}).meta({ description: "The slug of the organization to sign in with" }).optional(),
	providerId: z.string({}).meta({ description: "The ID of the provider to sign in with. This can be provided instead of email or issuer" }).optional(),
	domain: z.string({}).meta({ description: "The domain of the provider." }).optional(),
	callbackURL: z.string({}).meta({ description: "The URL to redirect to after login" }),
	errorCallbackURL: z.string({}).meta({ description: "The URL to redirect to after login" }).optional(),
	newUserCallbackURL: z.string({}).meta({ description: "The URL to redirect to after login if the user is new" }).optional(),
	scopes: z.array(z.string(), {}).meta({ description: "Scopes to request from the provider." }).optional(),
	loginHint: z.string({}).meta({ description: "Login hint to send to the identity provider (e.g., email or identifier). If supported, will be sent as 'login_hint'." }).optional(),
	requestSignUp: z.boolean({}).meta({ description: "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider" }).optional()
});
const signInSSO = (options) => {
	return createAuthEndpoint("/sign-in/sso", {
		method: "POST",
		body: signInSSOBodySchema,
		metadata: { openapi: {
			operationId: "signInWithSSO",
			summary: "Sign in with SSO provider",
			description: "This endpoint is used to sign in with an SSO provider. It redirects to the provider's authorization URL",
			responses: { "200": { description: "Authorization URL generated successfully for SSO sign-in" } }
		} }
	}, async (ctx) => {
		const body = ctx.body;
		let { email, organizationSlug, providerId, domain } = body;
		if (!options?.defaultSSO?.length && !email && !organizationSlug && !domain && !providerId) throw new APIError("BAD_REQUEST", { message: "email, organizationSlug, domain or providerId is required" });
		domain = body.domain || email?.split("@")[1];
		let orgId = "";
		if (organizationSlug) orgId = await ctx.context.adapter.findOne({
			model: "organization",
			where: [{
				field: "slug",
				value: organizationSlug
			}]
		}).then((res) => {
			if (!res) return "";
			return res.id;
		});
		let provider = null;
		if (options?.defaultSSO?.length) {
			const matchingDefault = providerId ? options.defaultSSO.find((defaultProvider) => defaultProvider.providerId === providerId) : options.defaultSSO.find((defaultProvider) => defaultProvider.domain === domain);
			if (matchingDefault) provider = {
				issuer: matchingDefault.oidcConfig?.issuer || "",
				providerId: matchingDefault.providerId,
				userId: "default",
				oidcConfig: matchingDefault.oidcConfig,
				domain: matchingDefault.domain,
				...options.domainVerification?.enabled ? { domainVerified: true } : {}
			};
		}
		if (!providerId && !orgId && !domain) throw new APIError("BAD_REQUEST", { message: "providerId, orgId or domain is required" });
		if (!provider) {
			const parseProvider = (res) => {
				if (!res) return null;
				return {
					...res,
					oidcConfig: res.oidcConfig ? safeJsonParse(res.oidcConfig) || void 0 : void 0
				};
			};
			if (providerId || orgId) provider = parseProvider(await ctx.context.adapter.findOne({
				model: "ssoProvider",
				where: [{
					field: providerId ? "providerId" : "organizationId",
					value: providerId || orgId
				}]
			}));
			else if (domain) {
				provider = parseProvider(await ctx.context.adapter.findOne({
					model: "ssoProvider",
					where: [{
						field: "domain",
						value: domain
					}]
				}));
				if (!provider) provider = parseProvider((await ctx.context.adapter.findMany({ model: "ssoProvider" })).find((p) => domainMatches(domain, p.domain)) ?? null);
			}
		}
		if (!provider) throw new APIError("NOT_FOUND", { message: "No provider found for the issuer" });
		if (!provider.oidcConfig) throw new APIError("BAD_REQUEST", { message: "OIDC provider is not configured" });
		if (options?.domainVerification?.enabled && !("domainVerified" in provider && provider.domainVerified)) throw new APIError("UNAUTHORIZED", { message: "Provider domain has not been verified" });
		let finalAuthUrl = provider.oidcConfig.authorizationEndpoint;
		if (!finalAuthUrl && provider.oidcConfig.discoveryEndpoint) {
			const discovery = await betterFetch(provider.oidcConfig.discoveryEndpoint, { method: "GET" });
			if (discovery.data) finalAuthUrl = discovery.data.authorization_endpoint;
		}
		if (!finalAuthUrl) throw new APIError("BAD_REQUEST", { message: "Invalid OIDC configuration. Authorization URL not found." });
		const state = await generateState(ctx, void 0, false);
		const redirectURI = `${ctx.context.baseURL}/sso/callback/${provider.providerId}`;
		const authorizationURL = await createAuthorizationURL({
			id: provider.issuer,
			options: {
				clientId: provider.oidcConfig.clientId,
				clientSecret: provider.oidcConfig.clientSecret
			},
			redirectURI,
			state: state.state,
			codeVerifier: provider.oidcConfig.pkce ? state.codeVerifier : void 0,
			scopes: ctx.body.scopes || provider.oidcConfig.scopes || [
				"openid",
				"email",
				"profile",
				"offline_access"
			],
			loginHint: ctx.body.loginHint || email,
			authorizationEndpoint: finalAuthUrl
		});
		return ctx.json({
			url: authorizationURL.toString(),
			redirect: true
		});
	});
};
const callbackSSOQuerySchema = z.object({
	code: z.string().optional(),
	state: z.string(),
	error: z.string().optional(),
	error_description: z.string().optional()
});
const callbackSSO = (options) => {
	return createAuthEndpoint("/sso/callback/:providerId", {
		method: "GET",
		query: callbackSSOQuerySchema,
		allowedMediaTypes: ["application/x-www-form-urlencoded", "application/json"],
		metadata: {
			...HIDE_METADATA,
			openapi: {
				operationId: "handleSSOCallback",
				summary: "Callback URL for SSO provider",
				description: "This endpoint is used as the callback URL for SSO providers. It handles the authorization code and exchanges it for an access token",
				responses: { "302": { description: "Redirects to the callback URL" } }
			}
		}
	}, async (ctx) => {
		const { code, error, error_description } = ctx.query;
		const stateData = await parseState(ctx);
		if (!stateData) {
			const errorURL = ctx.context.options.onAPIError?.errorURL || `${ctx.context.baseURL}/error`;
			throw ctx.redirect(`${errorURL}?error=invalid_state`);
		}
		const { callbackURL, errorURL, newUserURL, requestSignUp } = stateData;
		if (!code || error) throw ctx.redirect(`${errorURL || callbackURL}?error=${error}&error_description=${error_description}`);
		let provider = null;
		if (options?.defaultSSO?.length) {
			const matchingDefault = options.defaultSSO.find((defaultProvider) => defaultProvider.providerId === ctx.params.providerId);
			if (matchingDefault) provider = {
				...matchingDefault,
				issuer: matchingDefault.oidcConfig?.issuer || "",
				userId: "default",
				...options.domainVerification?.enabled ? { domainVerified: true } : {}
			};
		}
		if (!provider) provider = await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: ctx.params.providerId
			}]
		}).then((res) => {
			if (!res) return null;
			return {
				...res,
				oidcConfig: safeJsonParse(res.oidcConfig) || void 0
			};
		});
		if (!provider) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=provider not found`);
		if (options?.domainVerification?.enabled && !("domainVerified" in provider && provider.domainVerified)) throw new APIError("UNAUTHORIZED", { message: "Provider domain has not been verified" });
		let config = provider.oidcConfig;
		if (!config) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=provider not found`);
		const discovery = await betterFetch(config.discoveryEndpoint);
		if (discovery.data) config = {
			tokenEndpoint: discovery.data.token_endpoint,
			tokenEndpointAuthentication: discovery.data.token_endpoint_auth_method,
			userInfoEndpoint: discovery.data.userinfo_endpoint,
			scopes: [
				"openid",
				"email",
				"profile",
				"offline_access"
			],
			...config
		};
		if (!config.tokenEndpoint) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=token_endpoint_not_found`);
		const tokenResponse = await validateAuthorizationCode({
			code,
			codeVerifier: config.pkce ? stateData.codeVerifier : void 0,
			redirectURI: `${ctx.context.baseURL}/sso/callback/${provider.providerId}`,
			options: {
				clientId: config.clientId,
				clientSecret: config.clientSecret
			},
			tokenEndpoint: config.tokenEndpoint,
			authentication: config.tokenEndpointAuthentication === "client_secret_post" ? "post" : "basic"
		}).catch((e) => {
			if (e instanceof BetterFetchError) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=${e.message}`);
			return null;
		});
		if (!tokenResponse) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=token_response_not_found`);
		let userInfo = null;
		if (tokenResponse.idToken) {
			const idToken = decodeJwt(tokenResponse.idToken);
			if (!config.jwksEndpoint) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=jwks_endpoint_not_found`);
			const verified = await validateToken(tokenResponse.idToken, config.jwksEndpoint, {
				audience: config.clientId,
				issuer: provider.issuer
			}).catch((e) => {
				ctx.context.logger.error(e);
				return null;
			});
			if (!verified) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=token_not_verified`);
			const mapping = config.mapping || {};
			userInfo = {
				...Object.fromEntries(Object.entries(mapping.extraFields || {}).map(([key, value]) => [key, verified.payload[value]])),
				id: idToken[mapping.id || "sub"],
				email: idToken[mapping.email || "email"],
				emailVerified: options?.trustEmailVerified ? idToken[mapping.emailVerified || "email_verified"] : false,
				name: idToken[mapping.name || "name"],
				image: idToken[mapping.image || "picture"]
			};
		}
		if (!userInfo) {
			if (!config.userInfoEndpoint) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=user_info_endpoint_not_found`);
			const userInfoResponse = await betterFetch(config.userInfoEndpoint, { headers: { Authorization: `Bearer ${tokenResponse.accessToken}` } });
			if (userInfoResponse.error) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=${userInfoResponse.error.message}`);
			userInfo = userInfoResponse.data;
		}
		if (!userInfo.email || !userInfo.id) throw ctx.redirect(`${errorURL || callbackURL}?error=invalid_provider&error_description=missing_user_info`);
		const isTrustedProvider = "domainVerified" in provider && provider.domainVerified === true && validateEmailDomain(userInfo.email, provider.domain);
		const linked = await handleOAuthUserInfo(ctx, {
			userInfo: {
				email: userInfo.email,
				name: userInfo.name || "",
				id: userInfo.id,
				image: userInfo.image,
				emailVerified: options?.trustEmailVerified ? userInfo.emailVerified || false : false
			},
			account: {
				idToken: tokenResponse.idToken,
				accessToken: tokenResponse.accessToken,
				refreshToken: tokenResponse.refreshToken,
				accountId: userInfo.id,
				providerId: provider.providerId,
				accessTokenExpiresAt: tokenResponse.accessTokenExpiresAt,
				refreshTokenExpiresAt: tokenResponse.refreshTokenExpiresAt,
				scope: tokenResponse.scopes?.join(",")
			},
			callbackURL,
			disableSignUp: options?.disableImplicitSignUp && !requestSignUp,
			overrideUserInfo: config.overrideUserInfo,
			isTrustedProvider
		});
		if (linked.error) throw ctx.redirect(`${errorURL || callbackURL}?error=${linked.error}`);
		const { session, user } = linked.data;
		if (options?.provisionUser && linked.isRegister) await options.provisionUser({
			user,
			userInfo,
			token: tokenResponse,
			provider
		});
		await assignOrganizationFromProvider(ctx, {
			user,
			profile: {
				providerType: "oidc",
				providerId: provider.providerId,
				accountId: userInfo.id,
				email: userInfo.email,
				emailVerified: Boolean(userInfo.emailVerified),
				rawAttributes: userInfo
			},
			provider,
			token: tokenResponse,
			provisioningOptions: options?.organizationProvisioning
		});
		await setSessionCookie(ctx, {
			session,
			user
		});
		let toRedirectTo;
		try {
			toRedirectTo = (linked.isRegister ? newUserURL || callbackURL : callbackURL).toString();
		} catch {
			toRedirectTo = linked.isRegister ? newUserURL || callbackURL : callbackURL;
		}
		throw ctx.redirect(toRedirectTo);
	});
};

//#endregion
//#region src/index.ts
function oidcSso(options) {
	const optionsWithStore = options;
	let endpoints = {
		registerSSOProvider: registerSSOProvider(optionsWithStore),
		signInSSO: signInSSO(optionsWithStore),
		callbackSSO: callbackSSO(optionsWithStore),
		listSSOProviders: listSSOProviders(),
		getSSOProvider: getSSOProvider(),
		updateSSOProvider: updateSSOProvider(optionsWithStore),
		deleteSSOProvider: deleteSSOProvider()
	};
	if (options?.domainVerification?.enabled) {
		const domainVerificationEndpoints = {
			requestDomainVerification: requestDomainVerification(optionsWithStore),
			verifyDomain: verifyDomain(optionsWithStore)
		};
		endpoints = {
			...endpoints,
			...domainVerificationEndpoints
		};
	}
	return {
		id: "oidc-sso",
		endpoints,
		hooks: { after: [{
			matcher(context) {
				return context.path?.startsWith("/callback/") ?? false;
			},
			handler: createAuthMiddleware(async (ctx) => {
				const newSession = ctx.context.newSession;
				if (!newSession?.user) return;
				if (!ctx.context.hasPlugin("organization")) return;
				await assignOrganizationByDomain(ctx, {
					user: newSession.user,
					provisioningOptions: options?.organizationProvisioning,
					domainVerification: options?.domainVerification
				});
			})
		}] },
		schema: { ssoProvider: {
			modelName: options?.modelName ?? "ssoProvider",
			fields: {
				issuer: {
					type: "string",
					required: true,
					fieldName: options?.fields?.issuer ?? "issuer"
				},
				oidcConfig: {
					type: "string",
					required: false,
					fieldName: options?.fields?.oidcConfig ?? "oidcConfig"
				},
				userId: {
					type: "string",
					references: {
						model: "user",
						field: "id"
					},
					fieldName: options?.fields?.userId ?? "userId"
				},
				providerId: {
					type: "string",
					required: true,
					unique: true,
					fieldName: options?.fields?.providerId ?? "providerId"
				},
				organizationId: {
					type: "string",
					required: false,
					fieldName: options?.fields?.organizationId ?? "organizationId"
				},
				domain: {
					type: "string",
					required: true,
					fieldName: options?.fields?.domain ?? "domain"
				},
				...options?.domainVerification?.enabled ? { domainVerified: {
					type: "boolean",
					required: false
				} } : {}
			}
		} },
		options
	};
}

//#endregion
export { DiscoveryError, REQUIRED_DISCOVERY_FIELDS, computeDiscoveryUrl, discoverOIDCConfig, fetchDiscoveryDocument, needsRuntimeDiscovery, normalizeDiscoveryUrls, normalizeUrl, oidcSso, selectTokenEndpointAuthMethod, validateDiscoveryDocument, validateDiscoveryUrl };
//# sourceMappingURL=index.js.map