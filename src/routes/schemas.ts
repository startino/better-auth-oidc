import z from "zod/v4";

const oidcMappingSchema = z
	.object({
		id: z.string().optional(),
		email: z.string().optional(),
		emailVerified: z.string().optional(),
		name: z.string().optional(),
		image: z.string().optional(),
		extraFields: z.record(z.string(), z.any()).optional(),
	})
	.optional();

export const oidcConfigSchema = z.object({
	clientId: z.string().optional(),
	clientSecret: z.string().optional(),
	authorizationEndpoint: z.string().url().optional(),
	tokenEndpoint: z.string().url().optional(),
	userInfoEndpoint: z.string().url().optional(),
	tokenEndpointAuthentication: z
		.enum(["client_secret_post", "client_secret_basic"])
		.optional(),
	jwksEndpoint: z.string().url().optional(),
	discoveryEndpoint: z.string().url().optional(),
	scopes: z.array(z.string()).optional(),
	pkce: z.boolean().optional(),
	overrideUserInfo: z.boolean().optional(),
	mapping: oidcMappingSchema,
});

export const updateSSOProviderBodySchema = z.object({
	issuer: z.string().url().optional(),
	domain: z.string().optional(),
	oidcConfig: oidcConfigSchema.optional(),
});
