import type { Verification } from "better-auth";
import {
	APIError,
	createAuthEndpoint,
	sessionMiddleware,
} from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod/v4";
import type { SSOOptions, SSOProvider } from "../types";

const DNS_LABEL_MAX_LENGTH = 63;
const DEFAULT_TOKEN_PREFIX = "better-auth-token";

const domainVerificationBodySchema = z.object({
	providerId: z.string(),
});

export function getVerificationIdentifier(
	options: SSOOptions,
	providerId: string,
): string {
	const tokenPrefix =
		options.domainVerification?.tokenPrefix || DEFAULT_TOKEN_PREFIX;
	return `_${tokenPrefix}-${providerId}`;
}

/**
 * DNS-over-HTTPS TXT record lookup using Cloudflare's resolver.
 * Replaces node:dns/promises for edge/serverless compatibility.
 */
async function resolveTxtDoH(hostname: string): Promise<string[]> {
	const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`;
	const response = await fetch(url, {
		headers: { Accept: "application/dns-json" },
	});

	if (!response.ok) {
		throw new Error(`DoH request failed with status ${response.status}`);
	}

	const data = (await response.json()) as {
		Answer?: Array<{ type: number; data: string }>;
	};

	if (!data.Answer) {
		return [];
	}

	return data.Answer.filter((record) => record.type === 16).map((record) =>
		// TXT records come quoted from DoH JSON API — strip surrounding quotes
		record.data.replace(/^"|"$/g, ""),
	);
}

export const requestDomainVerification = (options: SSOOptions) => {
	return createAuthEndpoint(
		"/sso/request-domain-verification",
		{
			method: "POST",
			body: domainVerificationBodySchema,
			metadata: {
				openapi: {
					summary: "Request a domain verification",
					description:
						"Request a domain verification for the given SSO provider",
					responses: {
						"404": {
							description: "Provider not found",
						},
						"409": {
							description: "Domain has already been verified",
						},
						"201": {
							description: "Domain submitted for verification",
						},
					},
				},
			},
			use: [sessionMiddleware],
		},
		async (ctx) => {
			const body = ctx.body;
			const provider = await ctx.context.adapter.findOne<
				SSOProvider<SSOOptions>
			>({
				model: "ssoProvider",
				where: [{ field: "providerId", value: body.providerId }],
			});

			if (!provider) {
				throw new APIError("NOT_FOUND", {
					message: "Provider not found",
					code: "PROVIDER_NOT_FOUND",
				});
			}

			const userId = ctx.context.session.user.id;
			let isOrgMember = true;
			if (provider.organizationId && (ctx.context as any).hasPlugin?.("organization")) {
				const membershipsCount = await ctx.context.adapter.count({
					model: "member",
					where: [
						{ field: "userId", value: userId },
						{ field: "organizationId", value: provider.organizationId },
					],
				});

				isOrgMember = membershipsCount > 0;
			}

			if (provider.userId !== userId || !isOrgMember) {
				throw new APIError("FORBIDDEN", {
					message:
						"User must be owner of or belong to the SSO provider organization",
					code: "INSUFICCIENT_ACCESS",
				});
			}

			if ("domainVerified" in provider && provider.domainVerified) {
				throw new APIError("CONFLICT", {
					message: "Domain has already been verified",
					code: "DOMAIN_VERIFIED",
				});
			}

			const identifier = getVerificationIdentifier(
				options,
				provider.providerId,
			);

			const activeVerification =
				await ctx.context.adapter.findOne<Verification>({
					model: "verification",
					where: [
						{
							field: "identifier",
							value: identifier,
						},
						{ field: "expiresAt", value: new Date(), operator: "gt" },
					],
				});

			if (activeVerification) {
				ctx.setStatus(201);
				return ctx.json({ domainVerificationToken: activeVerification.value });
			}

			const domainVerificationToken = generateRandomString(24);
			await ctx.context.adapter.create<Verification>({
				model: "verification",
				data: {
					identifier,
					createdAt: new Date(),
					updatedAt: new Date(),
					value: domainVerificationToken,
					expiresAt: new Date(Date.now() + 3600 * 24 * 7 * 1000), // 1 week
				},
			});

			ctx.setStatus(201);
			return ctx.json({
				domainVerificationToken,
			});
		},
	);
};

export const verifyDomain = (options: SSOOptions) => {
	return createAuthEndpoint(
		"/sso/verify-domain",
		{
			method: "POST",
			body: domainVerificationBodySchema,
			metadata: {
				openapi: {
					summary: "Verify the provider domain ownership",
					description: "Verify the provider domain ownership via DNS records",
					responses: {
						"404": {
							description: "Provider not found",
						},
						"409": {
							description:
								"Domain has already been verified or no pending verification exists",
						},
						"502": {
							description:
								"Unable to verify domain ownership due to upstream validator error",
						},
						"204": {
							description: "Domain ownership was verified",
						},
					},
				},
			},
			use: [sessionMiddleware],
		},
		async (ctx) => {
			const body = ctx.body;
			const provider = await ctx.context.adapter.findOne<
				SSOProvider<SSOOptions>
			>({
				model: "ssoProvider",
				where: [{ field: "providerId", value: body.providerId }],
			});

			if (!provider) {
				throw new APIError("NOT_FOUND", {
					message: "Provider not found",
					code: "PROVIDER_NOT_FOUND",
				});
			}

			const userId = ctx.context.session.user.id;
			let isOrgMember = true;
			if (provider.organizationId && (ctx.context as any).hasPlugin?.("organization")) {
				const membershipsCount = await ctx.context.adapter.count({
					model: "member",
					where: [
						{ field: "userId", value: userId },
						{ field: "organizationId", value: provider.organizationId },
					],
				});

				isOrgMember = membershipsCount > 0;
			}

			if (provider.userId !== userId || !isOrgMember) {
				throw new APIError("FORBIDDEN", {
					message:
						"User must be owner of or belong to the SSO provider organization",
					code: "INSUFICCIENT_ACCESS",
				});
			}

			if ("domainVerified" in provider && provider.domainVerified) {
				throw new APIError("CONFLICT", {
					message: "Domain has already been verified",
					code: "DOMAIN_VERIFIED",
				});
			}

			const identifier = getVerificationIdentifier(
				options,
				provider.providerId,
			);

			if (identifier.length > DNS_LABEL_MAX_LENGTH) {
				throw new APIError("BAD_REQUEST", {
					message: `Verification identifier exceeds the DNS label limit of ${DNS_LABEL_MAX_LENGTH} characters`,
					code: "IDENTIFIER_TOO_LONG",
				});
			}

			const activeVerification =
				await ctx.context.adapter.findOne<Verification>({
					model: "verification",
					where: [
						{
							field: "identifier",
							value: identifier,
						},
						{ field: "expiresAt", value: new Date(), operator: "gt" },
					],
				});

			if (!activeVerification) {
				throw new APIError("NOT_FOUND", {
					message: "No pending domain verification exists",
					code: "NO_PENDING_VERIFICATION",
				});
			}

			let records: string[] = [];

			try {
				const hostname = new URL(provider.domain).hostname;
				records = await resolveTxtDoH(`${identifier}.${hostname}`);
			} catch (error) {
				ctx.context.logger.warn(
					"DNS resolution failure while validating domain ownership",
					error,
				);
			}

			const record = records.find((record) =>
				record.includes(
					`${activeVerification.identifier}=${activeVerification.value}`,
				),
			);
			if (!record) {
				throw new APIError("BAD_GATEWAY", {
					message: "Unable to verify domain ownership. Try again later",
					code: "DOMAIN_VERIFICATION_FAILED",
				});
			}

			await ctx.context.adapter.update<SSOProvider<SSOOptions>>({
				model: "ssoProvider",
				where: [{ field: "providerId", value: provider.providerId }],
				update: {
					domainVerified: true,
				},
			});

			ctx.setStatus(204);
			return;
		},
	);
};
