/**
 * Regression tests: every endpoint that touches the `member` or `organization`
 * model must be guarded by `hasPlugin("organization")`.
 *
 * These tests create a better-auth instance WITHOUT the organization plugin,
 * so the `member` and `organization` tables literally don't exist in the
 * SQLite database. Any missing guard causes the exact production error:
 *   "Model member not found in schema"
 */
import { describe, expect, it } from "vitest";
import {
	createTestInstanceWithoutOrg,
	registerProvider,
	SKIP_DISCOVERY_OIDC_CONFIG,
} from "./helpers";

describe("endpoints without organization plugin", () => {
	// ── Register ──────────────────────────────────────────────────────

	it("registers a provider without organizationId", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		const provider = await registerProvider(auth, headers);

		expect(provider.providerId).toBe("test-provider");
	});

	it("registers a provider WITH organizationId (guard skips member query)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		// Passing an organizationId that doesn't exist in any table.
		// Without the guard, this would crash querying `model: "member"`.
		const provider = await registerProvider(auth, headers, {
			organizationId: "org-that-does-not-exist",
		});

		expect(provider.providerId).toBe("test-provider");
	});

	// ── Sign-in ───────────────────────────────────────────────────────

	it("initiates sign-in with organizationSlug (guard skips organization query)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		// Register a provider so the sign-in lookup can find it by domain.
		await registerProvider(auth, headers);

		// organizationSlug is provided but the org plugin is absent.
		// Without the guard, this would crash querying `model: "organization"`.
		const result = await auth.api.signInSSO({
			body: {
				domain: "example.com",
				organizationSlug: "nonexistent-org",
				callbackURL: "http://localhost:3000/callback",
			},
		});

		expect(result).toHaveProperty("url");
		expect(result.redirect).toBe(true);
	});

	// ── List providers ────────────────────────────────────────────────

	it("lists providers including org-linked ones (guard skips batchCheckOrgAdmin)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		await registerProvider(auth, headers, {
			providerId: "personal-provider",
		});

		await registerProvider(auth, headers, {
			providerId: "org-provider",
			organizationId: "some-org-id",
		});

		const result = await auth.api.listSSOProviders({ headers });

		// Without org plugin, falls back to userId filter — both belong to test user.
		expect(result.providers.length).toBe(2);
	});

	// ── Get provider ──────────────────────────────────────────────────

	it("gets an org-linked provider (guard uses userId fallback)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		await registerProvider(auth, headers, {
			providerId: "org-provider",
			organizationId: "some-org-id",
		});

		const result = await auth.api.getSSOProvider({
			headers,
			query: { providerId: "org-provider" },
		});

		expect(result.providerId).toBe("org-provider");
	});

	// ── Update provider ───────────────────────────────────────────────

	it("updates an org-linked provider (checkProviderAccess guard)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		await registerProvider(auth, headers, {
			providerId: "org-provider",
			organizationId: "some-org-id",
		});

		const result = await auth.api.updateSSOProvider({
			headers,
			body: {
				providerId: "org-provider",
				domain: "updated.example.com",
			},
		});

		expect(result.domain).toBe("updated.example.com");
	});

	// ── Delete provider ───────────────────────────────────────────────

	it("deletes an org-linked provider (checkProviderAccess guard)", async () => {
		const { auth, signInWithTestUser } = await createTestInstanceWithoutOrg();
		const { headers } = await signInWithTestUser();

		await registerProvider(auth, headers, {
			providerId: "org-provider",
			organizationId: "some-org-id",
		});

		const result = await auth.api.deleteSSOProvider({
			headers,
			body: { providerId: "org-provider" },
		});

		expect(result.success).toBe(true);
	});

	// ── Domain verification ───────────────────────────────────────────

	it("requests domain verification for org-linked provider (guard skips member query)", async () => {
		const { auth, signInWithTestUser } =
			await createTestInstanceWithoutOrg({
				domainVerification: { enabled: true },
			});
		const { headers } = await signInWithTestUser();

		await registerProvider(auth, headers, {
			providerId: "org-provider",
			organizationId: "some-org-id",
		});

		const result = await auth.api.requestDomainVerification({
			headers,
			body: { providerId: "org-provider" },
		});

		expect(result).toHaveProperty("domainVerificationToken");
	});
});
