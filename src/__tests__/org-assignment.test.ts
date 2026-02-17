/**
 * Unit tests for organization assignment functions.
 * Verifies that assignOrganizationFromProvider and assignOrganizationByDomain
 * never touch the database adapter when hasPlugin("organization") is falsy.
 */
import { describe, expect, it, vi } from "vitest";
import {
	assignOrganizationByDomain,
	assignOrganizationFromProvider,
} from "../linking/org-assignment";

function createMockContext(hasPlugin?: (name: string) => boolean) {
	const adapter = {
		findOne: vi.fn(),
		findMany: vi.fn(),
		create: vi.fn(),
		count: vi.fn(),
	};

	// The functions access ctx.context.hasPlugin, so we need the nested structure
	const ctx = {
		context: {
			adapter,
			// hasPlugin is undefined when the organization plugin is not installed
			...(hasPlugin ? { hasPlugin } : {}),
		},
	};

	return { ctx, adapter };
}

describe("assignOrganizationFromProvider without org plugin", () => {
	it("skips assignment when hasPlugin is undefined", async () => {
		const { ctx, adapter } = createMockContext();

		await assignOrganizationFromProvider(ctx as any, {
			user: { id: "user-1", email: "user@example.com", name: "Test", createdAt: new Date(), updatedAt: new Date(), emailVerified: true, image: null },
			profile: {
				providerType: "oidc",
				providerId: "test-provider",
				accountId: "account-1",
				email: "user@example.com",
				emailVerified: true,
			},
			provider: {
				providerId: "test-provider",
				issuer: "https://idp.example.com",
				domain: "example.com",
				userId: "user-1",
				organizationId: "org-1",
			} as any,
		});

		expect(adapter.findOne).not.toHaveBeenCalled();
		expect(adapter.create).not.toHaveBeenCalled();
	});

	it("skips assignment when provider has no organizationId", async () => {
		const { ctx, adapter } = createMockContext(() => true);

		await assignOrganizationFromProvider(ctx as any, {
			user: { id: "user-1", email: "user@example.com", name: "Test", createdAt: new Date(), updatedAt: new Date(), emailVerified: true, image: null },
			profile: {
				providerType: "oidc",
				providerId: "test-provider",
				accountId: "account-1",
				email: "user@example.com",
				emailVerified: true,
			},
			provider: {
				providerId: "test-provider",
				issuer: "https://idp.example.com",
				domain: "example.com",
				userId: "user-1",
			} as any,
		});

		expect(adapter.findOne).not.toHaveBeenCalled();
		expect(adapter.create).not.toHaveBeenCalled();
	});
});

describe("assignOrganizationByDomain without org plugin", () => {
	it("skips assignment when hasPlugin is undefined", async () => {
		const { ctx, adapter } = createMockContext();

		await assignOrganizationByDomain(ctx as any, {
			user: { id: "user-1", email: "user@example.com", name: "Test", createdAt: new Date(), updatedAt: new Date(), emailVerified: true, image: null },
		});

		expect(adapter.findOne).not.toHaveBeenCalled();
		expect(adapter.findMany).not.toHaveBeenCalled();
		expect(adapter.create).not.toHaveBeenCalled();
	});

	it("skips assignment when provisioning is disabled", async () => {
		const { ctx, adapter } = createMockContext(() => true);

		await assignOrganizationByDomain(ctx as any, {
			user: { id: "user-1", email: "user@example.com", name: "Test", createdAt: new Date(), updatedAt: new Date(), emailVerified: true, image: null },
			provisioningOptions: { disabled: true },
		});

		expect(adapter.findOne).not.toHaveBeenCalled();
		expect(adapter.findMany).not.toHaveBeenCalled();
		expect(adapter.create).not.toHaveBeenCalled();
	});
});
