import type { BetterAuthClientPlugin } from "better-auth/client";
import type { OIDCSSOPlugin } from "./index";

interface OIDCSSOClientOptions {
	domainVerification?:
		| {
				enabled: boolean;
		  }
		| undefined;
}

export const oidcSsoClient = <CO extends OIDCSSOClientOptions>(
	options?: CO | undefined,
) => {
	return {
		id: "oidc-sso-client",
		$InferServerPlugin: {} as OIDCSSOPlugin<{
			domainVerification: {
				enabled: CO["domainVerification"] extends { enabled: true }
					? true
					: false;
			};
		}>,
		pathMethods: {
			"/sso/providers": "GET",
			"/sso/get-provider": "GET",
		},
	} satisfies BetterAuthClientPlugin;
};
