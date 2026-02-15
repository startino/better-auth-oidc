import type { Awaitable, OAuth2Tokens, User } from "better-auth";

export interface OIDCMapping {
	id?: string | undefined;
	email?: string | undefined;
	emailVerified?: string | undefined;
	name?: string | undefined;
	image?: string | undefined;
	extraFields?: Record<string, string> | undefined;
}

export interface OIDCConfig {
	issuer: string;
	pkce: boolean;
	clientId: string;
	clientSecret: string;
	authorizationEndpoint?: string | undefined;
	discoveryEndpoint: string;
	userInfoEndpoint?: string | undefined;
	scopes?: string[] | undefined;
	overrideUserInfo?: boolean | undefined;
	tokenEndpoint?: string | undefined;
	tokenEndpointAuthentication?:
		| ("client_secret_post" | "client_secret_basic")
		| undefined;
	jwksEndpoint?: string | undefined;
	mapping?: OIDCMapping | undefined;
}

type BaseSSOProvider = {
	issuer: string;
	oidcConfig?: OIDCConfig | undefined;
	userId: string;
	providerId: string;
	organizationId?: string | undefined;
	domain: string;
};

export type SSOProvider<O extends SSOOptions> =
	O["domainVerification"] extends { enabled: true }
		? {
				domainVerified: boolean;
			} & BaseSSOProvider
		: BaseSSOProvider;

export interface SSOOptions {
	/**
	 * custom function to provision a user when they sign in with an SSO provider.
	 */
	provisionUser?:
		| ((data: {
				/**
				 * The user object from the database
				 */
				user: User & Record<string, any>;
				/**
				 * The user info object from the provider
				 */
				userInfo: Record<string, any>;
				/**
				 * The OAuth2 tokens from the provider
				 */
				token?: OAuth2Tokens;
				/**
				 * The SSO provider
				 */
				provider: SSOProvider<SSOOptions>;
		  }) => Awaitable<void>)
		| undefined;
	/**
	 * Organization provisioning options
	 */
	organizationProvisioning?:
		| {
				disabled?: boolean;
				defaultRole?: "member" | "admin";
				getRole?: (data: {
					/**
					 * The user object from the database
					 */
					user: User & Record<string, any>;
					/**
					 * The user info object from the provider
					 */
					userInfo: Record<string, any>;
					/**
					 * The OAuth2 tokens from the provider
					 */
					token?: OAuth2Tokens;
					/**
					 * The SSO provider
					 */
					provider: SSOProvider<SSOOptions>;
				}) => Promise<"member" | "admin">;
		  }
		| undefined;
	/**
	 * Default SSO provider configurations for testing.
	 * These will take the precedence over the database providers.
	 */
	defaultSSO?:
		| Array<{
				/**
				 * The domain to match for this default provider.
				 * This is only used to match incoming requests to this default provider.
				 */
				domain: string;
				/**
				 * The provider ID to use
				 */
				providerId: string;
				/**
				 * OIDC configuration
				 */
				oidcConfig?: OIDCConfig;
		  }>
		| undefined;
	/**
	 * Override user info with the provider info.
	 * @default false
	 */
	defaultOverrideUserInfo?: boolean | undefined;
	/**
	 * Disable implicit sign up for new users. When set to true for the provider,
	 * sign-in need to be called with with requestSignUp as true to create new users.
	 */
	disableImplicitSignUp?: boolean | undefined;
	/**
	 * The model name for the SSO provider table. Defaults to "ssoProvider".
	 */
	modelName?: string;
	/**
	 * Map fields
	 */
	fields?: {
		issuer?: string | undefined;
		oidcConfig?: string | undefined;
		userId?: string | undefined;
		providerId?: string | undefined;
		organizationId?: string | undefined;
		domain?: string | undefined;
	};
	/**
	 * Configure the maximum number of SSO providers a user can register.
	 * You can also pass a function that returns a number.
	 * Set to 0 to disable SSO provider registration.
	 *
	 * @default 10
	 */
	providersLimit?: (number | ((user: User) => Awaitable<number>)) | undefined;
	/**
	 * Trust the email verified flag from the provider.
	 *
	 * @default false
	 *
	 * @deprecated This option is discouraged for new projects. Relying on provider-level `email_verified` is a weaker
	 * trust signal compared to using `trustedProviders` in `accountLinking` or enabling `domainVerification` for SSO.
	 */
	trustEmailVerified?: boolean | undefined;
	/**
	 * Enable domain verification on SSO providers
	 */
	domainVerification?: {
		/**
		 * Enables or disables the domain verification feature
		 */
		enabled?: boolean;
		/**
		 * Prefix used to generate the domain verification token.
		 * An underscore is automatically prepended to follow DNS
		 * infrastructure subdomain conventions (RFC 8552), so do
		 * not include a leading underscore.
		 *
		 * @default "better-auth-token"
		 */
		tokenPrefix?: string;
	};
}

export interface Member {
	id: string;
	userId: string;
	organizationId: string;
	role: string;
}
