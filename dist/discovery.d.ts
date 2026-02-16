import * as z$1 from "zod/v4";
import z from "zod/v4";
import * as better_auth9 from "better-auth";
import { Awaitable, OAuth2Tokens, User } from "better-auth";
import * as better_call6 from "better-call";

//#region src/types.d.ts
interface OIDCMapping {
  id?: string | undefined;
  email?: string | undefined;
  emailVerified?: string | undefined;
  name?: string | undefined;
  image?: string | undefined;
  extraFields?: Record<string, string> | undefined;
}
interface OIDCConfig {
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
  tokenEndpointAuthentication?: ("client_secret_post" | "client_secret_basic") | undefined;
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
type SSOProvider<O extends SSOOptions> = O["domainVerification"] extends {
  enabled: true;
} ? {
  domainVerified: boolean;
} & BaseSSOProvider : BaseSSOProvider;
interface SSOOptions {
  /**
   * custom function to provision a user when they sign in with an SSO provider.
   */
  provisionUser?: ((data: {
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
  }) => Awaitable<void>) | undefined;
  /**
   * Organization provisioning options
   */
  organizationProvisioning?: {
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
  } | undefined;
  /**
   * Default SSO provider configurations for testing.
   * These will take the precedence over the database providers.
   */
  defaultSSO?: Array<{
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
  }> | undefined;
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
//#endregion
//#region src/routes/domain-verification.d.ts
declare const requestDomainVerification: (options: SSOOptions) => better_call6.StrictEndpoint<"/sso/request-domain-verification", {
  method: "POST";
  body: z$1.ZodObject<{
    providerId: z$1.ZodString;
  }, z$1.core.$strip>;
  metadata: {
    openapi: {
      summary: string;
      description: string;
      responses: {
        "404": {
          description: string;
        };
        "409": {
          description: string;
        };
        "201": {
          description: string;
        };
      };
    };
  };
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
}, {
  domainVerificationToken: string;
}>;
declare const verifyDomain: (options: SSOOptions) => better_call6.StrictEndpoint<"/sso/verify-domain", {
  method: "POST";
  body: z$1.ZodObject<{
    providerId: z$1.ZodString;
  }, z$1.core.$strip>;
  metadata: {
    openapi: {
      summary: string;
      description: string;
      responses: {
        "404": {
          description: string;
        };
        "409": {
          description: string;
        };
        "502": {
          description: string;
        };
        "204": {
          description: string;
        };
      };
    };
  };
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
}, void>;
//# sourceMappingURL=domain-verification.d.ts.map
//#endregion
//#region src/routes/providers.d.ts
declare const listSSOProviders: () => better_call6.StrictEndpoint<"/sso/providers", {
  method: "GET";
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
      };
    };
  };
}, {
  providers: {
    providerId: string;
    type: "oidc";
    issuer: string;
    domain: string;
    organizationId: string | null;
    domainVerified: boolean;
    oidcConfig: {
      discoveryEndpoint: string;
      clientIdLastFour: string;
      pkce: boolean;
      authorizationEndpoint: string | undefined;
      tokenEndpoint: string | undefined;
      userInfoEndpoint: string | undefined;
      jwksEndpoint: string | undefined;
      scopes: string[] | undefined;
      tokenEndpointAuthentication: "client_secret_post" | "client_secret_basic" | undefined;
    } | undefined;
  }[];
}>;
declare const getSSOProvider: () => better_call6.StrictEndpoint<"/sso/get-provider", {
  method: "GET";
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
  query: z.ZodObject<{
    providerId: z.ZodString;
  }, z.core.$strip>;
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
        "404": {
          description: string;
        };
        "403": {
          description: string;
        };
      };
    };
  };
}, {
  providerId: string;
  type: "oidc";
  issuer: string;
  domain: string;
  organizationId: string | null;
  domainVerified: boolean;
  oidcConfig: {
    discoveryEndpoint: string;
    clientIdLastFour: string;
    pkce: boolean;
    authorizationEndpoint: string | undefined;
    tokenEndpoint: string | undefined;
    userInfoEndpoint: string | undefined;
    jwksEndpoint: string | undefined;
    scopes: string[] | undefined;
    tokenEndpointAuthentication: "client_secret_post" | "client_secret_basic" | undefined;
  } | undefined;
}>;
declare const updateSSOProvider: (options: SSOOptions) => better_call6.StrictEndpoint<"/sso/update-provider", {
  method: "POST";
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
  body: z.ZodObject<{
    issuer: z.ZodOptional<z.ZodString>;
    domain: z.ZodOptional<z.ZodString>;
    oidcConfig: z.ZodOptional<z.ZodObject<{
      clientId: z.ZodOptional<z.ZodString>;
      clientSecret: z.ZodOptional<z.ZodString>;
      authorizationEndpoint: z.ZodOptional<z.ZodString>;
      tokenEndpoint: z.ZodOptional<z.ZodString>;
      userInfoEndpoint: z.ZodOptional<z.ZodString>;
      tokenEndpointAuthentication: z.ZodOptional<z.ZodEnum<{
        client_secret_post: "client_secret_post";
        client_secret_basic: "client_secret_basic";
      }>>;
      jwksEndpoint: z.ZodOptional<z.ZodString>;
      discoveryEndpoint: z.ZodOptional<z.ZodString>;
      scopes: z.ZodOptional<z.ZodArray<z.ZodString>>;
      pkce: z.ZodOptional<z.ZodBoolean>;
      overrideUserInfo: z.ZodOptional<z.ZodBoolean>;
      mapping: z.ZodOptional<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        email: z.ZodOptional<z.ZodString>;
        emailVerified: z.ZodOptional<z.ZodString>;
        name: z.ZodOptional<z.ZodString>;
        image: z.ZodOptional<z.ZodString>;
        extraFields: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
      }, z.core.$strip>>;
    }, z.core.$strip>>;
    providerId: z.ZodString;
  }, z.core.$strip>;
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
        "404": {
          description: string;
        };
        "403": {
          description: string;
        };
      };
    };
  };
}, {
  providerId: string;
  type: "oidc";
  issuer: string;
  domain: string;
  organizationId: string | null;
  domainVerified: boolean;
  oidcConfig: {
    discoveryEndpoint: string;
    clientIdLastFour: string;
    pkce: boolean;
    authorizationEndpoint: string | undefined;
    tokenEndpoint: string | undefined;
    userInfoEndpoint: string | undefined;
    jwksEndpoint: string | undefined;
    scopes: string[] | undefined;
    tokenEndpointAuthentication: "client_secret_post" | "client_secret_basic" | undefined;
  } | undefined;
}>;
declare const deleteSSOProvider: () => better_call6.StrictEndpoint<"/sso/delete-provider", {
  method: "POST";
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
  body: z.ZodObject<{
    providerId: z.ZodString;
  }, z.core.$strip>;
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
        "404": {
          description: string;
        };
        "403": {
          description: string;
        };
      };
    };
  };
}, {
  success: boolean;
}>;
//# sourceMappingURL=providers.d.ts.map
//#endregion
//#region src/routes/sso.d.ts
declare const registerSSOProvider: <O extends SSOOptions>(options: O) => better_call6.StrictEndpoint<"/sso/register", {
  method: "POST";
  body: z.ZodObject<{
    providerId: z.ZodString;
    issuer: z.ZodString;
    domain: z.ZodString;
    oidcConfig: z.ZodObject<{
      clientId: z.ZodString;
      clientSecret: z.ZodString;
      authorizationEndpoint: z.ZodOptional<z.ZodString>;
      tokenEndpoint: z.ZodOptional<z.ZodString>;
      userInfoEndpoint: z.ZodOptional<z.ZodString>;
      tokenEndpointAuthentication: z.ZodOptional<z.ZodEnum<{
        client_secret_post: "client_secret_post";
        client_secret_basic: "client_secret_basic";
      }>>;
      jwksEndpoint: z.ZodOptional<z.ZodString>;
      discoveryEndpoint: z.ZodOptional<z.ZodString>;
      skipDiscovery: z.ZodOptional<z.ZodBoolean>;
      scopes: z.ZodOptional<z.ZodArray<z.ZodString>>;
      pkce: z.ZodOptional<z.ZodDefault<z.ZodBoolean>>;
      mapping: z.ZodOptional<z.ZodObject<{
        id: z.ZodString;
        email: z.ZodString;
        emailVerified: z.ZodOptional<z.ZodString>;
        name: z.ZodString;
        image: z.ZodOptional<z.ZodString>;
        extraFields: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
      }, z.core.$strip>>;
    }, z.core.$strip>;
    organizationId: z.ZodOptional<z.ZodString>;
    overrideUserInfo: z.ZodOptional<z.ZodDefault<z.ZodBoolean>>;
  }, z.core.$strip>;
  use: ((inputContext: better_auth9.MiddlewareInputContext<better_auth9.MiddlewareOptions>) => Promise<{
    session: {
      session: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        userId: string;
        expiresAt: Date;
        token: string;
        ipAddress?: string | null | undefined;
        userAgent?: string | null | undefined;
      };
      user: Record<string, any> & {
        id: string;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        emailVerified: boolean;
        name: string;
        image?: string | null | undefined;
      };
    };
  }>)[];
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
      };
    };
  };
}, O["domainVerification"] extends {
  enabled: true;
} ? {
  redirectURI: string;
  oidcConfig: OIDCConfig | null;
} & Omit<SSOProvider<O>, "oidcConfig"> & {
  domainVerified: boolean;
  domainVerificationToken: string;
} : {
  redirectURI: string;
  oidcConfig: OIDCConfig | null;
} & Omit<SSOProvider<O>, "oidcConfig">>;
declare const signInSSO: (options?: SSOOptions) => better_call6.StrictEndpoint<"/sign-in/sso", {
  method: "POST";
  body: z.ZodObject<{
    email: z.ZodOptional<z.ZodString>;
    organizationSlug: z.ZodOptional<z.ZodString>;
    providerId: z.ZodOptional<z.ZodString>;
    domain: z.ZodOptional<z.ZodString>;
    callbackURL: z.ZodString;
    errorCallbackURL: z.ZodOptional<z.ZodString>;
    newUserCallbackURL: z.ZodOptional<z.ZodString>;
    scopes: z.ZodOptional<z.ZodArray<z.ZodString>>;
    loginHint: z.ZodOptional<z.ZodString>;
    requestSignUp: z.ZodOptional<z.ZodBoolean>;
  }, z.core.$strip>;
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "200": {
          description: string;
        };
      };
    };
  };
}, {
  url: string;
  redirect: boolean;
}>;
declare const callbackSSO: (options?: SSOOptions) => better_call6.StrictEndpoint<"/sso/callback/:providerId", {
  method: "GET";
  query: z.ZodObject<{
    code: z.ZodOptional<z.ZodString>;
    state: z.ZodString;
    error: z.ZodOptional<z.ZodString>;
    error_description: z.ZodOptional<z.ZodString>;
  }, z.core.$strip>;
  allowedMediaTypes: string[];
  metadata: {
    openapi: {
      operationId: string;
      summary: string;
      description: string;
      responses: {
        "302": {
          description: string;
        };
      };
    };
    scope: "server";
  };
}, never>;
//# sourceMappingURL=sso.d.ts.map
//#endregion
//#region src/oidc/types.d.ts
/**
 * OIDC Discovery Types
 *
 * Types for the OIDC discovery document and hydrated configuration.
 * Based on OpenID Connect Discovery 1.0 specification.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
/**
 * Raw OIDC Discovery Document as returned by the IdP's
 * .well-known/openid-configuration endpoint.
 *
 * Required fields for Better Auth's OIDC support:
 * - issuer
 * - authorization_endpoint
 * - token_endpoint
 * - jwks_uri (required for ID token validation)
 *
 */
interface OIDCDiscoveryDocument {
  /** REQUIRED. URL using the https scheme that the OP asserts as its Issuer Identifier. */
  issuer: string;
  /** REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint. */
  authorization_endpoint: string;
  /**
   * REQUIRED (spec says "unless only implicit flow is used").
   * URL of the OP's OAuth 2.0 Token Endpoint.
   * We only support authorization code flow.
   */
  token_endpoint: string;
  /** REQUIRED. URL of the OP's JSON Web Key Set document for ID token validation. */
  jwks_uri: string;
  /** RECOMMENDED. URL of the OP's UserInfo Endpoint. */
  userinfo_endpoint?: string;
  /**
   * OPTIONAL. JSON array containing a list of Client Authentication methods
   * supported by this Token Endpoint.
   * Default: ["client_secret_basic"]
   */
  token_endpoint_auth_methods_supported?: string[];
  /** OPTIONAL. JSON array containing a list of the OAuth 2.0 scope values that this server supports. */
  scopes_supported?: string[];
  /** OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. */
  response_types_supported?: string[];
  /** OPTIONAL. JSON array containing a list of the Subject Identifier types that this OP supports. */
  subject_types_supported?: string[];
  /** OPTIONAL. JSON array containing a list of the JWS signing algorithms supported by the OP. */
  id_token_signing_alg_values_supported?: string[];
  /** OPTIONAL. JSON array containing a list of the claim names that the OP may supply values for. */
  claims_supported?: string[];
  /** OPTIONAL. URL of a page containing human-readable information about the OP. */
  service_documentation?: string;
  /** OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter. */
  claims_parameter_supported?: boolean;
  /** OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter. */
  request_parameter_supported?: boolean;
  /** OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter. */
  request_uri_parameter_supported?: boolean;
  /** OPTIONAL. Boolean value specifying whether the OP requires any request_uri values to be pre-registered. */
  require_request_uri_registration?: boolean;
  /** OPTIONAL. URL of the OP's end session endpoint. */
  end_session_endpoint?: string;
  /** OPTIONAL. URL of the OP's revocation endpoint. */
  revocation_endpoint?: string;
  /** OPTIONAL. URL of the OP's introspection endpoint. */
  introspection_endpoint?: string;
  /** OPTIONAL. JSON array of PKCE code challenge methods supported (e.g., "S256", "plain"). */
  code_challenge_methods_supported?: string[];
  /** Allow additional fields from the discovery document */
  [key: string]: unknown;
}
/**
 * Error codes for OIDC discovery operations.
 */
type DiscoveryErrorCode = /** Request to discovery endpoint timed out */
"discovery_timeout"
/** Discovery endpoint returned 404 or similar */ | "discovery_not_found"
/** Discovery endpoint returned invalid JSON */ | "discovery_invalid_json"
/** Discovery URL is invalid or malformed */ | "discovery_invalid_url"
/** Discovery URL is not trusted by the trusted origins configuration */ | "discovery_untrusted_origin"
/** Discovery document issuer doesn't match configured issuer */ | "issuer_mismatch"
/** Discovery document is missing required fields */ | "discovery_incomplete"
/** IdP only advertises token auth methods that Better Auth doesn't currently support */ | "unsupported_token_auth_method"
/** Catch-all for unexpected errors */ | "discovery_unexpected_error";
/**
 * Custom error class for OIDC discovery failures.
 * Can be caught and mapped to APIError at the edge.
 */
declare class DiscoveryError extends Error {
  readonly code: DiscoveryErrorCode;
  readonly details?: Record<string, unknown>;
  constructor(code: DiscoveryErrorCode, message: string, details?: Record<string, unknown>, options?: {
    cause?: unknown;
  });
}
/**
 * Hydrated OIDC configuration after discovery.
 * This is the normalized shape that gets persisted to the database
 * or merged into provider config at runtime.
 *
 * Field names are camelCase to match Better Auth conventions.
 */
interface HydratedOIDCConfig {
  /** The issuer URL (validated to match configured issuer) */
  issuer: string;
  /** The discovery endpoint URL */
  discoveryEndpoint: string;
  /** URL of the authorization endpoint */
  authorizationEndpoint: string;
  /** URL of the token endpoint */
  tokenEndpoint: string;
  /** URL of the JWKS endpoint */
  jwksEndpoint: string;
  /** URL of the userinfo endpoint (optional) */
  userInfoEndpoint?: string;
  /** Token endpoint authentication method */
  tokenEndpointAuthentication?: "client_secret_basic" | "client_secret_post";
  /** Scopes supported by the IdP */
  scopesSupported?: string[];
}
/**
 * Parameters for the discoverOIDCConfig function.
 */
interface DiscoverOIDCConfigParams {
  /** The issuer URL to discover configuration from */
  issuer: string;
  /**
   * Optional existing configuration.
   * Values provided here will override discovered values.
   */
  existingConfig?: Partial<HydratedOIDCConfig>;
  /**
   * Optional custom discovery endpoint URL.
   * If not provided, defaults to <issuer>/.well-known/openid-configuration
   */
  discoveryEndpoint?: string;
  /**
   * Optional timeout in milliseconds for the discovery request.
   * @default 10000 (10 seconds)
   */
  timeout?: number;
  /**
   * Trusted origin predicate. See "trustedOrigins" option
   * @param url the url to test
   * @returns {boolean} return true for urls that belong to a trusted origin and false otherwise
   */
  isTrustedOrigin: (url: string) => boolean;
}
/**
 * Required fields that must be present in a valid discovery document.
 */
declare const REQUIRED_DISCOVERY_FIELDS: readonly ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"];
type RequiredDiscoveryField = (typeof REQUIRED_DISCOVERY_FIELDS)[number];
//# sourceMappingURL=types.d.ts.map
//#endregion
//#region src/oidc/discovery.d.ts
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
declare function discoverOIDCConfig(params: DiscoverOIDCConfigParams): Promise<HydratedOIDCConfig>;
/**
 * Compute the discovery URL from an issuer URL.
 *
 * Per OIDC Discovery spec, the discovery document is located at:
 * <issuer>/.well-known/openid-configuration
 *
 * Handles trailing slashes correctly.
 */
declare function computeDiscoveryUrl(issuer: string): string;
/**
 * Validate a discovery URL before fetching.
 *
 * @param url - The discovery URL to validate
 * @param isTrustedOrigin - Origin verification tester function
 * @throws DiscoveryError if URL is invalid
 */
declare function validateDiscoveryUrl(url: string, isTrustedOrigin: DiscoverOIDCConfigParams["isTrustedOrigin"]): void;
/**
 * Fetch the OIDC discovery document from the IdP.
 *
 * @param url - The discovery endpoint URL
 * @param timeout - Request timeout in milliseconds
 * @returns The parsed discovery document
 * @throws DiscoveryError on network errors, timeouts, or invalid responses
 */
declare function fetchDiscoveryDocument(url: string, timeout?: number): Promise<OIDCDiscoveryDocument>;
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
declare function validateDiscoveryDocument(doc: OIDCDiscoveryDocument, configuredIssuer: string): void;
/**
 * Normalize URLs in the discovery document.
 *
 * @param document - The discovery document
 * @param issuer - The base issuer URL
 * @param isTrustedOrigin - Origin verification tester function
 * @returns The normalized discovery document
 */
declare function normalizeDiscoveryUrls(document: OIDCDiscoveryDocument, issuer: string, isTrustedOrigin: DiscoverOIDCConfigParams["isTrustedOrigin"]): OIDCDiscoveryDocument;
/**
 * Normalize a single URL endpoint.
 *
 * @param name - The endpoint name (e.g token_endpoint)
 * @param endpoint - The endpoint URL to normalize
 * @param issuer - The base issuer URL
 * @returns The normalized endpoint URL
 */
declare function normalizeUrl(name: string, endpoint: string, issuer: string): string;
/**
 * Select the token endpoint authentication method.
 *
 * @param doc - The discovery document
 * @param existing - Existing authentication method from config
 * @returns The selected authentication method
 */
declare function selectTokenEndpointAuthMethod(doc: OIDCDiscoveryDocument, existing?: "client_secret_basic" | "client_secret_post"): "client_secret_basic" | "client_secret_post";
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
declare function needsRuntimeDiscovery(config: Partial<HydratedOIDCConfig> | undefined): boolean;
//# sourceMappingURL=discovery.d.ts.map

//#endregion
export { updateSSOProvider as C, SSOOptions as D, OIDCConfig as E, SSOProvider as O, listSSOProviders as S, verifyDomain as T, callbackSSO as _, normalizeDiscoveryUrls as a, deleteSSOProvider as b, validateDiscoveryDocument as c, DiscoveryError as d, DiscoveryErrorCode as f, RequiredDiscoveryField as g, REQUIRED_DISCOVERY_FIELDS as h, needsRuntimeDiscovery as i, validateDiscoveryUrl as l, OIDCDiscoveryDocument as m, discoverOIDCConfig as n, normalizeUrl as o, HydratedOIDCConfig as p, fetchDiscoveryDocument as r, selectTokenEndpointAuthMethod as s, computeDiscoveryUrl as t, DiscoverOIDCConfigParams as u, registerSSOProvider as v, requestDomainVerification as w, getSSOProvider as x, signInSSO as y };
//# sourceMappingURL=discovery.d.ts.map