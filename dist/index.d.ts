import { C as updateSSOProvider, D as SSOOptions, E as OIDCConfig, O as SSOProvider, S as listSSOProviders, T as verifyDomain, _ as callbackSSO, a as normalizeDiscoveryUrls, b as deleteSSOProvider, c as validateDiscoveryDocument, d as DiscoveryError, f as DiscoveryErrorCode, g as RequiredDiscoveryField, h as REQUIRED_DISCOVERY_FIELDS, i as needsRuntimeDiscovery, l as validateDiscoveryUrl, m as OIDCDiscoveryDocument, n as discoverOIDCConfig, o as normalizeUrl, p as HydratedOIDCConfig, r as fetchDiscoveryDocument, s as selectTokenEndpointAuthMethod, t as computeDiscoveryUrl, u as DiscoverOIDCConfigParams, v as registerSSOProvider, w as requestDomainVerification, x as getSSOProvider, y as signInSSO } from "./discovery.js";
import { BetterAuthPlugin } from "better-auth";

//#region src/index.d.ts

type DomainVerificationEndpoints = {
  requestDomainVerification: ReturnType<typeof requestDomainVerification>;
  verifyDomain: ReturnType<typeof verifyDomain>;
};
type OIDCSSOEndpoints<O extends SSOOptions> = {
  registerSSOProvider: ReturnType<typeof registerSSOProvider<O>>;
  signInSSO: ReturnType<typeof signInSSO>;
  callbackSSO: ReturnType<typeof callbackSSO>;
  listSSOProviders: ReturnType<typeof listSSOProviders>;
  getSSOProvider: ReturnType<typeof getSSOProvider>;
  updateSSOProvider: ReturnType<typeof updateSSOProvider>;
  deleteSSOProvider: ReturnType<typeof deleteSSOProvider>;
};
type OIDCSSOPlugin<O extends SSOOptions> = {
  id: "oidc-sso";
  endpoints: OIDCSSOEndpoints<O> & (O extends {
    domainVerification: {
      enabled: true;
    };
  } ? DomainVerificationEndpoints : {});
};
declare function oidcSso<O extends SSOOptions & {
  domainVerification?: {
    enabled: true;
  };
}>(options?: O | undefined): {
  id: "oidc-sso";
  endpoints: OIDCSSOEndpoints<O> & DomainVerificationEndpoints;
  schema: NonNullable<BetterAuthPlugin["schema"]>;
  options: O;
};
declare function oidcSso<O extends SSOOptions>(options?: O | undefined): {
  id: "oidc-sso";
  endpoints: OIDCSSOEndpoints<O>;
};
//# sourceMappingURL=index.d.ts.map

//#endregion
export { type DiscoverOIDCConfigParams, DiscoveryError, type DiscoveryErrorCode, type HydratedOIDCConfig, type OIDCConfig, type OIDCDiscoveryDocument, OIDCSSOPlugin, REQUIRED_DISCOVERY_FIELDS, type RequiredDiscoveryField, type SSOOptions, type SSOProvider, computeDiscoveryUrl, discoverOIDCConfig, fetchDiscoveryDocument, needsRuntimeDiscovery, normalizeDiscoveryUrls, normalizeUrl, oidcSso, selectTokenEndpointAuthMethod, validateDiscoveryDocument, validateDiscoveryUrl };
//# sourceMappingURL=index.d.ts.map