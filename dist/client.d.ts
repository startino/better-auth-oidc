import { OIDCSSOPlugin } from "./index.js";

//#region src/client.d.ts
interface OIDCSSOClientOptions {
  domainVerification?: {
    enabled: boolean;
  } | undefined;
}
declare const oidcSsoClient: <CO extends OIDCSSOClientOptions>(options?: CO | undefined) => {
  id: "oidc-sso-client";
  $InferServerPlugin: OIDCSSOPlugin<{
    domainVerification: {
      enabled: CO["domainVerification"] extends {
        enabled: true;
      } ? true : false;
    };
  }>;
  pathMethods: {
    "/sso/providers": "GET";
    "/sso/get-provider": "GET";
  };
};
//#endregion
export { oidcSsoClient };
//# sourceMappingURL=client.d.ts.map