//#region src/client.ts
const oidcSsoClient = (options) => {
	return {
		id: "oidc-sso-client",
		$InferServerPlugin: {},
		pathMethods: {
			"/sso/providers": "GET",
			"/sso/get-provider": "GET"
		}
	};
};

//#endregion
export { oidcSsoClient };
//# sourceMappingURL=client.js.map