import { defineConfig } from "tsdown";

export default defineConfig({
	dts: { build: true },
	clean: true,
	format: ["esm"],
	entry: {
		index: "./src/index.ts",
		client: "./src/client.ts",
	},
	external: ["better-auth", "better-call", "@better-fetch/fetch"],
	sourcemap: true,
	hash: false,
});
