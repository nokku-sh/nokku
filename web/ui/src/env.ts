import { defineEnvVars } from '@sveltejs/kit/env';

// @migration-task Review usage of dynamic environment variables. They fall back to the empty string if not present, which may not be what you want.
export const variables = defineEnvVars({
	PUBLIC_DOCS_URL: { public: true, schema: (input) => input ?? '' },
	PUBLIC_UPGRADE_URL: { public: true, schema: (input) => input ?? '' },
	PUBLIC_LICENSE_PURCHASE_URL: { public: true, schema: (input) => input ?? '' }
});
