import { defineEnvVars } from '@sveltejs/kit/env';

// Unset variables are empty strings. config.ts supplies the defaults.
export const variables = defineEnvVars({
	PUBLIC_DOCS_URL: { public: true, schema: (input) => input ?? '' },
	PUBLIC_UPGRADE_URL: { public: true, schema: (input) => input ?? '' },
	PUBLIC_LICENSE_PURCHASE_URL: { public: true, schema: (input) => input ?? '' }
});
