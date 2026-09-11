import { env } from '$env/dynamic/public';

export const SupportEmail = env.PUBLIC_SUPPORT_EMAIL || 'mailto:support@mizuchi.dev';
export const DocsURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const UpgradeURL = env.PUBLIC_UPGRADE_URL || 'https://nokku.sh/pricing';
export const DaemonURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs/daemon';
export const CLIURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs/cli';
export const ToSURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/legal/terms';
export const PrivacyURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/legal/privacy';
export const ImprintURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/legal/imprint';

// Stripe Payment Link for the Enterprise license (Managed Payments).
export const LicensePurchaseURL =
	env.PUBLIC_LICENSE_PURCHASE_URL || 'https://buy.stripe.com/test_fZu00i4Zpc7DbLY27Dd7q01';
// export const LicensePurchaseURL =
// 	env.PUBLIC_LICENSE_PURCHASE_URL || 'https://buy.stripe.com/test_aFadR8fE38Vr03g9A5d7q00';

export const APP_NAME = 'Nokku';
export const DEFAULT_LANGUAGE = 'en';

// The list RPCs validate limit as 1..100, so a larger value is rejected with a
// validation error. Use this for "fetch everything" queries.
export const MAX_PAGE_SIZE = 100;
