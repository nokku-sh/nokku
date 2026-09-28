import { env } from '$env/dynamic/public';

export const SupportEmail = env.PUBLIC_SUPPORT_EMAIL || 'mailto:support@mizuchi.dev';
export const DocsURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const UpgradeURL = env.PUBLIC_UPGRADE_URL || 'https://nokku.sh/pricing';
export const DaemonURL = `${DocsURL}/daemon`;
export const CLIURL = `${DocsURL}/cli`;
export const ToSURL = 'https://nokku.sh/legal/terms';
export const PrivacyURL = 'https://nokku.sh/legal/privacy';
export const ImprintURL = 'https://nokku.sh/legal/imprint';

export const LicensePurchaseURL =
	env.PUBLIC_LICENSE_PURCHASE_URL || 'https://buy.stripe.com/test_fZu00i4Zpc7DbLY27Dd7q01';

export const APP_NAME = 'Nokku';
export const DEFAULT_LANGUAGE = 'en';

// The list RPCs reject limits above 100.
export const MAX_PAGE_SIZE = 100;
