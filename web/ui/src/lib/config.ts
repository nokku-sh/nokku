import { env } from '$env/dynamic/public';

export const DocsURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const UpgradeURL = env.PUBLIC_UPGRADE_URL || 'https://nokku.sh/pricing';

export const LicensePurchaseURL =
	env.PUBLIC_LICENSE_PURCHASE_URL || 'https://buy.stripe.com/test_fZu00i4Zpc7DbLY27Dd7q01';

// The list RPCs reject limits above 100.
export const MAX_PAGE_SIZE = 100;
