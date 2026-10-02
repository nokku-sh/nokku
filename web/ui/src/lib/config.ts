import { env } from '$env/dynamic/public';

export const DocsURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const UpgradeURL = env.PUBLIC_UPGRADE_URL || 'https://nokku.sh/pricing';

export const LicensePurchaseURL = env.PUBLIC_LICENSE_PURCHASE_URL || UpgradeURL;

// The list RPCs reject limits above 100.
export const MAX_PAGE_SIZE = 100;
