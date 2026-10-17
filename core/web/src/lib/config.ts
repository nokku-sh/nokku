import {
	PUBLIC_DOCS_URL,
	PUBLIC_UPGRADE_URL,
	PUBLIC_LICENSE_PURCHASE_URL,
	PUBLIC_LICENSE_TRIAL_URL
} from '$app/env/public';

export const DocsURL = PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const UpgradeURL = PUBLIC_UPGRADE_URL || 'https://nokku.sh/pricing';
export const LicensePurchaseURL = PUBLIC_LICENSE_PURCHASE_URL || UpgradeURL;
export const LicenseTrialURL = PUBLIC_LICENSE_TRIAL_URL || `${UpgradeURL}#trial`;

// The list RPCs reject limits above 100.
export const MAX_PAGE_SIZE = 100;
