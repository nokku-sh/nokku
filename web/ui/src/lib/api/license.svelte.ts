import { BillingService, type GetLicenseResponse } from '#lib/gen/nokku/v1/billing_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { timestampDate, timestampFromDate } from '@bufbuild/protobuf/wkt';
import { toast } from 'svelte-sonner';

const DAY = 86_400_000;
// The reminder starts this long before expiry. Data limits hold this long
// after it, see holdDays in internal/entitlement.
const WARN_DAYS = 30;
const HOLD_DAYS = 30;

export type LicenseState = 'none' | 'active' | 'expiring' | 'expired';

export function licenseStatus(res: GetLicenseResponse | undefined) {
	const expires = res?.expiresAt ? timestampDate(res.expiresAt) : undefined;
	const daysLeft = expires ? Math.ceil((expires.getTime() - Date.now()) / DAY) : undefined;

	let state: LicenseState = 'none';
	if (res?.active) {
		state = daysLeft !== undefined && daysLeft <= WARN_DAYS ? 'expiring' : 'active';
	} else if (expires) {
		state = 'expired';
	}
	return {
		state,
		daysLeft,
		expiresAt: res?.expiresAt,
		// Until then nothing beyond the Community limits is deleted.
		keptUntil: expires && timestampFromDate(new Date(expires.getTime() + HOLD_DAYS * DAY))
	};
}

export const license = {
	get: () => useQuery(BillingService.method.getLicense),

	// Applies at once, the server needs no restart.
	activate: () =>
		useMutation(BillingService.method.activateLicense, {
			onSuccess: () => toast.success('License activated')
		})
};
