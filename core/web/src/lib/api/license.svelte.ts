import { BillingService, type GetLicenseResponse } from '#lib/gen/nokku/v1/billing_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import { toast } from 'svelte-sonner';

const DAY = 86_400_000;
// The reminder starts this long before expiry, data limits hold this long after. See holdDays in internal/entitlement.
const WARN_DAYS = 30;
export const HOLD_DAYS = 30;

type LicenseState = 'none' | 'active' | 'expiring' | 'expired';

/** Whole days until ts, rounded up, so a mail and the app name the same count. */
export function daysUntil(ts: Timestamp): number {
	return Math.ceil((timestampDate(ts).getTime() - Date.now()) / DAY);
}

export function licenseStatus(res: GetLicenseResponse | undefined) {
	const daysLeft = res?.expiresAt ? daysUntil(res.expiresAt) : undefined;

	let state: LicenseState = 'none';
	if (res?.active) {
		state = daysLeft !== undefined && daysLeft <= WARN_DAYS ? 'expiring' : 'active';
	} else if (res?.expiresAt) {
		state = 'expired';
	}
	return {
		state,
		daysLeft,
		expiresAt: res?.expiresAt
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
