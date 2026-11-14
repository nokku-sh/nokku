import { BillingService } from '#lib/gen/nokku/v1/billing_pb.js';
import { useQuery } from '#lib/query/index.js';

export const billing = {
	// Admins only.
	get: () => useQuery(BillingService.method.getBilling, {}),
	// Slower, each fetch asks the license server for seats bought in the portal.
	getFresh: () => useQuery(BillingService.method.getBilling, { refresh: true })
};
