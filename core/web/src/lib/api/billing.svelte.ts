import { BillingService } from '#lib/gen/nokku/v1/billing_pb.js';
import { useQuery } from '#lib/query/index.js';

export const billing = {
	// Admins only. Each fetch also picks up seats bought in the portal.
	get: () => useQuery(BillingService.method.getBilling, {})
};
