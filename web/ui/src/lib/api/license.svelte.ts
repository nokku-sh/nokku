import { BillingService } from '$lib/gen/nokku/v1/billing_pb';
import { useQuery } from '$lib/query';

export const license = {
	// No activation mutation, the license comes from NOKKU_LICENSE_KEY.
	get: () => useQuery(BillingService.method.getLicense)
};
