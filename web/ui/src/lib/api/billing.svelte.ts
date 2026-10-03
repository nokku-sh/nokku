import { BillingService } from '#lib/gen/nokku/v1/billing_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';
import { toast } from 'svelte-sonner';

export const billing = {
	get: () =>
		useQuery(
			BillingService.method.getBilling,
			() => ({ workspaceId: workspaceID.current }),
			() => ({ enabled: !!workspaceID.current })
		),

	checkout: () =>
		useMutation(BillingService.method.createCheckout, {
			onSuccess: (data) => (window.location.href = data.url)
		}),
	portal: () =>
		useMutation(BillingService.method.createPortal, {
			onSuccess: (data) => (window.location.href = data.url)
		}),
	cancelSubscription: () =>
		useMutation(BillingService.method.cancelSubscription, {
			onSuccess: () => toast.success('Subscription cancelled')
		})
};
