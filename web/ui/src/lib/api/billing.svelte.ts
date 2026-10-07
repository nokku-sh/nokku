import { BillingService } from '#lib/gen/nokku/v1/billing_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { toast } from 'svelte-sonner';

export const billing = {
	// Admins only, pass when for pages other roles can open.
	get: (when?: () => boolean) =>
		useQuery(BillingService.method.getBilling, {}, () => ({ enabled: when?.() ?? true })),

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
