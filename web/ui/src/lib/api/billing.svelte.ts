import { BillingService } from '$lib/gen/nokku/v1/billing_pb';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';
import { toast } from 'svelte-sonner';

export const billing = {
	// Queries
	get: () => useQuery(BillingService.method.getBilling, { workspaceId: workspaceID.current }),

	// Mutations
	checkout: () =>
		useMutation(BillingService.method.createCheckout, {
			onSuccess: (data) => (window.location.href = data.url),
			transform: (variables) => ({ workspaceId: workspaceID.current, ...variables })
		}),
	portal: () =>
		useMutation(BillingService.method.createCustomerPortal, {
			onSuccess: (data) => (window.location.href = data.url),
			transform: (variables) => ({ workspaceId: workspaceID.current, ...variables })
		}),
	cancelSubscription: () =>
		useMutation(BillingService.method.cancelSubscription, {
			onSuccess: () => toast.success('Subscription cancelled'),
			transform: (variables) => ({ workspaceId: workspaceID.current, ...variables })
		})
};
