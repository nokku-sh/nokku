import { ServiceAccountService } from '$lib/gen/nokku/v1/service_account_pb';
import { useQuery, useMutation } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';
import { toast } from 'svelte-sonner';

export const serviceAccount = {
	// Queries
	get: (id?: string) =>
		useQuery(
			ServiceAccountService.method.getServiceAccount,
			{ id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.serviceAccount }
		),
	list: (opts?: () => { limit?: number; offset?: number; query?: string }) =>
		useQuery(
			ServiceAccountService.method.listServiceAccounts,
			() => ({ workspaceId: workspaceID.current, ...opts?.() }),
			{ enabled: !!workspaceID.current }
		),

	// Mutations
	create: () =>
		useMutation(ServiceAccountService.method.createServiceAccount, {
			onSuccess: () => toast.success('Service account created!'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	update: () =>
		useMutation(ServiceAccountService.method.updateServiceAccount, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	delete: () =>
		useMutation(ServiceAccountService.method.deleteServiceAccount, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		})
};
