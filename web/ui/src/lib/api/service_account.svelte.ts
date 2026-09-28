import { ServiceAccountService } from '$lib/gen/nokku/v1/service_account_pb';
import { useQuery, useMutation } from '$lib/query';
import { pageIndex, pageSize, workspaceID } from '$lib/store.svelte';
import { toast } from 'svelte-sonner';

export const serviceAccount = {
	get: (id?: string) =>
		useQuery(
			ServiceAccountService.method.getServiceAccount,
			{ workspaceId: workspaceID.current, id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.serviceAccount }
		),
	list: (opts?: () => { query?: string }) =>
		useQuery(
			ServiceAccountService.method.listServiceAccounts,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...opts?.()
			}),
			{ enabled: !!workspaceID.current }
		),

	create: () =>
		useMutation(ServiceAccountService.method.createServiceAccount, {
			onSuccess: () => toast.success('Service account created!')
		}),
	update: () => useMutation(ServiceAccountService.method.updateServiceAccount),
	delete: () => useMutation(ServiceAccountService.method.deleteServiceAccount)
};
