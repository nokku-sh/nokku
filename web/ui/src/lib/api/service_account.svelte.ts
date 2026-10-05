import { MAX_PAGE_SIZE } from '#lib/config.js';
import { ServiceAccountService } from '#lib/gen/nokku/v1/service_account_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useQuery, useMutation } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';

export const serviceAccount = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			ServiceAccountService.method.getServiceAccount,
			() => ({ workspaceId: workspaceID.current, id: extract(id) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(id),
				select: (res) => res.serviceAccount
			})
		),
	list: (
		opts?: () => { query?: string; roleName?: string; limit?: number; offset?: number },
		when?: () => boolean
	) =>
		useQuery(
			ServiceAccountService.method.listServiceAccounts,
			() => ({
				workspaceId: workspaceID.current,
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: !!workspaceID.current && (when?.() ?? true) })
		),

	create: () =>
		useMutation(ServiceAccountService.method.createServiceAccount, {
			onSuccess: () => toast.success('Service account created')
		}),
	update: () => useMutation(ServiceAccountService.method.updateServiceAccount),
	delete: () => useMutation(ServiceAccountService.method.deleteServiceAccount),
	deleteMany: () =>
		useBulkMutation(
			ServiceAccountService.method.deleteServiceAccount,
			(n) => `${plural(n, 'service account')} deleted`
		)
};
