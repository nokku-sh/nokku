import type { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
import { MAX_PAGE_SIZE } from '#lib/config.js';
import { ServiceAccountService } from '#lib/gen/nokku/v1/service_account_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useQuery, useMutation } from '#lib/query/index.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';

export const serviceAccount = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			ServiceAccountService.method.getServiceAccount,
			() => ({ id: extract(id) }),
			() => ({
				enabled: !!extract(id),
				select: (res) => res.serviceAccount
			})
		),
	list: (
		opts?: () => { query?: string; role?: WorkspaceRole; limit?: number; offset?: number },
		when?: () => boolean
	) =>
		useQuery(
			ServiceAccountService.method.listServiceAccounts,
			() => ({
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: when?.() ?? true })
		),

	create: () =>
		useMutation(ServiceAccountService.method.createServiceAccount, {
			onSuccess: () => toast.success('Service account created')
		}),
	update: () => useMutation(ServiceAccountService.method.updateServiceAccount),
	delete: () => useMutation(ServiceAccountService.method.deleteServiceAccount),
	rotate: () => useMutation(ServiceAccountService.method.rotateServiceAccountToken),
	deleteMany: () =>
		useBulkMutation(
			ServiceAccountService.method.deleteServiceAccount,
			(n) => `${plural(n, 'service account')} deleted`
		)
};
