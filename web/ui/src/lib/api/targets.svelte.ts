import { MAX_PAGE_SIZE } from '$lib/config';
import { TargetService } from '$lib/gen/nokku/v1/target_pb';
import { toast } from 'svelte-sonner';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '$lib/query';
import { plural, useBulkMutation } from './bulk';
import { workspaceID } from '$lib/store.svelte';

export const target = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getTarget,
			() => ({ workspaceId: workspaceID.current, id: extract(id) }),
			() => ({ enabled: !!workspaceID.current && !!extract(id), select: (res) => res.target })
		),
	list: (
		opts?: () => {
			query?: string;
			daemonId?: string;
			caId?: string;
			tags?: string[];
			principals?: string[];
			limit?: number;
			offset?: number;
		},
		when?: () => boolean
	) =>
		useQuery(
			TargetService.method.listTargets,
			() => ({
				workspaceId: workspaceID.current,
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({
				enabled: !!workspaceID.current && (when?.() ?? true),
				refetchInterval: 15000
			})
		),
	access: (subjectId: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getSubjectAccess,
			() => ({ workspaceId: workspaceID.current, subjectId: extract(subjectId) }),
			() => ({ enabled: !!workspaceID.current && !!extract(subjectId) })
		),
	filters: () =>
		useQuery(
			TargetService.method.getTargetFilters,
			() => ({ workspaceId: workspaceID.current }),
			() => ({ enabled: !!workspaceID.current })
		),

	create: () =>
		useMutation(TargetService.method.createTarget, {
			onSuccess: () => toast.success('Target created!')
		}),
	update: () => useMutation(TargetService.method.updateTarget),
	delete: () =>
		useMutation(TargetService.method.deleteTarget, {
			onSuccess: () => toast.success('Target deleted')
		}),
	deleteMany: () =>
		useBulkMutation(TargetService.method.deleteTarget, (n) => `${plural(n, 'target')} deleted`)
};
