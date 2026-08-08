import { TargetService } from '$lib/gen/nokku/v1/target_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { pageIndex, pageSize, workspaceID } from '$lib/store.svelte';

export const target = {
	// Queries
	get: (id?: string) =>
		useQuery(
			TargetService.method.getTarget,
			{ workspaceId: workspaceID.current, id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.target }
		),
	list: (
		opts?: () => {
			query?: string;
			daemonId?: string;
			caId?: string;
			tags?: string[];
			principals?: string[];
		}
	) =>
		useQuery(
			TargetService.method.listTargets,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...opts?.()
			}),
			{
				enabled: !!workspaceID.current,
				refetchInterval: 15000
			}
		),
	access: (subjectId?: string) =>
		useQuery(
			TargetService.method.getSubjectAccess,
			{ workspaceId: workspaceID.current, subjectId },
			{ enabled: !!workspaceID.current && !!subjectId }
		),
	filters: () =>
		useQuery(TargetService.method.getTargetFilters, () => ({ workspaceId: workspaceID.current }), {
			enabled: !!workspaceID.current
		}),

	// Mutations
	create: () =>
		useMutation(TargetService.method.createTarget, {
			onSuccess: () => toast.success('Target created!')
		}),
	update: () => useMutation(TargetService.method.updateTarget),
	delete: () =>
		useMutation(TargetService.method.deleteTarget, {
			onSuccess: () => toast.success('Target deleted')
		})
};
