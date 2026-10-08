import { MAX_PAGE_SIZE } from '#lib/config.js';
import { TargetService, type AccessGraphFilterSchema } from '#lib/gen/nokku/v1/target_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { toast } from 'svelte-sonner';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { plural, useBulkMutation } from './bulk';

export type AccessGraphFilter = MessageInitShape<typeof AccessGraphFilterSchema>;

export const target = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getTarget,
			() => ({ id: extract(id) }),
			() => ({ enabled: !!extract(id), select: (res) => res.target })
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
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: when?.() ?? true })
		),
	access: (subjectId: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getSubjectAccess,
			() => ({ subjectId: extract(subjectId) }),
			() => ({ enabled: !!extract(subjectId) })
		),
	filters: () => useQuery(TargetService.method.getTargetFilters, {}),
	// Without a filter this is the whole workspace.
	accessGraph: (filter?: () => AccessGraphFilter | undefined, when?: () => boolean) =>
		useQuery(
			TargetService.method.getAccessGraph,
			() => ({ filter: filter?.() }),
			() => ({ enabled: when?.() ?? true })
		),
	// Nothing loads until a tag is set. The empty tag is the untagged targets.
	accessGraphTargets: (opts: () => { tag?: string; filter?: AccessGraphFilter; limit: number }) =>
		useQuery(
			TargetService.method.listAccessGraphTargets,
			() => ({ ...opts() }),
			() => ({
				enabled: opts().tag !== undefined,
				// Keeps the rows in place while more of the same tag load.
				placeholderData: (prev, prevQuery) => {
					const input = prevQuery?.queryKey[1].input;
					return typeof input === 'object' && input.tag === opts().tag ? prev : undefined;
				}
			})
		),

	create: () =>
		useMutation(TargetService.method.createTarget, {
			onSuccess: () => toast.success('Target created')
		}),
	update: () => useMutation(TargetService.method.updateTarget),
	delete: () =>
		useMutation(TargetService.method.deleteTarget, {
			onSuccess: () => toast.success('Target deleted')
		}),
	deleteMany: () =>
		useBulkMutation(TargetService.method.deleteTarget, (n) => `${plural(n, 'target')} deleted`)
};
