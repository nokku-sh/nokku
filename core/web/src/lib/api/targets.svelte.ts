import { MAX_PAGE_SIZE } from '#lib/config.js';
import { authTransport, LIVE } from './client';
import {
	TargetService,
	type AccessGraphFilterSchema,
	type GetAccessMatrixRequestSchema,
	type ListTargetsRequestSchema
} from '#lib/gen/nokku/v1/target_pb.js';
import { createClient } from '@connectrpc/connect';
import { keepPreviousData } from '@tanstack/svelte-query';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { toast } from 'svelte-sonner';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { plural, useBulkMutation } from './bulk';
import { usePatch } from './mask';

export type AccessGraphFilter = MessageInitShape<typeof AccessGraphFilterSchema>;

// What a delete takes with it, for the dialogs that ask first.
export function deleteWarning(t: { name: string; daemonId: string }) {
	return t.daemonId
		? 'Everyone loses access to this server. Its login accounts, grants and daemon are removed.'
		: `Everyone loses access to this server. Its login accounts and grants are removed. Run nk rm ${t.name} first, it removes what Nokku wrote on the server.`;
}

const client = createClient(TargetService, authTransport);

// How many servers a person, team or service account reaches, for the delete dialogs. They still ask without it.
export const serverCount = (subjectId: string) =>
	client.getSubjectAccess({ subjectId }).then(
		(res) => res.targets.length,
		() => undefined
	);

export const target = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getTarget,
			() => ({ id: extract(id) }),
			() => ({ enabled: !!extract(id), select: (res) => res.target })
		),
	list: (
		opts?: () => MessageInitShape<typeof ListTargetsRequestSchema>,
		when?: () => boolean,
		live = false
	) =>
		useQuery(
			TargetService.method.listTargets,
			() => ({
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			// The servers page passes live, each one carries its daemon's online state.
			() => ({ enabled: when?.() ?? true, ...(live && { refetchInterval: LIVE }) })
		),
	access: (subjectId: MaybeGetter<string | undefined>) =>
		useQuery(
			TargetService.method.getSubjectAccess,
			() => ({ subjectId: extract(subjectId) }),
			() => ({ enabled: !!extract(subjectId) })
		),
	filters: (when?: () => boolean) =>
		useQuery(TargetService.method.getTargetFilters, {}, () => ({ enabled: when?.() ?? true })),
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

	// A page of the access matrix. The last page stays on screen while the next one loads.
	accessMatrix: (input: () => MessageInitShape<typeof GetAccessMatrixRequestSchema>) =>
		useQuery(TargetService.method.getAccessMatrix, input, () => ({
			placeholderData: keepPreviousData
		})),

	create: () =>
		useMutation(TargetService.method.createTarget, {
			onSuccess: () => toast.success('Server added')
		}),
	update: () => usePatch(TargetService.method.updateTarget),
	forgetHostKey: () =>
		useMutation(TargetService.method.forgetHostKey, {
			onSuccess: () => toast.success('Host key forgotten')
		}),
	delete: () =>
		useMutation(TargetService.method.deleteTarget, {
			onSuccess: () => toast.success('Server deleted')
		}),
	deleteMany: () =>
		useBulkMutation(TargetService.method.deleteTarget, (n) => `${plural(n, 'server')} deleted`)
};
