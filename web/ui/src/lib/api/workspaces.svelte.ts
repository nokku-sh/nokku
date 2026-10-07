import { MAX_PAGE_SIZE } from '#lib/config.js';
import { WorkspaceService } from '#lib/gen/nokku/v1/workspace_pb.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { AuditLogFilterSchema, UtilService } from '#lib/gen/nokku/v1/util_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { InvitationService } from '#lib/gen/nokku/v1/invitation_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';

// The host picks the workspace, so none of these name one.
export const workspace = {
	get: () => useQuery(WorkspaceService.method.getWorkspace, {}, { select: (res) => res.workspace }),

	update: () => useMutation(WorkspaceService.method.updateWorkspace),
	delete: () =>
		useMutation(WorkspaceService.method.deleteWorkspace, {
			onSuccess: () => {
				toast.success('Workspace deleted');
				window.location.assign('/login');
			}
		}),
	// Public, only on the root host of a hosted Nokku.
	create: () => useMutation(WorkspaceService.method.createWorkspace)
};

export const users = {
	get: (userId: MaybeGetter<string | undefined>) =>
		useQuery(
			WorkspaceService.method.getUser,
			() => ({ userId: extract(userId) }),
			() => ({ enabled: !!extract(userId), select: (res) => res.user })
		),
	list: (
		opts?: () => {
			query?: string;
			role?: string;
			limit?: number;
			offset?: number;
		},
		when?: () => boolean
	) =>
		useQuery(
			WorkspaceService.method.listUsers,
			() => ({ limit: MAX_PAGE_SIZE, offset: 0, ...opts?.() }),
			() => ({ enabled: when?.() ?? true })
		),

	updateRole: () => useMutation(WorkspaceService.method.updateUserRole),
	setActive: () =>
		useMutation(WorkspaceService.method.setUserActive, {
			onSuccess: (_, v) => toast.success(v.active ? 'Account reactivated' : 'Account deactivated')
		}),
	delete: () =>
		useMutation(WorkspaceService.method.deleteUser, {
			onSuccess: () => toast.success('Account deleted')
		}),
	deleteMany: () =>
		useBulkMutation(WorkspaceService.method.deleteUser, (n) => `${plural(n, 'account')} deleted`),
	transferOwnership: () =>
		useMutation(WorkspaceService.method.transferOwnership, {
			onSuccess: () => toast.success('Ownership transferred')
		})
};

export const invite = {
	get: (token: MaybeGetter<string>) =>
		useQuery(
			InvitationService.method.getInvitation,
			() => ({ token: extract(token) }),
			() => ({ enabled: !!extract(token), retry: false })
		),
	// Always succeeds from the outside, the link lands in the inbox or not.
	accept: () => useMutation(InvitationService.method.acceptInvitation)
};

export type AuditFilter = MessageInitShape<typeof AuditLogFilterSchema>;
export type AuditQuery = { filter?: AuditFilter; limit?: number; offset?: number };

// Empty filters are dropped so they don't split the query cache.
export const cleanFilters = <T extends object>(filters?: T): Partial<T> =>
	Object.fromEntries(
		Object.entries(filters ?? {}).filter(
			([, v]) => v !== undefined && v !== '' && v !== null && !(Array.isArray(v) && !v.length)
		)
	) as Partial<T>;

export const util = {
	getVersion: () =>
		useQuery(UtilService.method.getVersion, undefined, () => ({
			select: (res) => res.version
		})),
	// Who runs this server. Empty fields mean not configured, typical for self-hosting.
	instanceInfo: () =>
		useQuery(UtilService.method.getInstanceInfo, undefined, () => ({ staleTime: Infinity })),
	getLogs: (opts?: () => AuditQuery) =>
		useQuery(UtilService.method.listAuditLogs, () => {
			const { filter, limit, offset } = opts?.() ?? {};
			return {
				limit: limit ?? MAX_PAGE_SIZE,
				offset: offset ?? 0,
				filter: cleanFilters(filter) as AuditFilter
			};
		}),

	exportLogs: () =>
		useMutation(UtilService.method.exportAuditLogs, {
			onSuccess: (data) => {
				const blob = new Blob([data.data.slice()], {
					type: data.contentType || 'application/octet-stream'
				});
				const url = URL.createObjectURL(blob);
				const link = document.createElement('a');
				link.href = url;
				link.download = data.filename || 'audit_logs.csv';
				document.body.appendChild(link);
				link.click();
				document.body.removeChild(link);
				URL.revokeObjectURL(url);

				toast.success('Audit logs exported');
			},
			onError: (error) => {
				toast.error(`Export failed: ${error.message}`);
			}
		})
};
