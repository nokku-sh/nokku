import { MAX_PAGE_SIZE } from '$lib/config';
import { WorkspaceService } from '$lib/gen/nokku/v1/workspace_pb';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { AuditLogFilterSchema, UtilService } from '$lib/gen/nokku/v1/util_pb';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { InvitationService } from '$lib/gen/nokku/v1/invitation_pb';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '$lib/query';
import { inviteToken, workspaceID } from '$lib/store.svelte';

export const workspace = {
	get: () =>
		useQuery(
			WorkspaceService.method.getWorkspace,
			() => ({ workspaceId: workspaceID.current }),
			() => ({
				enabled: !!workspaceID.current,
				select: (res) => {
					if (!res.workspace) workspaceID.current = '';
					return res.workspace;
				}
			})
		),
	list: () =>
		useQuery(
			WorkspaceService.method.listWorkspaces,
			{},
			{
				select: (res) => {
					if (!workspaceID.current && res.workspaces.length > 0) {
						workspaceID.current = res.workspaces[0].id;
					}
					if (!res.workspaces.length) workspaceID.current = '';
					return res.workspaces;
				}
			}
		),
	getMember: (userId: MaybeGetter<string | undefined>) =>
		useQuery(
			WorkspaceService.method.getWorkspaceMember,
			() => ({ workspaceId: workspaceID.current, userId: extract(userId) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(userId),
				select: (res) => res.member
			})
		),
	listMembers: (
		opts?: () => {
			query?: string;
			roleName?: string;
			teamIds?: string[];
			limit?: number;
			offset?: number;
		},
		when?: () => boolean
	) =>
		useQuery(
			WorkspaceService.method.listWorkspaceMembers,
			() => ({
				workspaceId: workspaceID.current,
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: !!workspaceID.current && (when?.() ?? true) })
		),

	create: () =>
		useMutation(WorkspaceService.method.createWorkspace, {
			onSuccess: (data) => {
				if (data.workspace) workspaceID.current = data.workspace.id;
				toast.success('Workspace created!');
			}
		}),
	update: () => useMutation(WorkspaceService.method.updateWorkspace),
	delete: () =>
		useMutation(WorkspaceService.method.deleteWorkspace, {
			onSuccess: (_, variables) => {
				if (variables.workspaceId === workspaceID.current) {
					workspaceID.current = '';
				}
				toast.success('Workspace deleted');
			}
		}),
	updateMember: () => useMutation(WorkspaceService.method.updateWorkspaceMember),
	removeMember: () =>
		useMutation(WorkspaceService.method.removeWorkspaceMember, {
			onSuccess: () => toast.success('Member removed')
		}),
	removeMembers: () =>
		useBulkMutation(
			WorkspaceService.method.removeWorkspaceMember,
			(n) => `${plural(n, 'member')} removed`
		),
	updateOwner: () =>
		useMutation(WorkspaceService.method.updateWorkspaceOwner, {
			onSuccess: () => toast.success('Owner updated')
		})
};

export const invite = {
	get: () =>
		useQuery(
			InvitationService.method.getInvitation,
			() => ({ token: inviteToken.current }),
			() => ({ enabled: !!inviteToken.current })
		),

	claim: () =>
		useMutation(InvitationService.method.acceptInvitation, {
			onSuccess: () => {
				inviteToken.current = '';
				return toast.success('Welcome!');
			},
			onError: () => {
				inviteToken.current = '';
				return toast.error('Failed to join workspace');
			}
		})
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
			enabled: !!workspaceID.current,
			select: (res) => res.version
		})),
	getLogs: (opts?: () => AuditQuery) =>
		useQuery(
			UtilService.method.listAuditLogs,
			() => {
				const { filter, limit, offset } = opts?.() ?? {};
				return {
					workspaceId: workspaceID.current,
					limit: limit ?? MAX_PAGE_SIZE,
					offset: offset ?? 0,
					filter: cleanFilters(filter) as AuditFilter
				};
			},
			() => ({ enabled: !!workspaceID.current })
		),

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

				toast.success('Audit logs exported successfully');
			},
			onError: (error) => {
				toast.error(`Export failed: ${error.message}`);
			}
		})
};
