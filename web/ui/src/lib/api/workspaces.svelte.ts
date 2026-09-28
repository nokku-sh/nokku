import { WorkspaceService } from '$lib/gen/nokku/v1/workspace_pb';
import { toast } from 'svelte-sonner';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import { InvitationService } from '$lib/gen/nokku/v1/invitation_pb';
import { useMutation, useQuery } from '$lib/query';
import { inviteToken, pageIndex, pageSize, workspaceID } from '$lib/store.svelte';
import type { Timestamp } from '@bufbuild/protobuf/wkt';

export const workspace = {
	get: () =>
		useQuery(
			WorkspaceService.method.getWorkspace,
			{ workspaceId: workspaceID.current },
			{
				enabled: !!workspaceID.current,
				select: (res) => {
					if (!res.workspace) workspaceID.current = '';
					return res.workspace;
				}
			}
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
	listMembers: (
		opts?: () => {
			query?: string;
			roleName?: string;
			teamIds?: string[];
			limit?: number;
			offset?: number;
		}
	) =>
		useQuery(
			WorkspaceService.method.listWorkspaceMembers,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...opts?.()
			}),
			{ enabled: !!workspaceID.current }
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
	updateOwner: () =>
		useMutation(WorkspaceService.method.updateWorkspaceOwner, {
			onSuccess: () => toast.success('Owner updated')
		})
};

export const invite = {
	get: () =>
		useQuery(
			InvitationService.method.getInvitation,
			{ token: inviteToken.current },
			{ enabled: !!inviteToken.current }
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

export const util = {
	getVersion: () =>
		useQuery(UtilService.method.getVersion, undefined, {
			enabled: !!workspaceID.current,
			select: (res) => res.version
		}),
	getLogs: (opts?: {
		search?: string;
		actorIds?: string[];
		actorKinds?: string[];
		actions?: string[];
		status?: boolean;
		startDate?: Timestamp;
		endDate?: Timestamp;
		limit?: number;
		offset?: number;
	}) => {
		const cleanFilters = Object.fromEntries(
			Object.entries(opts ?? {}).filter(([, v]) => v !== undefined && v !== '' && v !== null)
		);

		return useQuery(
			UtilService.method.listAuditLogs,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...cleanFilters
			}),
			{ enabled: !!workspaceID.current }
		);
	},

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
