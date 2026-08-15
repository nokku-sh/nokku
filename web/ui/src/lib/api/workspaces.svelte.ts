import { WorkspaceService } from '$lib/gen/nokku/v1/workspace_pb';
import { toast } from 'svelte-sonner';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import { InvitationService } from '$lib/gen/nokku/v1/invitation_pb';
import { useMutation, useQuery } from '$lib/query';
import { inviteToken, pageIndex, pageSize, workspaceID } from '$lib/store.svelte';
import type { Timestamp } from '@bufbuild/protobuf/wkt';

export const workspace = {
	// Queries
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
	getMember: (userId?: string) =>
		useQuery(
			WorkspaceService.method.getWorkspaceMember,
			{ workspaceId: workspaceID.current, userId },
			{ enabled: !!workspaceID.current && !!userId, select: (res) => res.member }
		),
	listMembers: (
		opts?: () => {
			query?: string;
			roleName?: string;
			teamIds?: string[];
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

	// Mutations
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
	updateSettings: () => useMutation(WorkspaceService.method.updateWorkspaceSettings),
	setRecordingKey: () =>
		useMutation(WorkspaceService.method.setRecordingKey, {
			onSuccess: () => toast.success('Recording encryption enabled')
		}),
	clearRecordingKey: () =>
		useMutation(WorkspaceService.method.clearRecordingKey, {
			onSuccess: () => toast.success('Recording encryption disabled')
		}),
	updateOwner: () =>
		useMutation(WorkspaceService.method.updateWorkspaceOwner, {
			onSuccess: () => toast.success('Owner updated')
		})
};

export const invite = {
	// Queries
	get: () =>
		useQuery(
			InvitationService.method.getInvitation,
			{ token: inviteToken.current },
			{ enabled: !!inviteToken.current }
		),

	// Mutations
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
		}),
	refresh: () =>
		useMutation(InvitationService.method.refreshInviteToken, {
			onSuccess: () => toast.success('Invitation token refreshed!')
		}),
	revoke: () =>
		useMutation(InvitationService.method.revokeInviteToken, {
			onSuccess: () => {
				inviteToken.current = '';
				return toast.success('Invitation revoked!');
			}
		})
};

export const util = {
	// Queries
	getVersion: () =>
		useQuery(UtilService.method.getVersion, undefined, {
			enabled: !!workspaceID.current,
			select: (res) => res.version
		}),
	getLogs: (filters?: {
		search?: string;
		actorIds?: string[];
		actorTypes?: string[];
		actions?: string[];
		status?: boolean;
		startDate?: Timestamp;
		endDate?: Timestamp;
	}) => {
		// Filter out undefined/empty values
		const cleanFilters = Object.fromEntries(
			Object.entries(filters ?? {}).filter(([_, v]) => v !== undefined && v !== '' && v !== null)
		);

		return useQuery(
			UtilService.method.listAuditLogs,
			{
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...cleanFilters
			},
			{ enabled: !!workspaceID.current }
		);
	},

	// Mutations
	exportLogs: () =>
		useMutation(UtilService.method.exportAuditLogs, {
			onSuccess: (data) => {
				// Trigger browser download
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
