import { TeamService } from '$lib/gen/nokku/v1/team_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { pageIndex, pageSize, workspaceID } from '$lib/store.svelte';

export const team = {
	get: (id?: string) =>
		useQuery(
			TeamService.method.getTeam,
			{ workspaceId: workspaceID.current, id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.team }
		),
	list: (opts?: () => { query?: string }) =>
		useQuery(
			TeamService.method.listTeams,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...opts?.()
			}),
			{ enabled: !!workspaceID.current }
		),
	// Pass enabled to defer the fetch, e.g. until a hover card opens.
	members: (teamId: string, opts?: () => { enabled?: boolean }) =>
		useQuery(
			TeamService.method.listTeamMembers,
			() => ({ workspaceId: workspaceID.current, teamId }),
			{
				enabled: !!workspaceID.current && !!teamId,
				select: (res) => res.members,
				...opts?.()
			}
		),
	listForUser: (userId?: string) =>
		useQuery(
			TeamService.method.listTeamsForUser,
			() => ({ workspaceId: workspaceID.current, userId }),
			{
				enabled: !!workspaceID.current && !!userId,
				select: (res) => res.teams
			}
		),

	create: () =>
		useMutation(TeamService.method.createTeam, {
			onSuccess: () => toast.success('Team created!')
		}),
	update: () => useMutation(TeamService.method.updateTeam),
	delete: () =>
		useMutation(TeamService.method.deleteTeam, {
			onSuccess: () => toast.success('Team deleted')
		}),
	removeMember: () =>
		useMutation(TeamService.method.removeTeamMember, {
			onSuccess: () => toast.success('Member removed')
		}),
	addMember: () =>
		useMutation(TeamService.method.addTeamMember, {
			onSuccess: () => toast.success('Member added')
		})
};
