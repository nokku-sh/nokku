import { TeamService } from '$lib/gen/nokku/v1/team_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';

export const team = {
	// Queries
	get: (id?: string) =>
		useQuery(
			TeamService.method.getTeam,
			{ id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.team }
		),
	list: (opts?: () => { limit?: number; offset?: number; query?: string }) =>
		useQuery(
			TeamService.method.listTeams,
			() => ({ workspaceId: workspaceID.current, ...opts?.() }),
			{ enabled: !!workspaceID.current }
		),

	// Mutations
	create: () =>
		useMutation(TeamService.method.createTeam, {
			onSuccess: () => toast.success('Team created!'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	update: () =>
		useMutation(TeamService.method.updateTeam, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	delete: () =>
		useMutation(TeamService.method.deleteTeam, {
			onSuccess: () => toast.success('Team deleted'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	removeMember: () =>
		useMutation(TeamService.method.removeTeamMember, {
			onSuccess: () => toast.success('Member removed'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	addMember: () =>
		useMutation(TeamService.method.addTeamMember, {
			onSuccess: () => toast.success('Member added'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		})
};
