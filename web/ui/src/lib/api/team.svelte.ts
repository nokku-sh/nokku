import { MAX_PAGE_SIZE } from '#lib/config.js';
import { TeamService } from '#lib/gen/nokku/v1/team_pb.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';

export const team = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			TeamService.method.getTeam,
			() => ({ workspaceId: workspaceID.current, id: extract(id) }),
			() => ({ enabled: !!workspaceID.current && !!extract(id), select: (res) => res.team })
		),
	list: (opts?: () => { query?: string; limit?: number; offset?: number }, when?: () => boolean) =>
		useQuery(
			TeamService.method.listTeams,
			() => ({
				workspaceId: workspaceID.current,
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: !!workspaceID.current && (when?.() ?? true) })
		),
	// Pass enabled to defer the fetch, e.g. until a hover card opens.
	members: (teamId: MaybeGetter<string | undefined>, opts?: () => { enabled?: boolean }) =>
		useQuery(
			TeamService.method.listTeamMembers,
			() => ({ workspaceId: workspaceID.current, teamId: extract(teamId) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(teamId) && (opts?.().enabled ?? true),
				select: (res) => res.members
			})
		),
	listForUser: (userId: MaybeGetter<string | undefined>) =>
		useQuery(
			TeamService.method.listTeamsForUser,
			() => ({ workspaceId: workspaceID.current, userId: extract(userId) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(userId),
				select: (res) => res.teams
			})
		),

	create: () =>
		useMutation(TeamService.method.createTeam, {
			onSuccess: () => toast.success('Team created')
		}),
	update: () => useMutation(TeamService.method.updateTeam),
	delete: () =>
		useMutation(TeamService.method.deleteTeam, {
			onSuccess: () => toast.success('Team deleted')
		}),
	deleteMany: () =>
		useBulkMutation(TeamService.method.deleteTeam, (n) => `${plural(n, 'team')} deleted`),
	removeMember: () =>
		useMutation(TeamService.method.removeTeamMember, {
			onSuccess: () => toast.success('Member removed')
		}),
	addMember: () =>
		useMutation(TeamService.method.addTeamMember, {
			onSuccess: () => toast.success('Member added')
		})
};
