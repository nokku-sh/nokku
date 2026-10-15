import { MAX_PAGE_SIZE } from '#lib/config.js';
import { TeamService } from '#lib/gen/nokku/v1/team_pb.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';

export const team = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			TeamService.method.getTeam,
			() => ({ id: extract(id) }),
			() => ({ enabled: !!extract(id), select: (res) => res.team })
		),
	list: (opts?: () => { query?: string; limit?: number; offset?: number }, when?: () => boolean) =>
		useQuery(
			TeamService.method.listTeams,
			() => ({
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: when?.() ?? true })
		),
	members: (teamId: MaybeGetter<string | undefined>) =>
		useQuery(
			TeamService.method.listTeamMembers,
			() => ({ teamId: extract(teamId) }),
			() => ({
				enabled: !!extract(teamId),
				select: (res) => res.members
			})
		),
	listForUser: (userId: MaybeGetter<string | undefined>) =>
		useQuery(
			TeamService.method.listTeamsForUser,
			() => ({ userId: extract(userId) }),
			() => ({
				enabled: !!extract(userId),
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
	// No toasts, the sheet footer reports membership changes.
	removeMember: () => useMutation(TeamService.method.removeTeamMember),
	addMember: () => useMutation(TeamService.method.addTeamMember)
};
