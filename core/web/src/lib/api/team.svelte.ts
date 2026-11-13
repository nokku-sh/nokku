import { MAX_PAGE_SIZE } from '#lib/config.js';
import { TeamService } from '#lib/gen/nokku/v1/team_pb.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { usePatch } from './mask';
import { serverCount } from './targets.svelte';

export async function teamDeleteWarning(id: string, members: number | undefined) {
	if (members === 0) return 'It has no members, so nobody loses access.';
	const servers = await serverCount(id);
	if (servers === 0) return 'It grants no access, so nobody loses any.';
	const who =
		members === undefined
			? 'Members lose'
			: `${plural(members, 'member')} ${members === 1 ? 'loses' : 'lose'}`;
	const what = servers
		? `what this team grants on ${plural(servers, 'server')}`
		: 'everything granted through this team';
	return `${who} ${what}. Access they hold themselves stays.`;
}

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
	update: () => usePatch(TeamService.method.updateTeam),
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
