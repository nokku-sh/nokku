import { serviceAccount } from '$lib/api/service_account.svelte';
import { team } from '$lib/api/team.svelte';
import { workspace } from '$lib/api/workspaces.svelte';
import { SubjectKind, type Principal } from '$lib/gen/nokku/v1/principal_pb';
import type { ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
import type { Team } from '$lib/gen/nokku/v1/team_pb';
import type { WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';

export type Subject = {
	id: string;
	kind: SubjectKind;
	name: string;
	detail: string;
	member?: WorkspaceMember;
};

/** A grant on a login account, resolved to a name lazily by SubjectChip. */
export type SubjectRef = { id: string; kind: SubjectKind; subject?: Subject };

export const kindLabels: Record<SubjectKind, { one: string; many: string }> = {
	[SubjectKind.UNSPECIFIED]: { one: 'subject', many: 'subjects' },
	[SubjectKind.USER]: { one: 'member', many: 'members' },
	[SubjectKind.TEAM]: { one: 'team', many: 'teams' },
	[SubjectKind.SERVICE_ACCOUNT]: { one: 'service account', many: 'service accounts' }
};

export const fromMember = (m: WorkspaceMember): Subject => ({
	id: m.id,
	kind: SubjectKind.USER,
	name: m.name || m.email,
	detail: m.email,
	member: m
});

export const fromTeam = (t: Team): Subject => ({
	id: t.id,
	kind: SubjectKind.TEAM,
	name: t.name,
	detail: `${t.memberCount} ${t.memberCount === 1 ? 'member' : 'members'}`
});

export const fromServiceAccount = (s: ServiceAccount): Subject => ({
	id: s.id,
	kind: SubjectKind.SERVICE_ACCOUNT,
	name: s.name,
	detail: s.description || 'Service account'
});

export function subjectHref(kind: SubjectKind, id: string) {
	switch (kind) {
		case SubjectKind.USER:
			return `/access/members?id=${id}`;
		case SubjectKind.TEAM:
			return `/access/teams?id=${id}`;
		case SubjectKind.SERVICE_ACCOUNT:
			return `/access/service-accounts?id=${id}`;
		default:
			return undefined;
	}
}

export function subjectIds(p: Principal, kind: SubjectKind): string[] {
	switch (kind) {
		case SubjectKind.USER:
			return p.userIds;
		case SubjectKind.TEAM:
			return p.teamIds;
		case SubjectKind.SERVICE_ACCOUNT:
			return p.serviceAccountIds;
		default:
			return [];
	}
}

export function grantsOf(p: Principal): SubjectRef[] {
	return [
		...p.userIds.map((id) => ({ id, kind: SubjectKind.USER })),
		...p.teamIds.map((id) => ({ id, kind: SubjectKind.TEAM })),
		...p.serviceAccountIds.map((id) => ({ id, kind: SubjectKind.SERVICE_ACCOUNT }))
	];
}

const SEARCH_LIMIT = 20;

// useSubjectSearch asks the server for matches, so it scales to any workspace
// size. Nothing loads until `when` is true, e.g. while a picker is open.
export function useSubjectSearch(query: () => string, when: () => boolean) {
	const opts = () => ({ query: query() || undefined, limit: SEARCH_LIMIT });
	const members = workspace.listMembers(opts, when);
	const teams = team.list(opts, when);
	const serviceAccounts = serviceAccount.list(opts, when);

	return {
		get groups() {
			return [
				{ heading: 'Members', items: (members.data?.members ?? []).map(fromMember) },
				{ heading: 'Teams', items: (teams.data?.teams ?? []).map(fromTeam) },
				{
					heading: 'Service accounts',
					items: (serviceAccounts.data?.serviceAccounts ?? []).map(fromServiceAccount)
				}
			];
		},
		get loading() {
			return members.isLoading || teams.isLoading || serviceAccounts.isLoading;
		}
	};
}
