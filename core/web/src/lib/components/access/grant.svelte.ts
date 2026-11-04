import { MAX_PAGE_SIZE } from '#lib/config.js';
import {
	SubjectKind,
	type AddSubjectsRequestSchema,
	type RemoveSubjectsRequestSchema
} from '#lib/gen/nokku/v1/target_account_pb.js';
import { TargetService, type Target } from '#lib/gen/nokku/v1/target_pb.js';
import { useTransport } from '#lib/query/index.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { callUnaryMethod } from '@connectrpc/connect-query-core';
import { createQuery, keepPreviousData } from '@tanstack/svelte-query';
import { subjectIds, type Subject } from './subjects.svelte';

/** What the sheet starts with, from wherever it was opened. */
export type GrantPrefill = {
	subjects?: Subject[];
	servers?: Pick<Target, 'id' | 'name'>[];
	tags?: string[];
	account?: string;
	hours?: number;
	changeEnds?: boolean;
};

// The form lives here, so every open starts from what its caller passed.
class GrantSheetState {
	open = $state(false);
	subjects = $state<Subject[]>([]);
	servers = $state<Pick<Target, 'id' | 'name'>[]>([]);
	tags = $state<string[]>([]);
	account = $state('');
	/** How long the grant lasts, 0 is for good. */
	hours = $state(0);
	/** Send grants that stand again, so they take the new end. */
	changeEnds = $state(false);

	show(prefill: GrantPrefill = {}) {
		this.subjects = prefill.subjects ?? [];
		this.servers = prefill.servers?.map(({ id, name }) => ({ id, name })) ?? [];
		this.tags = prefill.tags ?? [];
		this.account = prefill.account ?? '';
		this.hours = prefill.hours ?? 0;
		this.changeEnds = prefill.changeEnds ?? false;
		this.open = true;
	}
}

// One sheet for the whole app, the layout mounts it.
export const grantSheet = new GrantSheetState();
export const openGrant = (prefill?: GrantPrefill) => grantSheet.show(prefill);

/** Each server is a call or two, past this the batch grant from the backlog is the way. */
export const MAX_SERVERS = 500;

/** The most subject ids AddSubjects takes at once. */
const MAX_IDS = 50;

type Where = { servers: Target[]; tooMany: boolean };

// useGrantWhere turns the picked servers and tags into servers with their accounts and grants.
export function useGrantWhere(where: () => { ids: string[]; tags: string[] }, when: () => boolean) {
	const transport = useTransport();

	return createQuery(() => {
		const ids = [...where().ids].sort();
		const tags = [...where().tags].sort();
		return {
			// Under connect-query, so the refetch after any change refreshes it too.
			queryKey: ['connect-query', 'grant-where', { ids, tags }],
			enabled: when() && ids.length + tags.length > 0,
			placeholderData: keepPreviousData,
			queryFn: async (): Promise<Where> => {
				const found = new Map<string, Target>();
				for (const tag of tags) {
					for (let offset = 0; ; offset += MAX_PAGE_SIZE) {
						const res = await callUnaryMethod(transport, TargetService.method.listTargets, {
							tags: [tag],
							limit: MAX_PAGE_SIZE,
							offset
						});
						for (const t of res.targets) found.set(t.id, t);
						if (found.size > MAX_SERVERS) return { servers: [], tooMany: true };
						if (!res.targets.length || offset + MAX_PAGE_SIZE >= res.total) break;
					}
				}
				const missing = ids.filter((id) => !found.has(id));
				for (let i = 0; i < missing.length; i += MAX_PAGE_SIZE) {
					const res = await callUnaryMethod(transport, TargetService.method.listTargets, {
						ids: missing.slice(i, i + MAX_PAGE_SIZE),
						limit: MAX_PAGE_SIZE
					});
					for (const t of res.targets) found.set(t.id, t);
				}
				if (found.size > MAX_SERVERS) return { servers: [], tooMany: true };
				return {
					servers: [...found.values()].sort((a, b) => a.name.localeCompare(b.name)),
					tooMany: false
				};
			}
		};
	});
}

/** The accounts on the servers, the most common first. */
export function accountsOf(servers: Target[]): { username: string; servers: number }[] {
	const counts = new Map<string, number>();
	for (const t of servers) {
		for (const a of t.accounts) counts.set(a.username, (counts.get(a.username) ?? 0) + 1);
	}
	return [...counts]
		.map(([username, n]) => ({ username, servers: n }))
		.sort((a, b) => b.servers - a.servers || a.username.localeCompare(b.username));
}

type GrantCall = Omit<MessageInitShape<typeof AddSubjectsRequestSchema>, '$typeName'>;

type GrantRow = {
	subject: Subject;
	/** New grants. */
	added: number;
	/** Grants that stand already with the same end. */
	same: number;
	/** Grants that stand with another end, they keep it unless the caller asks. */
	otherEnd: number;
};

type GrantPlan = {
	rows: GrantRow[];
	/** Servers without the account, nothing happens there. */
	skipped: Target[];
	/** Servers that have the account. */
	servers: number;
	calls: GrantCall[];
};

const sameEnd = (a?: Timestamp, b?: Timestamp) =>
	(a === undefined && b === undefined) ||
	(a !== undefined && b !== undefined && a.seconds === b.seconds);

/** AddSubjects sets the end exactly as sent, so a grant that stands only goes again to change its end. */
export function planGrant(
	subjects: Subject[],
	servers: Target[],
	account: string,
	expiresAt: Timestamp | undefined,
	changeEnds: boolean
): GrantPlan {
	const rows = subjects.map((subject) => ({ subject, added: 0, same: 0, otherEnd: 0 }));
	const skipped: Target[] = [];
	const calls: GrantCall[] = [];

	for (const server of servers) {
		const acc = server.accounts.find((a) => a.username === account);
		if (!acc) {
			skipped.push(server);
			continue;
		}
		const send = new Map<SubjectKind, string[]>();
		for (const row of rows) {
			const { id, kind } = row.subject;
			if (subjectIds(acc, kind).includes(id)) {
				if (sameEnd(acc.expiresAt[id], expiresAt)) {
					row.same++;
					continue;
				}
				row.otherEnd++;
				if (!changeEnds) continue;
			} else {
				row.added++;
			}
			send.set(kind, [...(send.get(kind) ?? []), id]);
		}
		for (const [kind, ids] of send) {
			for (let i = 0; i < ids.length; i += MAX_IDS) {
				calls.push({ id: acc.id, kind, subjectIds: ids.slice(i, i + MAX_IDS), expiresAt });
			}
		}
	}

	return { rows, skipped, servers: servers.length - skipped.length, calls };
}

type RevokeCall = Omit<MessageInitShape<typeof RemoveSubjectsRequestSchema>, '$typeName'>;

type RevokePlan = {
	/** Each account with the servers it goes from, the most first. */
	accounts: { username: string; servers: Target[] }[];
	servers: Target[];
	calls: RevokeCall[];
};

/** Only the subject's own grants. What a member gets through a team stays. */
export function planRevoke(subject: Subject, servers: Target[]): RevokePlan {
	const accounts = new Map<string, Target[]>();
	const hit: Target[] = [];
	const calls: RevokeCall[] = [];

	for (const server of servers) {
		const held = server.accounts.filter((a) => subjectIds(a, subject.kind).includes(subject.id));
		if (!held.length) continue;
		hit.push(server);
		for (const a of held) {
			accounts.set(a.username, [...(accounts.get(a.username) ?? []), server]);
			calls.push({ id: a.id, kind: subject.kind, subjectIds: [subject.id] });
		}
	}

	return {
		accounts: [...accounts]
			.map(([username, servers]) => ({ username, servers }))
			.sort((a, b) => b.servers.length - a.servers.length || a.username.localeCompare(b.username)),
		servers: hit,
		calls
	};
}

/** A name for a subject that says what it is, like team:ops. */
export function subjectLabel(s: Subject): string {
	switch (s.kind) {
		case SubjectKind.TEAM:
			return `team:${s.name}`;
		case SubjectKind.SERVICE_ACCOUNT:
			return `sa:${s.name}`;
		default:
			return s.name;
	}
}
