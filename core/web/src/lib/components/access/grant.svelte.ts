import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
import type { Subject } from './subjects.svelte';

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
