import type { AccessGraphFilter } from '#lib/api/targets.svelte.js';
import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
import type {
	AccessGraphSubject,
	AccessGraphTarget,
	GetAccessGraphResponse
} from '#lib/gen/nokku/v1/target_pb.js';
import type { User } from '#lib/gen/nokku/v1/account_pb.js';
import type { Edge, Node } from '@xyflow/svelte';

export type FocusKind = 'user' | 'team' | 'service-account' | 'target' | 'account' | 'tag';
/** The id is a UUID, or the username or tag itself. */
export type Focus = { kind: FocusKind; id: string };

const focusKinds: FocusKind[] = ['user', 'team', 'service-account', 'target', 'account', 'tag'];

export const subjectFocus: Record<SubjectKind, FocusKind> = {
	[SubjectKind.UNSPECIFIED]: 'user',
	[SubjectKind.USER]: 'user',
	[SubjectKind.TEAM]: 'team',
	[SubjectKind.SERVICE_ACCOUNT]: 'service-account'
};

export function parseFocus(param: string | null): Focus | undefined {
	if (param === null) return undefined;
	const at = param.indexOf(':');
	const kind = param.slice(0, at) as FocusKind;
	return at > 0 && focusKinds.includes(kind) ? { kind, id: param.slice(at + 1) } : undefined;
}

export function filterOf(focus: Focus): AccessGraphFilter {
	switch (focus.kind) {
		case 'target':
			return { targetId: focus.id };
		case 'account':
			return { username: focus.id };
		case 'tag':
			return { tag: focus.id };
		default:
			return { subjectId: focus.id };
	}
}

export const tagLabel = (tag: string) => tag || 'Untagged';

export type Section = 'teams' | 'people' | 'bots' | 'accounts' | 'tags' | 'members' | 'targets';

/** Rows a section shows before the rest folds into a "more" row. */
export const PAGE: Record<Section, number> = {
	teams: 8,
	people: 6,
	bots: 4,
	accounts: 10,
	tags: 12,
	members: 8,
	targets: 10
};

/** The list RPC's page limit. Past it, search is the way to a target. */
export const MAX_TARGETS = 100;

type Lane = 'who' | 'as' | 'where';

export type RowData = {
	kind: FocusKind | 'more';
	lane: Lane;
	label: string;
	detail?: string;
	count?: string;
	tone: 'normal' | 'lit' | 'dim';
	selected?: boolean;
	child?: boolean;
	/** Set on rows that open, e.g. a team onto its members. */
	expanded?: boolean;
	onselect: () => void;
	ontoggle?: () => void;
};

/** A heading names its lane and what the numbers under it count. */
export type LabelData = { text: string; heading?: boolean };

export type View = {
	overview: GetAccessGraphResponse;
	/** The graph narrowed to the focus. Unset without one and while it loads. */
	focused?: GetAccessGraphResponse;
	focus?: Focus;
	shown: Record<Section, number>;
	openTeam?: string;
	members?: User[];
	openTag?: string;
	targets?: AccessGraphTarget[];
	targetTotal?: number;
};

export type Actions = {
	focus: (focus: Focus) => void;
	toggleTeam: (id: string) => void;
	toggleTag: (tag: string) => void;
	more: (section: Section) => void;
};

/** Targets behind one drawn edge, overall and for the focus. */
export type Link = { source: string; target: string; base: number; lit: number };

const LANES: Record<Lane, { x: number; width: number }> = {
	who: { x: 0, width: 280 },
	as: { x: 400, width: 200 },
	where: { x: 720, width: 280 }
};
export const GRAPH_WIDTH = 1000;

const ROW = 40;
const CHILD = 32;
const LABEL = 20;
const GAP = 6;
const INDENT = 20;

const fixed = { draggable: false, selectable: false, connectable: false };

// Lanes are plain sorted lists, so every position is arithmetic. Whatever does
// not fit a section folds into its "more" row, which carries the edges of the
// rows it hides, so the overview never drops access silently.
export function buildGraph(view: View, actions: Actions): { nodes: Node[]; links: Link[] } {
	const { overview, focused, focus } = view;
	const nodes: Node[] = [];
	// The node a subject, account or tag is drawn in: its own or a "more" row.
	const home = new Map<string, string>();

	const lit = new Set<string>();
	const reached = new Map<string, number>();
	if (focused) {
		for (const s of focused.subjects) {
			reached.set(`s:${s.id}`, s.targets);
			if (s.targets > 0) lit.add(`s:${s.id}`);
		}
		for (const a of focused.accounts) {
			reached.set(`a:${a.username}`, a.targets);
			lit.add(`a:${a.username}`);
		}
		for (const t of focused.tags) {
			reached.set(`t:${t.tag}`, t.targets);
			if (t.targets > 0) lit.add(`t:${t.tag}`);
		}
	}
	const focusKey =
		focus &&
		(focus.kind === 'account'
			? `a:${focus.id}`
			: focus.kind === 'tag'
				? `t:${focus.id}`
				: `s:${focus.id}`);
	const pinned = new Set([
		focusKey,
		view.openTeam && `s:${view.openTeam}`,
		view.openTag === undefined ? undefined : `t:${view.openTag}`
	]);
	const tone = (key: string) => (!focused ? 'normal' : lit.has(key) ? 'lit' : 'dim');
	// "12/340" on a lit row. One target only ever reaches 1, so it keeps the total.
	const ratio = (key: string, of: number) => {
		const n = reached.get(key);
		return !n || n === of || focus?.kind === 'target' ? String(of) : `${n}/${of}`;
	};

	function lane(name: Lane) {
		const { x, width } = LANES[name];
		let y = 0;
		const label = (id: string, data: LabelData, child = false) => {
			const dx = child ? INDENT : 0;
			nodes.push({
				id,
				type: 'label',
				position: { x: x + dx, y },
				width: width - dx,
				height: LABEL,
				data,
				...fixed
			});
			y += LABEL + GAP;
		};
		const row = (id: string, data: Omit<RowData, 'lane'>) => {
			const dx = data.child ? INDENT : 0;
			const height = data.child ? CHILD : ROW;
			nodes.push({
				id,
				type: 'row',
				position: { x: x + dx, y },
				width: width - dx,
				height,
				data: { ...data, lane: name },
				...fixed
			});
			y += height + GAP;
		};
		// Splits one section into the rows that show and a "more" row for the
		// rest. The focused row and the open ones always show.
		const fold = <T>(section: Section, all: T[], key: (item: T) => string) => {
			const visible = all.slice(0, view.shown[section]);
			const rest = all.slice(view.shown[section]);
			const hidden = rest.filter((item) => !pinned.has(key(item)));
			visible.push(...rest.filter((item) => pinned.has(key(item))));
			for (const item of visible) home.set(key(item), key(item));
			for (const item of hidden) home.set(key(item), `more:${section}`);
			const more = () => {
				if (hidden.length === 0) return;
				row(`more:${section}`, {
					kind: 'more',
					label: `${hidden.length} more`,
					tone: !focused ? 'normal' : hidden.some((i) => lit.has(key(i))) ? 'lit' : 'dim',
					onselect: () => actions.more(section)
				});
			};
			return { visible, more };
		};
		return { label, row, fold, space: () => (y += GAP * 2) };
	}

	const who = lane('who');
	who.label('head:who', { text: 'Who', heading: true });
	const sections: [Section, SubjectKind, string][] = [
		['teams', SubjectKind.TEAM, 'Teams'],
		['people', SubjectKind.USER, 'People'],
		['bots', SubjectKind.SERVICE_ACCOUNT, 'Service accounts']
	];
	for (const [section, kind, title] of sections) {
		const all = overview.subjects
			.filter((s) => s.kind === kind)
			.sort((a, b) => b.targets - a.targets || a.name.localeCompare(b.name));
		if (all.length === 0) continue;

		who.label(`label:${section}`, { text: `${title} · ${all.length}` });
		const { visible, more } = who.fold(section, all, (s) => `s:${s.id}`);
		for (const s of visible) {
			const key = `s:${s.id}`;
			const isTeam = kind === SubjectKind.TEAM;
			who.row(key, {
				kind: subjectFocus[kind],
				label: s.name || s.email,
				detail: subjectDetail(s),
				count: ratio(key, s.targets),
				tone: tone(key),
				selected: key === focusKey,
				expanded: isTeam ? view.openTeam === s.id : undefined,
				onselect: () => actions.focus({ kind: subjectFocus[kind], id: s.id }),
				ontoggle: isTeam ? () => actions.toggleTeam(s.id) : undefined
			});
			if (!isTeam || view.openTeam !== s.id) continue;

			if (!view.members) {
				who.label(`m:${s.id}:loading`, { text: 'Loading' }, true);
				continue;
			}
			if (view.members.length === 0) who.label(`m:${s.id}:empty`, { text: 'No members' }, true);
			// Members inherit the team's access, so they light up with it, unless
			// the focus is one person.
			for (const m of view.members.slice(0, view.shown.members)) {
				const isFocus = focus?.kind === 'user' && focus.id === m.id;
				who.row(`m:${s.id}:${m.id}`, {
					kind: 'user',
					label: m.name || m.email,
					detail: m.name ? m.email : undefined,
					tone: focus?.kind === 'user' && focused ? (isFocus ? 'lit' : 'dim') : tone(key),
					selected: isFocus,
					child: true,
					onselect: () => actions.focus({ kind: 'user', id: m.id })
				});
			}
			if (view.members.length > view.shown.members) {
				who.row('more:members', {
					kind: 'more',
					label: `${view.members.length - view.shown.members} more`,
					tone: 'normal',
					child: true,
					onselect: () => actions.more('members')
				});
			}
		}
		more();
		who.space();
	}

	const as = lane('as');
	as.label('head:as', { text: 'Logs in as', heading: true });
	const accounts = [...overview.accounts].sort(
		(a, b) => b.targets - a.targets || a.username.localeCompare(b.username)
	);
	as.label('label:accounts', { text: `Accounts · ${accounts.length}` });
	const accountRows = as.fold('accounts', accounts, (a) => `a:${a.username}`);
	for (const a of accountRows.visible) {
		const key = `a:${a.username}`;
		as.row(key, {
			kind: 'account',
			label: a.username,
			count: ratio(key, a.targets),
			tone: tone(key),
			selected: key === focusKey,
			onselect: () => actions.focus({ kind: 'account', id: a.username })
		});
	}
	accountRows.more();

	const where = lane('where');
	where.label('head:where', { text: 'Where', heading: true });
	// Untagged sorts last, it is the leftover bucket.
	const tags = [...overview.tags].sort(
		(a, b) =>
			Number(a.tag === '') - Number(b.tag === '') || b.total - a.total || a.tag.localeCompare(b.tag)
	);
	where.label('label:tags', { text: `Tags · ${tags.filter((t) => t.tag !== '').length}` });
	const tagRows = where.fold('tags', tags, (t) => `t:${t.tag}`);
	for (const t of tagRows.visible) {
		const key = `t:${t.tag}`;
		const granted = focused ? (reached.get(key) ?? 0) : t.targets;
		where.row(key, {
			kind: 'tag',
			label: tagLabel(t.tag),
			count: granted === t.total ? String(t.total) : `${granted}/${t.total}`,
			tone: tone(key),
			selected: key === focusKey,
			expanded: view.openTag === t.tag,
			onselect: () => actions.focus({ kind: 'tag', id: t.tag }),
			ontoggle: () => actions.toggleTag(t.tag)
		});
		if (view.openTag !== t.tag) continue;

		if (!view.targets) {
			where.label(`x:${t.tag}:loading`, { text: 'Loading' }, true);
			continue;
		}
		for (const target of view.targets) {
			where.row(`x:${t.tag}:${target.id}`, {
				kind: 'target',
				label: target.name,
				detail: !focus && !target.matched ? 'no access' : undefined,
				tone: !target.matched ? 'dim' : focus ? 'lit' : 'normal',
				selected: focus?.kind === 'target' && focus.id === target.id,
				child: true,
				onselect: () => actions.focus({ kind: 'target', id: target.id })
			});
		}
		const rest = (view.targetTotal ?? 0) - view.targets.length;
		if (rest > 0 && view.shown.targets < MAX_TARGETS) {
			where.row('more:targets', {
				kind: 'more',
				label: `${rest} more`,
				tone: 'normal',
				child: true,
				onselect: () => actions.more('targets')
			});
		} else if (rest > 0) {
			where.label('more:targets', { text: `${rest} more, search finds them` }, true);
		}
	}
	tagRows.more();

	const links = new Map<string, Link>();
	const add = (from: string, to: string, field: 'base' | 'lit', targets: number) => {
		const source = home.get(from);
		const target = home.get(to);
		if (!source || !target) return;
		const id = `${source}>${target}`;
		const link = links.get(id) ?? { source, target, base: 0, lit: 0 };
		link[field] += targets;
		links.set(id, link);
	};
	for (const g of overview.grants) add(`s:${g.subjectId}`, `a:${g.username}`, 'base', g.targets);
	for (const r of overview.reach) add(`a:${r.username}`, `t:${r.tag}`, 'base', r.targets);
	for (const g of focused?.grants ?? [])
		add(`s:${g.subjectId}`, `a:${g.username}`, 'lit', g.targets);
	for (const r of focused?.reach ?? []) add(`a:${r.username}`, `t:${r.tag}`, 'lit', r.targets);

	return { nodes, links: [...links.values()] };
}

function subjectDetail(s: AccessGraphSubject) {
	if (s.kind === SubjectKind.TEAM)
		return `${s.memberCount} ${s.memberCount === 1 ? 'member' : 'members'}`;
	return s.kind === SubjectKind.USER && s.name ? s.email : undefined;
}

// Every link draws as a quiet ribbon as thick as its target count. The part
// the focus reaches draws again on top.
export function drawEdges(links: Link[], focused: boolean, hovered?: string): Edge[] {
	const max = Math.max(1, ...links.map((l) => l.base));
	const width = (targets: number) => 1.5 + 8.5 * Math.sqrt(Math.min(targets, max) / max);
	const edge = (id: string, l: Link, style: string, extra?: Partial<Edge>): Edge => ({
		id,
		source: l.source,
		target: l.target,
		selectable: false,
		focusable: false,
		interactionWidth: 0,
		style,
		...extra
	});

	const base = links.map((l) => {
		const hot = hovered === l.source || hovered === l.target;
		const stroke = hot ? 'var(--primary)' : 'var(--muted-foreground)';
		const opacity = hot ? 0.6 : focused ? 0.12 : 0.28;
		return edge(
			`e:${l.source}>${l.target}`,
			l,
			`stroke:${stroke};stroke-width:${width(l.base)}px;opacity:${opacity}`
		);
	});
	const lit = links
		.filter((l) => l.lit > 0)
		.map((l) =>
			edge(
				`l:${l.source}>${l.target}`,
				l,
				`stroke:var(--primary);stroke-width:${width(l.lit)}px;opacity:0.85`,
				{ zIndex: 1 }
			)
		);
	return [...base, ...lit];
}
