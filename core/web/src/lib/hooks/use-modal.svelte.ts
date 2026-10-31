import { untrack } from 'svelte';
import {
	create,
	type DescMessage,
	type MessageInitShape,
	type MessageShape
} from '@bufbuild/protobuf';
import { ownMessage } from '#lib/api/mask.js';

// $state only deep-proxies plain objects, a protobuf message instance would never re-render the form.
function plainClone<Desc extends DescMessage>(schema: Desc, entity: MessageShape<Desc>) {
	const message = create(schema, $state.snapshot(entity) as MessageInitShape<Desc>);
	const clone = structuredClone($state.snapshot(message)) as Record<string, unknown>;
	clone.$typeName = schema.typeName;
	return clone as MessageShape<Desc>;
}

// newDraft is the blank model of a create form. What init does not name stays undefined, so a form names every
// field it reads.
export function newDraft<Desc extends DescMessage>(schema: Desc, init?: MessageInitShape<Desc>) {
	return plainClone(schema, create(schema, init));
}

type Plain = Record<string, unknown>;

// useDraft is the editable copy of an entity. A refetch moves the fields nobody touched along, so another tab's change
// shows up and is never saved back. save sends only what differs from the server's copy.
export function useDraft<Desc extends DescMessage>(
	schema: Desc,
	source: () => MessageShape<Desc> | undefined,
	keyOf: (entity: MessageShape<Desc>) => string | undefined = (e) => (e as { id?: string }).id
) {
	const key = $derived.by(() => {
		const entity = source();
		return entity && keyOf(entity);
	});
	// base is what the server last said, the draft is compared against it.
	const edit = $derived.by(() => {
		if (!key) return undefined;
		const entity = untrack(source);
		if (!entity) return undefined;
		const draft = $state(plainClone(schema, entity));
		return { draft, base: plainClone(schema, entity) as Plain };
	});

	$effect(() => {
		const entity = source();
		untrack(() => {
			if (!entity || !edit || keyOf(entity) !== key) return;
			const fresh = plainClone(schema, entity) as Plain;
			rebase(schema, edit.draft as Plain, edit.base, fresh);
			edit.base = fresh;
		});
	});

	return {
		get current() {
			return edit?.draft;
		},
		/** Sends what changed since the server's copy, and counts it as the server's once it went through. */
		async save(send: (changes: Partial<MessageShape<Desc>>) => Promise<unknown>) {
			const current = edit;
			if (!current) return;
			const sent = diff(schema, $state.snapshot(current.draft) as Plain, current.base);
			if (!sent) return;
			await send(sent as Partial<MessageShape<Desc>>);
			merge(schema, current.base, sent);
		}
	};
}

const nested = (desc: DescMessage, localName: string) => {
	const field = desc.fields.find((f) => f.localName === localName);
	return field && ownMessage(field);
};

function diff(desc: DescMessage, draft: Plain, base: Plain): Plain | undefined {
	const out: Plain = {};
	for (const field of desc.fields) {
		const k = field.localName;
		const sub = nested(desc, k);
		if (sub && draft[k] && base[k]) {
			const changed = diff(sub, draft[k] as Plain, base[k] as Plain);
			if (changed) out[k] = changed;
		} else if (!same(draft[k], base[k])) {
			out[k] = draft[k];
		}
	}
	return Object.keys(out).length ? out : undefined;
}

function rebase(desc: DescMessage, draft: Plain, base: Plain, fresh: Plain) {
	for (const field of desc.fields) {
		const k = field.localName;
		const sub = nested(desc, k);
		if (sub && draft[k] && base[k] && fresh[k]) {
			rebase(sub, draft[k] as Plain, base[k] as Plain, fresh[k] as Plain);
		} else if (same(draft[k], base[k])) {
			draft[k] = structuredClone(fresh[k]);
		}
	}
}

function merge(desc: DescMessage, base: Plain, sent: Plain) {
	for (const [k, v] of Object.entries(sent)) {
		const sub = nested(desc, k);
		if (sub && base[k] && v) merge(sub, base[k] as Plain, v as Plain);
		else base[k] = structuredClone(v);
	}
}

function same(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
	const ka = Object.keys(a);
	const kb = Object.keys(b);
	return ka.length === kb.length && ka.every((k) => same((a as Plain)[k], (b as Plain)[k]));
}
