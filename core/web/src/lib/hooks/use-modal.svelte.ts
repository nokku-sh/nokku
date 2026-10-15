import { untrack } from 'svelte';
import {
	create,
	type DescMessage,
	type MessageInitShape,
	type MessageShape
} from '@bufbuild/protobuf';

export function createModalState<T>(defaultValue: T = {} as T) {
	let open = $state(false);
	let selected = $state<T>(defaultValue);

	return {
		get open() {
			return open;
		},
		set open(value: boolean) {
			open = value;
		},
		get selected() {
			return selected;
		},
		openWith(item: T) {
			selected = item;
			open = true;
		},
		close() {
			open = false;
		}
	};
}

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

// useDraft only resets when a different entity loads, so background refetches never clobber edits.
export function useDraft<Desc extends DescMessage>(
	schema: Desc,
	source: () => MessageShape<Desc> | undefined,
	keyOf: (entity: MessageShape<Desc>) => string | undefined = (e) => (e as { id?: string }).id
) {
	const key = $derived.by(() => {
		const entity = source();
		return entity && keyOf(entity);
	});
	const draft = $derived.by(() => {
		if (!key) return undefined;
		const entity = untrack(source);
		const copy = $state(entity ? plainClone(schema, entity) : undefined);
		return copy;
	});
	return {
		get current() {
			return draft;
		}
	};
}
