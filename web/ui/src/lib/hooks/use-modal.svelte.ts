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

// $state only deep-proxies plain objects, protobuf messages are class
// instances and would never re-render the form.
function plainClone<Desc extends DescMessage>(schema: Desc, entity: MessageShape<Desc>) {
	const message = create(schema, $state.snapshot(entity) as MessageInitShape<Desc>);
	const clone = structuredClone($state.snapshot(message)) as Record<string, unknown>;
	// Unset fields with explicit presence keep their defaults on the prototype,
	// which structuredClone drops, so copy them over as own values.
	for (const field of schema.fields) {
		const value = (message as Record<string, unknown>)[field.localName];
		if (clone[field.localName] === undefined && value !== undefined) {
			clone[field.localName] = structuredClone(value);
		}
	}
	clone.$typeName = schema.typeName;
	return clone as MessageShape<Desc>;
}

// useDraft gives an editable copy of a loaded entity. It only resets when a
// different entity loads, so background refetches never clobber edits.
export function useDraft<Desc extends DescMessage>(
	schema: Desc,
	source: () => MessageShape<Desc> | undefined
) {
	const key = $derived((source() as { id?: string } | undefined)?.id);
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

// createEntityModalState edits a clone, so the query cache is never mutated.
export function createEntityModalState<Desc extends DescMessage>(
	schema: Desc,
	newInit?: () => MessageInitShape<Desc>
) {
	type Entity = MessageShape<Desc>;
	const clone = (entity: Entity) => plainClone(schema, entity);

	let open = $state(false);
	let draft = $state<Entity>(clone(create(schema)));

	return {
		get open() {
			return open;
		},
		set open(value: boolean) {
			open = value;
		},
		get draft() {
			return draft;
		},
		openNew() {
			draft = clone(create(schema, newInit?.()));
			open = true;
		}
	};
}
