import {
	create,
	type DescMessage,
	type MessageInitShape,
	type MessageShape
} from '@bufbuild/protobuf';

/**
 * Reactive modal state manager for Svelte 5
 * Handles open state and selected item for modal dialogs
 */
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
		set selected(value: T) {
			selected = value;
		},
		/** Open modal with selected item */
		openWith(item: T) {
			selected = item;
			open = true;
		},
		/** Open modal for creating new item (resets to default) */
		openNew() {
			selected = defaultValue;
			open = true;
		},
		/** Close modal and optionally reset selection */
		close(resetSelection = false) {
			open = false;
			if (resetSelection) {
				selected = defaultValue;
			}
		}
	};
}

/**
 * Modal state for entity create/edit forms. The draft is a protobuf message
 * built with create(), so form fields always bind to a complete, schema-valid
 * object. openEdit() clones the entity into a fresh draft, which means the
 * query cache is never mutated and reopening an entity starts from its latest
 * server state.
 */
export function createEntityModalState<Desc extends DescMessage>(
	schema: Desc,
	newInit?: () => MessageInitShape<Desc>
) {
	type Entity = MessageShape<Desc>;

	// Svelte's $state only deep-proxies plain objects and arrays. Protobuf
	// messages are class instances, so they would pass through untracked and
	// field writes would never re-render the form. Cloning into a plain object
	// (keeping the $typeName discriminator) makes every draft reactive.
	function plainClone(entity: Entity): Entity {
		const clone = structuredClone(entity) as Entity;
		if (!('$typeName' in clone)) {
			(clone as { $typeName?: string }).$typeName = schema.typeName;
		}
		return clone;
	}

	let open = $state(false);
	let draft = $state<Entity>(plainClone(create(schema)));

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
		set draft(value: Entity) {
			draft = value;
		},
		/** Start a blank draft from the schema defaults (or a custom init) */
		openNew() {
			draft = plainClone(create(schema, newInit?.()));
			open = true;
		},
		/** Clone an existing entity into a fresh editable draft */
		openEdit(entity: Entity) {
			draft = plainClone(create(schema, entity));
			open = true;
		},
		close() {
			open = false;
		}
	};
}

/**
 * Create multiple modal states at once for pages with several modals
 */
export function createModalStates<T extends Record<string, unknown>>(config: {
	[K in keyof T]: T[K];
}) {
	const states = {} as { [K in keyof T]: ReturnType<typeof createModalState<T[K]>> };
	for (const key in config) {
		states[key] = createModalState<T[typeof key]>(config[key]);
	}
	return states;
}
