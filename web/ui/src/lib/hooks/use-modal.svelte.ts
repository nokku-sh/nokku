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
		set selected(value: T) {
			selected = value;
		},
		openWith(item: T) {
			selected = item;
			open = true;
		},
		openNew() {
			selected = defaultValue;
			open = true;
		},
		close(resetSelection = false) {
			open = false;
			if (resetSelection) {
				selected = defaultValue;
			}
		}
	};
}

// createEntityModalState edits a clone, so the query cache is never mutated.
export function createEntityModalState<Desc extends DescMessage>(
	schema: Desc,
	newInit?: () => MessageInitShape<Desc>
) {
	type Entity = MessageShape<Desc>;

	// $state only deep-proxies plain objects, protobuf messages are class
	// instances and would never re-render the form.
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
		openNew() {
			draft = plainClone(create(schema, newInit?.()));
			open = true;
		},
		openEdit(entity: Entity) {
			draft = plainClone(create(schema, entity));
			open = true;
		},
		close() {
			open = false;
		}
	};
}

export function createModalStates<T extends Record<string, unknown>>(config: {
	[K in keyof T]: T[K];
}) {
	const states = {} as { [K in keyof T]: ReturnType<typeof createModalState<T[K]>> };
	for (const key in config) {
		states[key] = createModalState<T[typeof key]>(config[key]);
	}
	return states;
}
