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
