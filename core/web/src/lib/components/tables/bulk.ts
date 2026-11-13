import { Trash } from '@lucide/svelte';
import { plural } from '#lib/api/bulk.js';
import { listNames } from '#lib/utils.js';
import type { BulkAction } from './types';

/** The bulk Delete every list offers. Label, icon and confirm stay the same, the noun and the consequence vary. */
export function bulkDelete<T>(opts: {
	noun: string;
	/** For nouns whose plural isn't noun + s. */
	nouns?: string;
	/** Names the rows in the dialog. */
	name?: (item: T) => string;
	/** Rows the delete leaves alone, so the dialog counts and names only what goes. */
	skip?: (item: T) => boolean;
	description?: string;
	/** Asks to type the count first, for deletes that are hard to undo. */
	typed?: boolean;
	fresh?: boolean;
	run: (selected: T[]) => unknown;
}): BulkAction<T> {
	const { name, skip } = opts;
	const rows = (selected: T[]) => (skip ? selected.filter((item) => !skip(item)) : selected);
	return {
		label: 'Delete',
		fresh: opts.fresh,
		icon: Trash,
		variant: 'destructive',
		show: (selected) => rows(selected).length > 0,
		confirm: (selected) => {
			const going = rows(selected);
			const count = plural(going.length, opts.noun, opts.nouns);
			const consequence = opts.description ?? 'This cannot be undone.';
			return {
				title: `Delete ${count}?`,
				description: name ? `${listNames(going.map(name), 5)}. ${consequence}` : consequence,
				confirmText: 'Delete',
				typeToConfirm: opts.typed ? count : undefined
			};
		},
		onClick: (selected) => opts.run(rows(selected))
	};
}
