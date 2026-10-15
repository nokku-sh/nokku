import { Trash2 } from '@lucide/svelte';
import { plural } from '#lib/api/bulk.js';
import type { BulkAction } from './types';

/** The bulk Delete every list offers. Label, icon and confirm stay the same, the noun and the consequence vary. */
export function bulkDelete<T>(opts: {
	noun: string;
	/** For nouns whose plural isn't noun + s. */
	nouns?: string;
	description?: string;
	run: (selected: T[]) => unknown;
}): BulkAction<T> {
	return {
		label: 'Delete',
		icon: Trash2,
		variant: 'destructive',
		confirm: (selected) => ({
			title: `Delete ${plural(selected.length, opts.noun, opts.nouns)}?`,
			description: opts.description ?? 'This cannot be undone.',
			confirmText: 'Delete'
		}),
		onClick: opts.run
	};
}
