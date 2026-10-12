import type { LucideIcon } from '@lucide/svelte';
import type { ButtonVariant } from '#lib/components/ui/button/index.js';
import type { ConfirmOptions } from '#lib/hooks/use-confirm.svelte.js';
import type { FilterOption } from '#lib/components/blocks/FilterPill.svelte';

export type BulkAction<T> = {
	label: string;
	icon?: LucideIcon;
	variant?: ButtonVariant;
	class?: string;
	disabled?: boolean;
	/** Asks first. The action runs inside the dialog, which shows its spinner. */
	confirm?: (selectedItems: T[]) => ConfirmOptions;
	onClick?: (selectedItems: T[]) => unknown;
};

export type FilterConfig = {
	title: string;
	options: FilterOption[];
	param: string;
	mode?: 'single' | 'multi';
};
