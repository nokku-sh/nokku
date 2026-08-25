import type { IconProps, LucideIcon } from '@lucide/svelte';

export type Action = {
	type: 'button' | 'dropdown' | 'popover';
	label: string;
	icon?: LucideIcon;
	onClick: () => void;
	variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
	classProps?: string;
	iconProps?: IconProps;
	disabled?: boolean;
	popover?: PopoverAction;
};

export type PopoverAction = {
	description?: string;
	confirmLabel?: string;
	cancelLabel?: string;
};

export type BulkAction<T> = {
	type: 'button' | 'select';
	label: string;
	icon?: LucideIcon;
	variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
	class?: string;
	disabled?: boolean;
	// For button type
	onClick?: (selectedItems: T[]) => Promise<void> | void;
	// For select type
	options?: {
		label: string;
		value: string;
		onClick: (selectedItems: T[], value: string) => Promise<void> | void;
	}[];
};

export type FacetedFilter = {
	label: string;
	value: string;
	icon?: LucideIcon;
};

export type FilterOption = {
	label: string;
	value: string;
	icon?: LucideIcon;
};

export type FilterConfig = {
	title: string;
	options: FilterOption[];
	param: string;
	mode?: 'single' | 'multi';
};
