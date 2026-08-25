import type { LucideIcon } from '@lucide/svelte';

export interface HealthIssue {
	id: string;
	tone: 'info' | 'warn' | 'danger';
	icon: LucideIcon;
	title: string;
	description: string;
	ctaLabel: string;
	href: string;
}

export interface SetupStep {
	id: string;
	label: string;
	done: boolean;
	href: string;
}
