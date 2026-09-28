import { Crown, Eye, ShieldCheck, ShieldIcon, ShieldUser, User } from '@lucide/svelte';

/** Roles from least to most privileged. Each includes the ones before it. */
const order = ['member', 'viewer', 'editor', 'admin', 'owner'] as const;
export type RoleName = (typeof order)[number];

const icons = { owner: Crown, admin: ShieldUser, editor: ShieldCheck, viewer: Eye, member: User };
const colors = {
	owner: 'text-chart-2',
	admin: 'text-chart-5',
	editor: 'text-chart-4',
	viewer: 'text-chart-1',
	member: 'text-muted-foreground'
};

export function roleLabel(name: string): string {
	return name.charAt(0).toUpperCase() + name.slice(1);
}

export function roleIcon(name: string) {
	return icons[name as RoleName] ?? ShieldIcon;
}

export function roleColor(name: string): string {
	return colors[name as RoleName] ?? 'text-foreground';
}

/** Whether role grants everything required grants. Unknown roles grant nothing. */
export function atLeast(role: string | undefined, required: RoleName): boolean {
	const rank = order.indexOf(role as RoleName);
	return rank >= 0 && rank >= order.indexOf(required);
}
