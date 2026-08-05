import { Crown, Eye, ShieldCheck, ShieldIcon } from '@lucide/svelte';
import type { Role } from '$lib/gen/nokku/v1/util_pb';

const icons = { owner: Crown, editor: ShieldCheck, viewer: Eye } as const;
const colors = {
	owner: 'text-amber-500',
	editor: 'text-indigo-500',
	viewer: 'text-blue-500'
} as const;

export function roleLabel(name: string): string {
	return name.charAt(0).toUpperCase() + name.slice(1);
}

export function roleIcon(name: string) {
	return icons[name as keyof typeof icons] ?? ShieldIcon;
}

export function roleColor(name: string): string {
	return colors[name as keyof typeof colors] ?? 'text-foreground';
}

export function assignableRoles(list: Role[], to: 'users' | 'serviceAccounts'): Role[] {
	return list.filter((r) => (to === 'users' ? r.assignableToUsers : r.assignableToServiceAccounts));
}
