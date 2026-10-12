import { Crown, Eye, ShieldCheck, ShieldIcon, ShieldUser, User } from '@lucide/svelte';
import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';

const icons: Partial<Record<WorkspaceRole, typeof ShieldIcon>> = {
	[WorkspaceRole.OWNER]: Crown,
	[WorkspaceRole.ADMIN]: ShieldUser,
	[WorkspaceRole.EDITOR]: ShieldCheck,
	[WorkspaceRole.VIEWER]: Eye,
	[WorkspaceRole.MEMBER]: User
};
const colors: Partial<Record<WorkspaceRole, string>> = {
	[WorkspaceRole.OWNER]: 'text-chart-2',
	[WorkspaceRole.ADMIN]: 'text-chart-5',
	[WorkspaceRole.EDITOR]: 'text-chart-4',
	[WorkspaceRole.VIEWER]: 'text-chart-1',
	[WorkspaceRole.MEMBER]: 'text-muted-foreground'
};

/** A service account never manages people, the API takes nothing above the editor. */
export const SERVICE_ACCOUNT_MAX_ROLE = WorkspaceRole.EDITOR;

/** The role as a word, like "admin". URLs and string-valued inputs carry it. Empty for no role. */
export function roleSlug(role: WorkspaceRole | undefined): string {
	return role ? (WorkspaceRole[role] ?? '').toLowerCase() : '';
}

/** Reads a roleSlug back. */
export function parseRole(slug: string | null | undefined): WorkspaceRole | undefined {
	const role = WorkspaceRole[(slug ?? '').toUpperCase() as keyof typeof WorkspaceRole];
	return typeof role === 'number' && role !== WorkspaceRole.UNSPECIFIED ? role : undefined;
}

export function roleLabel(role: WorkspaceRole | undefined): string {
	const slug = roleSlug(role);
	return slug.charAt(0).toUpperCase() + slug.slice(1);
}

export function roleIcon(role: WorkspaceRole | undefined) {
	return icons[role ?? WorkspaceRole.UNSPECIFIED] ?? ShieldIcon;
}

export function roleColor(role: WorkspaceRole | undefined): string {
	return colors[role ?? WorkspaceRole.UNSPECIFIED] ?? 'text-foreground';
}

/** Whether role grants everything required grants. The roles are ordered, no role grants nothing. */
export function atLeast(role: WorkspaceRole | undefined, required: WorkspaceRole): boolean {
	return (role ?? WorkspaceRole.UNSPECIFIED) >= required;
}
