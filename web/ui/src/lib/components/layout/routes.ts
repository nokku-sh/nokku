import { DocsURL, SupportEmail } from '$lib/config';
import { atLeast, type RoleName } from '$lib/roles';
import {
	Activity,
	BookText,
	Bot,
	CircleUser,
	CreditCard,
	FileClock,
	Gauge,
	IdCard,
	KeyRound,
	Mail,
	Orbit,
	Radio,
	Server,
	ServerCog,
	Settings,
	Shield,
	ShieldCheck,
	SlidersHorizontal,
	SquareTerminal,
	User,
	Users,
	VectorSquare,
	Video,
	Waypoints,
	type LucideIcon
} from '@lucide/svelte';

export type RouteItem = {
	title: string;
	url: string;
	/** Jump key, pressed after g. */
	shortcut?: string;
	icon: LucideIcon;
	items?: RouteItem[];
	/** Least workspace role that can use the page. Unset means every member. */
	role?: RoleName;
};

export const AppRoutes: Record<string, RouteItem[]> = {
	Overview: [
		{ title: 'Dashboard', url: '/', icon: Gauge, shortcut: 'd' },
		{
			title: 'Access',
			url: '/access',
			icon: ShieldCheck,
			role: 'viewer',
			items: [
				{ title: 'Members', url: '/access/members', icon: CircleUser, shortcut: 'm' },
				{ title: 'Teams', url: '/access/teams', icon: Users },
				{ title: 'Service accounts', url: '/access/service-accounts', icon: Waypoints }
			]
		},
		{
			title: 'Infrastructure',
			url: '/infrastructure',
			icon: Orbit,
			role: 'viewer',
			items: [
				{ title: 'Targets', url: '/infrastructure/targets', icon: Server, shortcut: 't' },
				{ title: 'Daemons', url: '/infrastructure/daemons', icon: Bot, shortcut: 'n' },
				{ title: 'Topology', url: '/infrastructure/topology', icon: VectorSquare }
			]
		},
		{ title: 'Certificates', url: '/certificates', icon: IdCard, shortcut: 'c' },
		{ title: 'Sessions', url: '/sessions', icon: SquareTerminal, role: 'viewer', shortcut: 'x' },
		{ title: 'Recordings', url: '/recordings', icon: Video, role: 'viewer', shortcut: 'r' }
	],
	Management: [
		{ title: 'Audit log', url: '/audit', icon: FileClock, shortcut: 'a', role: 'viewer' },
		{
			title: 'Settings',
			url: '/settings',
			icon: Settings,
			role: 'viewer',
			items: [
				{ title: 'Workspace', url: '/settings', icon: SlidersHorizontal, shortcut: 's' },
				{ title: 'Daemon defaults', url: '/settings/daemons', icon: ServerCog },
				{ title: 'Audit streaming', url: '/settings/audit', icon: Radio },
				{ title: 'Single sign-on', url: '/settings/sso', icon: KeyRound }
			]
		}
	]
};

export const UserRoutes: RouteItem[] = [
	{
		title: 'Profile',
		url: '/profile',
		icon: User,
		items: [
			{ title: 'Profile', url: '/profile', icon: User, shortcut: 'p' },
			{ title: 'Security', url: '/profile/security', icon: Shield },
			{ title: 'Activity', url: '/profile/activity', icon: Activity },
			{ title: 'Billing', url: '/profile/billing', icon: CreditCard, shortcut: 'b' }
		]
	}
];

export const SupportRoutes: Record<string, RouteItem[]> = {
	Support: [
		{ title: 'Documentation', url: DocsURL, icon: BookText },
		{ title: 'Support', url: SupportEmail, icon: Mail }
	]
};

/** The pages themselves, without the groups that only hold children. */
function leaves(items: RouteItem[]): RouteItem[] {
	return items.flatMap((item) => (item.items?.length ? leaves(item.items) : [item]));
}

export const pageRoutes = [...leaves(Object.values(AppRoutes).flat()), ...leaves(UserRoutes)];

/** The nav entry for a path, used for titles, icons and crumbs. */
export function routeFor(path: string): RouteItem | undefined {
	const clean = path.replace(/\/$/, '') || '/';
	return pageRoutes.find((r) => r.url === clean);
}

// Show everything until the role is known, so the nav doesn't flicker.
export function canSee(route: RouteItem, role: string | undefined): boolean {
	return role === undefined || atLeast(role, route.role ?? 'member');
}
