import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
import { DocsURL } from '#lib/config.js';
import { atLeast } from '#lib/roles.js';
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
	role?: WorkspaceRole;
};

export const AppRoutes: Record<string, RouteItem[]> = {
	Overview: [
		{ title: 'Dashboard', url: '/', icon: Gauge, shortcut: 'd' },
		{
			title: 'Topology',
			url: '/topology',
			icon: VectorSquare,
			role: WorkspaceRole.VIEWER,
			shortcut: 'o'
		},
		{
			title: 'Access',
			url: '/access',
			icon: ShieldCheck,
			role: WorkspaceRole.VIEWER,
			items: [
				{ title: 'Users', url: '/access/users', icon: CircleUser, shortcut: 'm' },
				{ title: 'Teams', url: '/access/teams', icon: Users },
				{ title: 'Service accounts', url: '/access/service-accounts', icon: Waypoints }
			]
		},
		{
			title: 'Infrastructure',
			url: '/infrastructure',
			icon: Orbit,
			role: WorkspaceRole.VIEWER,
			items: [
				{ title: 'Targets', url: '/infrastructure/targets', icon: Server, shortcut: 't' },
				{ title: 'Daemons', url: '/infrastructure/daemons', icon: Bot, shortcut: 'n' }
			]
		},
		{ title: 'Certificate authorities', url: '/certificates', icon: IdCard, shortcut: 'c' },
		{
			title: 'Sessions',
			url: '/sessions',
			icon: SquareTerminal,
			role: WorkspaceRole.VIEWER,
			shortcut: 'x'
		},
		{
			title: 'Recordings',
			url: '/recordings',
			icon: Video,
			role: WorkspaceRole.VIEWER,
			shortcut: 'r'
		}
	],
	Management: [
		{
			title: 'Audit log',
			url: '/audit',
			icon: FileClock,
			shortcut: 'a',
			role: WorkspaceRole.VIEWER
		},
		{
			title: 'Settings',
			url: '/settings',
			icon: Settings,
			role: WorkspaceRole.VIEWER,
			items: [
				{ title: 'Workspace', url: '/settings', icon: SlidersHorizontal, shortcut: 's' },
				{ title: 'Daemon defaults', url: '/settings/daemons', icon: ServerCog },
				{
					title: 'Audit streaming',
					url: '/settings/audit',
					icon: Radio,
					role: WorkspaceRole.OWNER
				},
				{ title: 'Single sign-on', url: '/settings/sso', icon: KeyRound },
				{
					title: 'Billing',
					url: '/settings/billing',
					icon: CreditCard,
					shortcut: 'b',
					role: WorkspaceRole.ADMIN
				}
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
			{ title: 'Activity', url: '/profile/activity', icon: Activity }
		]
	}
];

// Support is added at runtime, only when the server has a support email.
export const SupportRoutes: Record<string, RouteItem[]> = {
	Support: [{ title: 'Documentation', url: DocsURL, icon: BookText }]
};

/** The pages themselves, without the groups that only hold children. */
function leaves(items: RouteItem[]): RouteItem[] {
	return items.flatMap((item) => (item.items?.length ? leaves(item.items) : [item]));
}

const pageRoutes = [...leaves(Object.values(AppRoutes).flat()), ...leaves(UserRoutes)];

/** The nav entry for a path, used for titles, icons and crumbs. */
export function routeFor(path: string): RouteItem | undefined {
	const clean = path.replace(/\/$/, '') || '/';
	return pageRoutes.find((r) => r.url === clean);
}

// Show everything until the role is known, so the nav doesn't flicker.
export function canSee(route: RouteItem, role: WorkspaceRole | undefined): boolean {
	return role === undefined || atLeast(role, route.role ?? WorkspaceRole.MEMBER);
}

/** The nav for a role, without the pages it can't use and the groups that leaves empty. */
export function visibleRoutes(routes: RouteItem[], role: WorkspaceRole | undefined): RouteItem[] {
	return routes
		.filter((r) => canSee(r, role))
		.map((r) => (r.items ? { ...r, items: visibleRoutes(r.items, role) } : r))
		.filter((r) => !r.items || r.items.length > 0);
}

export function supportRoute(email: string | undefined): RouteItem | undefined {
	return email ? { title: 'Support', url: `mailto:${email}`, icon: Mail } : undefined;
}
