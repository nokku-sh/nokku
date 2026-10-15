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
	Server,
	ServerCog,
	Shield,
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

// Groups hold four pages at most, so every entry is a link and nothing hides behind a toggle.
export const AppRoutes: Record<string, RouteItem[]> = {
	Overview: [
		{ title: 'Dashboard', url: '/', icon: Gauge, shortcut: 'h' },
		// Every member opens shells on their own servers here.
		{ title: 'Sessions', url: '/sessions', icon: SquareTerminal, shortcut: 's' },
		{
			title: 'Topology',
			url: '/topology',
			icon: VectorSquare,
			role: WorkspaceRole.VIEWER,
			shortcut: 'o'
		}
	],
	Access: [
		{
			title: 'Users',
			url: '/access/users',
			icon: CircleUser,
			role: WorkspaceRole.VIEWER,
			shortcut: 'u'
		},
		{
			title: 'Teams',
			url: '/access/teams',
			icon: Users,
			role: WorkspaceRole.VIEWER,
			shortcut: 'm'
		},
		{
			title: 'Service accounts',
			url: '/access/service-accounts',
			icon: Waypoints,
			role: WorkspaceRole.VIEWER,
			shortcut: 'v'
		}
	],
	Infrastructure: [
		{
			title: 'Targets',
			url: '/infrastructure/targets',
			icon: Server,
			role: WorkspaceRole.VIEWER,
			shortcut: 't'
		},
		{
			title: 'Daemons',
			url: '/infrastructure/daemons',
			icon: Bot,
			role: WorkspaceRole.VIEWER,
			shortcut: 'd'
		},
		{
			title: 'Certificate authorities',
			url: '/certificates',
			icon: IdCard,
			role: WorkspaceRole.VIEWER,
			shortcut: 'c'
		}
	],
	Activity: [
		{
			title: 'Recordings',
			url: '/recordings',
			icon: Video,
			role: WorkspaceRole.VIEWER,
			shortcut: 'r'
		},
		{
			title: 'Audit log',
			url: '/audit',
			icon: FileClock,
			role: WorkspaceRole.VIEWER,
			shortcut: 'a'
		}
	],
	Settings: [
		{
			title: 'Workspace',
			url: '/settings',
			icon: SlidersHorizontal,
			role: WorkspaceRole.VIEWER,
			shortcut: 'w'
		},
		{
			title: 'Daemon defaults',
			url: '/settings/daemons',
			icon: ServerCog,
			role: WorkspaceRole.VIEWER,
			shortcut: 'f'
		},
		{
			title: 'Single sign-on',
			url: '/settings/sso',
			icon: KeyRound,
			role: WorkspaceRole.VIEWER,
			shortcut: 'i'
		},
		{
			title: 'Billing',
			url: '/settings/billing',
			icon: CreditCard,
			role: WorkspaceRole.ADMIN,
			shortcut: 'b'
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
			{ title: 'Security', url: '/profile/security', icon: Shield, shortcut: 'k' },
			{ title: 'Activity', url: '/profile/activity', icon: Activity, shortcut: 'l' }
		]
	}
];

// Support is added at runtime, only when the server has a support email.
export const SupportRoutes: RouteItem[] = [
	{ title: 'Documentation', url: DocsURL, icon: BookText }
];

/** The pages without the groups that only hold children. A page without a role of its own takes the group's. */
function leaves(items: RouteItem[], role?: WorkspaceRole): RouteItem[] {
	return items.flatMap((item) => {
		const own = item.role ?? role;
		return item.items?.length ? leaves(item.items, own) : [{ ...item, role: own }];
	});
}

const pageRoutes = [...leaves(Object.values(AppRoutes).flat()), ...leaves(UserRoutes)];

// A second page on the same letter would silently win the jump, so dev refuses to start with one.
if (import.meta.env.DEV) {
	const seen = new Map<string, string>();
	for (const r of pageRoutes) {
		if (!r.shortcut) continue;
		const other = seen.get(r.shortcut);
		if (other) throw new Error(`g ${r.shortcut} is taken by both ${other} and ${r.title}`);
		seen.set(r.shortcut, r.title);
	}
}

/** The nav entry for a path, used for titles, icons and crumbs. */
export function routeFor(path: string): RouteItem | undefined {
	const clean = path.replace(/\/$/, '') || '/';
	return pageRoutes.find((r) => r.url === clean);
}

// Show everything until the role is known, so the nav doesn't flicker.
function canSee(route: RouteItem, role: WorkspaceRole | undefined): boolean {
	return role === undefined || atLeast(role, route.role ?? WorkspaceRole.MEMBER);
}

/** Whether the role may open a path. A page under a nav entry counts as that entry. */
export function canVisit(path: string, role: WorkspaceRole | undefined): boolean {
	const clean = path.replace(/\/$/, '') || '/';
	const route = pageRoutes
		.filter((r) => clean === r.url || clean.startsWith(r.url + '/'))
		.sort((a, b) => b.url.length - a.url.length)[0];
	return !route || canSee(route, role);
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
