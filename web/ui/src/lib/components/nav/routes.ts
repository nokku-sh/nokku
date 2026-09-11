import { DocsURL, SupportEmail } from '$lib/config';
import {
	Activity,
	BookText,
	Bot,
	CircleQuestionMark,
	CircleUser,
	Gauge,
	IdCard,
	KeyRound,
	Mail,
	Orbit,
	ScrollText,
	Settings,
	Shield,
	Sparkles,
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
	shortcut?: string;
	icon: LucideIcon;
	items?: RouteItem[];
};

export const AppRoutes: Record<string, RouteItem[]> = {
	Overview: [
		{ title: 'Dashboard', url: '/', icon: Gauge, shortcut: 'd' },
		{
			title: 'Access',
			url: '/access',
			icon: CircleUser,
			items: [
				{ title: 'Members', url: '/access/members', icon: CircleUser },
				{ title: 'Teams', url: '/access/teams', icon: Users },
				{ title: 'Service Accounts', url: '/access/service-accounts', icon: Waypoints }
			]
		},
		{
			title: 'Infrastructure',
			url: '/infrastructure',
			icon: Orbit,
			items: [
				{ title: 'Targets', url: '/infrastructure/targets', icon: BookText },
				{ title: 'Daemons', url: '/infrastructure/daemons', icon: CircleQuestionMark },
				{ title: 'Topology', url: '/infrastructure/topology', icon: VectorSquare }
			]
		},
		{ title: 'Certificates', url: '/certificates', icon: IdCard, shortcut: 'c' },
		{ title: 'Sessions', url: '/sessions', icon: SquareTerminal },
		{ title: 'Recordings', url: '/recordings', icon: Video }
	],
	Management: [
		{ title: 'Activity', url: '/activity', icon: Activity, shortcut: 'a' },
		{
			title: 'Settings',
			url: '/settings',
			icon: Settings,
			items: [
				{ title: 'General', url: '/settings', icon: Settings, shortcut: 's' },
				{ title: 'Daemons', url: '/settings/daemons', icon: Bot },
				{ title: 'Audit Streaming', url: '/settings/audit', icon: ScrollText },
				{ title: 'Single Sign-On', url: '/settings/sso', icon: KeyRound }
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
			{ title: 'Billing', url: '/profile/billing', icon: Sparkles, shortcut: 'b' }
		]
	}
];

export const SupportRoutes: Record<string, RouteItem[]> = {
	Support: [
		{ title: 'Documentation', url: DocsURL, icon: BookText },
		{ title: 'Support', url: SupportEmail, icon: Mail }
	]
};
