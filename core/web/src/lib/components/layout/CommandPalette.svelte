<script lang="ts" module>
	let open = $state(false);
	let search = $state('');

	export function openPalette() {
		search = '';
		open = true;
	}
</script>

<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '#lib/api/auth.svelte.js';
	import { useConnect, useServers } from '#lib/api/connect.svelte.js';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { team } from '#lib/api/team.svelte.js';
	import { users, util } from '#lib/api/workspaces.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as Kbd from '#lib/components/ui/kbd/index.js';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import {
		Bot,
		CircleUser,
		IdCard,
		Moon,
		Rocket,
		Server,
		Sun,
		UserPlus,
		Users,
		Waypoints
	} from '@lucide/svelte';
	import { mode, toggleMode } from 'mode-watcher';
	import { Debounced } from 'runed';
	import {
		AppRoutes,
		SupportRoutes,
		UserRoutes,
		supportRoute,
		visibleRoutes,
		type RouteItem
	} from './routes';

	const SHELLS = 6;
	const FOUND = 5;

	const me = user.self();
	const can = user.can();
	const options = auth.options();
	const info = util.instanceInfo();
	const support = $derived(supportRoute(info.data?.supportEmail));
	const connect = useConnect();
	const servers = useServers(() => open);

	// deploy@web-1 finds the account on the server, so @ splits like a space.
	const words = $derived(
		search
			.toLowerCase()
			.split(/[\s@]+/)
			.filter(Boolean)
	);
	const matches = (...text: (string | undefined)[]) => {
		const hay = text.join(' ').toLowerCase();
		return words.every((w) => hay.includes(w));
	};

	const shells = $derived(
		servers.list
			.flatMap((t) => t.usernames.map((username) => ({ t, username })))
			.filter(({ t, username }) => matches(username, t.name, t.metadata?.hostname))
			.slice(0, SHELLS)
	);

	const actions = $derived(
		[
			{
				title: 'Add target',
				icon: Server,
				url: '/infrastructure/targets?new=1',
				show: can.edit,
				keywords: 'server host create'
			},
			{
				title: 'Enroll a daemon',
				icon: Rocket,
				url: '/infrastructure/daemons?new=1',
				show: can.admin,
				keywords: 'nokkud token install'
			},
			{
				title: 'Invite people',
				icon: UserPlus,
				url: '/access/users?new=1',
				show: can.admin && !!options.data?.magicLink,
				keywords: 'user member add'
			},
			{ title: 'Create team', icon: Users, url: '/access/teams?new=1', show: can.edit },
			{
				title: 'Create service account',
				icon: Waypoints,
				url: '/access/service-accounts?new=1',
				show: can.edit,
				keywords: 'api ci automation'
			},
			{
				title: 'Create CA',
				icon: IdCard,
				url: '/certificates?new=1',
				show: can.edit,
				keywords: 'certificate authority'
			},
			{
				title: mode.current === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
				icon: mode.current === 'dark' ? Sun : Moon,
				run: toggleMode,
				show: true,
				keywords: 'theme'
			}
		].filter((a) => a.show && matches(a.title, a.keywords))
	);

	// The server searches, so this also finds what the loaded pages don't hold.
	const typed = new Debounced(() => search.trim(), 200);
	const finding = $derived(open && can.view && typed.current.length >= 2);
	const find = () => ({ query: typed.current, limit: FOUND });
	const foundTargets = target.list(find, () => finding);
	const foundUsers = users.list(find, () => finding);
	const foundTeams = team.list(find, () => finding);
	const foundDaemons = daemon.list(find, () => finding);
	const foundAccounts = serviceAccount.list(find, () => finding);

	const found = $derived(
		(finding
			? [
					{
						heading: 'Targets',
						icon: Server,
						rows: (foundTargets.data?.targets ?? []).map((t) => ({
							url: `/infrastructure/targets?id=${t.id}`,
							title: t.name,
							hint: t.metadata?.hostname || t.endpoints[0]
						}))
					},
					{
						heading: 'Users',
						icon: CircleUser,
						rows: (foundUsers.data?.users ?? []).map((u) => ({
							url: `/access/users?id=${u.id}`,
							title: u.name || u.email,
							hint: u.name ? u.email : undefined
						}))
					},
					{
						heading: 'Teams',
						icon: Users,
						rows: (foundTeams.data?.teams ?? []).map((t) => ({
							url: `/access/teams?id=${t.id}`,
							title: t.name,
							hint: t.description
						}))
					},
					{
						heading: 'Daemons',
						icon: Bot,
						rows: (foundDaemons.data?.daemons ?? []).map((d) => ({
							url: `/infrastructure/daemons?id=${d.id}`,
							title: d.name,
							hint: d.online ? 'online' : 'offline'
						}))
					},
					{
						heading: 'Service accounts',
						icon: Waypoints,
						rows: (foundAccounts.data?.serviceAccounts ?? []).map((a) => ({
							url: `/access/service-accounts?id=${a.id}`,
							title: a.name,
							hint: a.description
						}))
					}
				]
			: []
		).filter((g) => g.rows.length)
	);

	function leaves(items: RouteItem[], parent = ''): RouteItem[] {
		return items.flatMap((item) =>
			item.items?.length
				? leaves(item.items, item.title)
				: [
						{
							...item,
							title: parent && parent !== item.title ? `${parent} → ${item.title}` : item.title
						}
					]
		);
	}

	// The same role gate as the sidebar.
	const allPages = $derived.by(() => {
		const role = me.data?.role;
		const app = Object.entries(AppRoutes).map(
			([name, routes]) => [name, leaves(visibleRoutes(routes, role))] as const
		);
		return [
			...app,
			['You', leaves(UserRoutes)] as const,
			...Object.entries(SupportRoutes).map(
				([name, routes]) => [name, leaves(support ? [...routes, support] : routes)] as const
			)
		];
	});

	const pages = $derived(
		allPages
			.map(([name, items]) => [name, items.filter((i) => matches(i.title))] as const)
			.filter(([, items]) => items.length)
	);

	const shortcuts = $derived(
		new Map(
			allPages.flatMap(([, items]) =>
				items.filter((i) => i.shortcut).map((i) => [i.shortcut, i.url])
			)
		)
	);

	let pendingG = false;
	let gTimer: ReturnType<typeof setTimeout>;

	function isTyping(target: EventTarget | null) {
		return (
			target instanceof HTMLElement &&
			(target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))
		);
	}

	// Cmd+K opens the palette, g then a letter jumps to a page.
	function onkeydown(e: KeyboardEvent) {
		if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
			e.preventDefault();
			if (open) open = false;
			else openPalette();
			return;
		}
		if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;

		const key = e.key.toLowerCase();
		if (pendingG) {
			pendingG = false;
			const url = shortcuts.get(key);
			if (url) {
				e.preventDefault();
				void goto(url);
			}
			return;
		}
		if (key === 'g') {
			pendingG = true;
			clearTimeout(gTimer);
			gTimer = setTimeout(() => (pendingG = false), 1000);
		}
	}

	function go(url: string) {
		open = false;
		if (url.startsWith('http') || url.startsWith('mailto:')) window.open(url, '_blank');
		else void goto(url);
	}

	function connectTo(t: Target, username: string) {
		open = false;
		void (servers.canShell(t) ? connect.shell(t, username) : connect.copy(t, username));
	}
</script>

<svelte:window {onkeydown} />

<Command.Dialog
	bind:open
	shouldFilter={false}
	title="Command palette"
	description="Open a shell, find something or jump to a page"
>
	<Command.Input bind:value={search} placeholder="Search, connect or jump to..." />
	<Command.List>
		<Command.Empty>Nothing matches.</Command.Empty>

		{#if shells.length}
			<Command.Group heading={words.length ? 'Connect' : 'Connect again'}>
				{#each shells as { t, username } (t.id + username)}
					{@const shell = servers.canShell(t)}
					<Command.Item
						value={`connect:${t.id}:${username}`}
						onSelect={() => connectTo(t, username)}
					>
						<StatusDot tone={shell ? 'success' : 'muted'} class="mx-1" />
						<span class="truncate font-mono text-xs">{username}@{t.name}</span>
						<Command.Shortcut>{shell ? 'web shell' : 'copy ssh'}</Command.Shortcut>
					</Command.Item>
				{/each}
			</Command.Group>
		{/if}

		{#if actions.length}
			<Command.Group heading="Actions">
				{#each actions as action (action.title)}
					<Command.Item
						value={`action:${action.title}`}
						onSelect={() => {
							if (action.url) return go(action.url);
							open = false;
							action.run?.();
						}}
					>
						<action.icon />
						<span>{action.title}</span>
					</Command.Item>
				{/each}
			</Command.Group>
		{/if}

		{#each found as group (group.heading)}
			<Command.Group heading={group.heading}>
				{#each group.rows as row (row.url)}
					<Command.Item value={row.url} onSelect={() => go(row.url)}>
						<group.icon />
						<span class="truncate">{row.title}</span>
						{#if row.hint}
							<span class="truncate text-xs text-muted-foreground">{row.hint}</span>
						{/if}
					</Command.Item>
				{/each}
			</Command.Group>
		{/each}

		{#each pages as [name, items] (name)}
			<Command.Group heading={name}>
				{#each items as item (item.url + item.title)}
					<Command.Item value={`page:${item.url}:${item.title}`} onSelect={() => go(item.url)}>
						<item.icon />
						<span>{item.title}</span>
						{#if item.shortcut}
							<Command.Shortcut class="flex items-center gap-1">
								<Kbd.Root>G</Kbd.Root>
								<Kbd.Root>{item.shortcut.toUpperCase()}</Kbd.Root>
							</Command.Shortcut>
						{/if}
					</Command.Item>
				{/each}
			</Command.Group>
		{/each}
	</Command.List>
</Command.Dialog>
