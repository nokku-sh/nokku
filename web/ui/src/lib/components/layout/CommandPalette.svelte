<script lang="ts" module>
	let open = $state(false);

	export function openPalette() {
		open = true;
	}
</script>

<script lang="ts">
	import { goto } from '$app/navigation';
	import { util } from '#lib/api/workspaces.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as Kbd from '#lib/components/ui/kbd/index.js';
	import {
		AppRoutes,
		SupportRoutes,
		UserRoutes,
		canSee,
		supportRoute,
		type RouteItem
	} from './routes';

	const me = user.self();
	const info = util.instanceInfo();
	const support = $derived(supportRoute(info.data?.supportEmail));

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
	const groups = $derived.by(() => {
		const role = me.data?.role;
		const app = Object.entries(AppRoutes).map(
			([name, routes]) => [name, leaves(routes.filter((r) => canSee(r, role)))] as const
		);
		return [
			...app,
			['You', leaves(UserRoutes)] as const,
			...Object.entries(SupportRoutes).map(
				([name, routes]) => [name, leaves(support ? [...routes, support] : routes)] as const
			)
		].filter(([, items]) => items.length);
	});

	const shortcuts = $derived(
		new Map(
			groups.flatMap(([, items]) => items.filter((i) => i.shortcut).map((i) => [i.shortcut, i.url]))
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
			open = !open;
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

	function run(url: string) {
		open = false;
		if (url.startsWith('http') || url.startsWith('mailto:')) window.open(url, '_blank');
		else void goto(url);
	}
</script>

<svelte:window {onkeydown} />

<Command.Dialog bind:open>
	<Command.Input placeholder="Jump to a page..." />
	<Command.List>
		<Command.Empty>No page matches.</Command.Empty>
		{#each groups as [name, items], i (name)}
			{#if i > 0}<Command.Separator />{/if}
			<Command.Group heading={name}>
				{#each items as item (item.url + item.title)}
					<Command.Item onSelect={() => run(item.url)}>
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
