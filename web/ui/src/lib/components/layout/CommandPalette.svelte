<script lang="ts">
	import { goto } from '$app/navigation';
	import * as Command from '$lib/components/ui/command';
	import * as Kbd from '$lib/components/ui/kbd';
	import { AppRoutes, SupportRoutes, UserRoutes, type RouteItem } from '$lib/components/nav/routes';

	let open = $state(false);
	let lastKey = '';
	let keyTimeout: ReturnType<typeof setTimeout>;

	function flattenRoutes(items: RouteItem[], parentTitle = '') {
		const flatItems: Array<{ title: string; url: string; icon: any; shortcut?: string }> = [];
		for (const item of items) {
			if (item.items && item.items.length > 0) {
				flatItems.push(...flattenRoutes(item.items, item.title));
			} else {
				flatItems.push({
					title: parentTitle ? `${parentTitle} → ${item.title}` : item.title,
					url: item.url,
					icon: item.icon,
					shortcut: item.shortcut
				});
			}
		}
		return flatItems;
	}

	const allFlatRoutes = [
		...Object.values(AppRoutes).flatMap((routes) => flattenRoutes(routes)),
		...flattenRoutes(UserRoutes),
		...Object.values(SupportRoutes).flatMap((routes) => flattenRoutes(routes))
	];

	const shortcutMap = new Map(
		allFlatRoutes.filter((item) => item.shortcut).map((item) => [item.shortcut, item.url])
	);

	function handleKeydown(e: KeyboardEvent) {
		if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
			return;
		}

		const currentKey = e.key.toLowerCase();

		if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
			e.preventDefault();
			open = !open;
			return;
		}

		if (lastKey === 'g') {
			const destinationUrl = shortcutMap.get(currentKey);

			if (destinationUrl) {
				e.preventDefault();
				goto(destinationUrl);
			}

			lastKey = '';
			return;
		}

		if (currentKey === 'g') {
			lastKey = 'g';
			clearTimeout(keyTimeout);
			keyTimeout = setTimeout(() => {
				lastKey = '';
			}, 1000);
		}
	}

	function runCommand(url: string) {
		if (url.startsWith('http') || url.startsWith('mailto:')) {
			window.open(url, '_blank');
		} else {
			goto(url);
		}
		open = false;
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<Command.Dialog bind:open>
	<Command.Input placeholder="Search..." />
	<Command.List>
		<Command.Empty>No results found.</Command.Empty>

		{#each Object.entries(AppRoutes) as [groupName, routes]}
			<Command.Group heading={groupName}>
				{#each flattenRoutes(routes) as item}
					<Command.Item onSelect={() => runCommand(item.url)}>
						{@const Icon = item.icon}
						<Icon class="mr-2" />
						<span>{item.title}</span>
						{#if item.shortcut}
							<Command.Shortcut>
								<Kbd.Root>G</Kbd.Root>
								<span>+</span>
								<Kbd.Root>{item.shortcut.toUpperCase()}</Kbd.Root>
							</Command.Shortcut>
						{/if}
					</Command.Item>
				{/each}
			</Command.Group>
			<Command.Separator />
		{/each}

		<Command.Group heading="User">
			{#each flattenRoutes(UserRoutes) as item}
				<Command.Item onSelect={() => runCommand(item.url)}>
					{@const Icon = item.icon}
					<Icon class="mr-2" />
					<span>{item.title}</span>
					{#if item.shortcut}
						<Command.Shortcut>
							<Kbd.Root>G</Kbd.Root>
							<span>+</span>
							<Kbd.Root>{item.shortcut.toUpperCase()}</Kbd.Root>
						</Command.Shortcut>
					{/if}
				</Command.Item>
			{/each}
		</Command.Group>

		{#each Object.entries(SupportRoutes) as [groupName, routes]}
			<Command.Group heading={groupName}>
				{#each flattenRoutes(routes) as item}
					<Command.Item onSelect={() => runCommand(item.url)}>
						{@const Icon = item.icon}
						<Icon class="mr-2" />
						<span>{item.title}</span>
					</Command.Item>
				{/each}
			</Command.Group>
		{/each}
	</Command.List>
</Command.Dialog>
