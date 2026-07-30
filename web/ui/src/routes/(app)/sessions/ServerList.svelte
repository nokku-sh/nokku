<script lang="ts">
	import { target } from '$lib/api/targets.svelte';
	import { user } from '$lib/api/user.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import ConnectPopover from './ConnectPopover.svelte';
	import { Server, WifiOff } from '@lucide/svelte';
	import { InputGroupVariants } from '$lib/components/ui/input-group';

	const currentUser = $derived(user.self());

	const access = $derived(target.access(currentUser.data?.id));
	const targets = $derived(access.data?.targets);
	const agents = $derived(access.data?.daemons);

	let searchQuery = $state('');

	// Build a list of connectable servers: targets the user can access, with their daemon info
	// const connectableServers = $derived.by(() => {
	// 	if (!accessibleTargets.data || !agents.data || !targets.data) return [];

	// 	return accessibleTargets.data.sort((a, b) => {
	// 		// Online first, then alphabetical
	// 		if (a.online !== b.online) return a.online ? -1 : 1;
	// 		return a.name.localeCompare(b.name);
	// 	});
	// });

	const filtered = $derived.by(() => {
		if (!targets) return [];
		const q = searchQuery.toLowerCase();
		return targets?.filter(
			(s) =>
				s.name.toLowerCase().includes(q) ||
				s.metadata?.hostname?.toLowerCase().includes(q) ||
				s.endpoints[0]?.toLowerCase().includes(q)
		);
	});
	const onlineCount = $derived(agents?.filter((s) => s.online).length);
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="border-b px-3 py-3">
		<div class="mb-2 flex items-center justify-between">
			<h2 class="text-sm font-semibold">Servers</h2>
			<Badge variant="outline" class="text-xs">
				{onlineCount} online
			</Badge>
		</div>
		<InputGroupVariants
			variant="search"
			bind:value={searchQuery}
			searchResults={filtered?.length}
		/>
	</div>

	<!-- Server list -->
	<div class="flex-1 overflow-y-auto">
		{#if access.isPending}
			<div class="space-y-1 p-2">
				{#each Array(5) as _}
					<div class="flex items-center gap-2 rounded-md p-2">
						<Skeleton class="size-2 rounded-full" />
						<Skeleton class="h-4 flex-1" />
					</div>
				{/each}
			</div>
		{:else if filtered.length === 0}
			<div class="flex flex-col items-center justify-center py-8 text-center">
				<Server class="mb-2 size-8 text-muted-foreground/30" />
				<p class="text-xs text-muted-foreground">
					{searchQuery ? 'No matches' : 'No servers available'}
				</p>
			</div>
		{:else}
			<div class="space-y-0.5 p-1.5">
				{#each filtered as target}
					{@const isOnline = agents?.some((a) => a.id === target.daemonId && a.online)}

					<div class="group relative">
						{#if isOnline && target.daemonId}
							<ConnectPopover {target} />
						{:else}
							<!-- Offline daemon -->
							<Tooltip.Provider>
								<Tooltip.Root>
									<Tooltip.Trigger>
										<div
											class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm opacity-50"
										>
											<span class="size-1.5 shrink-0 rounded-full bg-gray-400"></span>
											<div class="min-w-0 flex-1">
												<p class="truncate text-xs font-medium">{target.name}</p>
												{#if target.metadata?.hostname}
													<p class="truncate text-[10px] text-muted-foreground">
														{target.metadata.hostname}
													</p>
												{/if}
											</div>
											<WifiOff class="size-3 text-muted-foreground" />
										</div>
									</Tooltip.Trigger>
									<Tooltip.Content side="right">
										<p class="text-xs">Daemon offline</p>
									</Tooltip.Content>
								</Tooltip.Root>
							</Tooltip.Provider>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	</div>
</div>
