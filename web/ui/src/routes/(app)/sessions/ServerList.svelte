<script lang="ts">
	import * as Empty from '$lib/components/ui/empty';
	import StatusDot from '$lib/components/blocks/StatusDot.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { user } from '$lib/api/user.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import ConnectPopover from './ConnectPopover.svelte';
	import { Server, WifiOff } from '@lucide/svelte';
	import { InputGroupVariants } from '$lib/components/ui/input-group';

	const currentUser = user.self();

	const access = target.access(() => currentUser.data?.id);
	const targets = $derived(access.data?.targets);
	const agents = $derived(access.data?.daemons);

	let searchQuery = $state('');

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

	<div class="flex-1 overflow-y-auto">
		{#if access.isPending}
			<div class="space-y-1 p-2">
				{#each { length: 5 }, i (i)}
					<div class="flex items-center gap-2 rounded-md p-2">
						<Skeleton class="size-2 rounded-full" />
						<Skeleton class="h-4 flex-1" />
					</div>
				{/each}
			</div>
		{:else if filtered.length === 0}
			<Empty.Root class="py-8">
				<Empty.Header>
					<Empty.Media variant="icon"><Server /></Empty.Media>
					<Empty.Title class="text-sm">{searchQuery ? 'No matches' : 'No servers yet'}</Empty.Title>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="space-y-0.5 p-1.5">
				{#each filtered as target (target.id)}
					{@const isOnline = agents?.some((a) => a.id === target.daemonId && a.online)}

					<div class="group relative">
						{#if isOnline && target.daemonId}
							<ConnectPopover {target} />
						{:else}
							<Tooltip.Provider>
								<Tooltip.Root>
									<Tooltip.Trigger>
										<div
											class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm opacity-50"
										>
											<StatusDot class="size-1.5" />
											<div class="min-w-0 flex-1">
												<p class="truncate text-xs font-medium">{target.name}</p>
												{#if target.metadata?.hostname}
													<p class="truncate text-2xs text-muted-foreground">
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
