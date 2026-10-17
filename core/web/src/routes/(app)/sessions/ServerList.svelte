<script lang="ts">
	import { serverMatches, useServers } from '#lib/api/connect.svelte.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Server } from '@lucide/svelte';
	import ServerRow from './ServerRow.svelte';

	const servers = useServers();

	let searchQuery = $state('');

	const filtered = $derived(servers.list.filter((t) => serverMatches(t, searchQuery)));
</script>

<div class="flex h-full flex-col">
	<div class="border-b px-3 py-3">
		<div class="mb-2 flex items-center justify-between">
			<h2 class="text-sm font-semibold">Servers</h2>
			<Badge variant="outline" class="text-xs">
				{servers.list.filter(servers.online).length} online
			</Badge>
		</div>
		<InputGroupVariants variant="search" bind:value={searchQuery} searchResults={filtered.length} />
	</div>

	<div class="flex-1 overflow-y-auto">
		{#if servers.loading}
			<div class="flex flex-col gap-1 p-2">
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
			<div class="flex flex-col gap-0.5 p-1.5">
				{#each filtered as target (target.id)}
					<ServerRow {target} why={servers.why(target)} />
				{/each}
			</div>
		{/if}
	</div>
</div>
