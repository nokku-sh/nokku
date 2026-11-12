<script lang="ts">
	import { serverMatches, useServers } from '#lib/api/connect.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { openGrant } from '#lib/components/access/grant.svelte.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { displayName } from '#lib/utils.js';
	import { Server, UserPlus } from '@lucide/svelte';
	import ServerRow from './ServerRow.svelte';

	const servers = useServers();
	const me = user.self();
	const can = user.can();

	// The list holds the servers the caller has a login account on, which may be none even for the owner.
	function grantMyself() {
		const u = me.data;
		if (!u) return;
		openGrant({
			subjects: [
				{ id: u.id, kind: SubjectKind.USER, name: displayName(u), detail: u.email, user: u }
			]
		});
	}

	let searchQuery = $state('');

	const filtered = $derived(servers.list.filter((t) => serverMatches(t, searchQuery)));
</script>

<div class="flex h-full flex-col">
	<div class="border-b px-3 py-3">
		<div class="mb-2 flex items-center justify-between">
			<h2 class="text-sm font-semibold">Your servers</h2>
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
					<Empty.Title class="text-sm">
						{searchQuery ? 'No matches' : 'No login account yet'}
					</Empty.Title>
					{#if !searchQuery}
						<Empty.Description>
							This lists the servers you have a login account on.
							{can.edit ? 'Grant yourself one to open a shell.' : 'Ask an admin for access.'}
						</Empty.Description>
					{/if}
				</Empty.Header>
				{#if !searchQuery && can.edit}
					<Empty.Content>
						<Button size="sm" onclick={grantMyself}>
							<UserPlus data-icon="inline-start" />
							Grant yourself access
						</Button>
					</Empty.Content>
				{/if}
			</Empty.Root>
		{:else}
			<div class="flex flex-col gap-0.5 p-1.5">
				{#each filtered as target (target.id)}
					<ServerRow {target} why={servers.why(target)} records={servers.records(target)} />
				{/each}
			</div>
		{/if}
	</div>
</div>
