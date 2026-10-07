<script lang="ts">
	import { serverMatches, useConnect, useServers } from '#lib/api/connect.svelte.js';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import * as Kbd from '#lib/components/ui/kbd/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { focusOnSlash } from '#lib/hooks/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Search, Server } from '@lucide/svelte';

	let { showAll = false }: { showAll?: boolean } = $props();

	const LIMIT = 9;

	const connect = useConnect();
	const all = useServers();

	let query = $state('');

	const servers = $derived(all.list.filter((t) => serverMatches(t, query)));
	const visible = $derived(query ? servers : servers.slice(0, LIMIT));
</script>

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title>Your servers</Card.Title>
		<Card.Description>Click an account to open a shell, or copy its ssh command.</Card.Description>
		<Card.Action>
			<InputGroup.Root class="w-44 sm:w-56">
				<InputGroup.Input
					bind:value={query}
					placeholder="Filter"
					aria-label="Filter servers"
					{@attach focusOnSlash}
				/>
				<InputGroup.Addon><Search /></InputGroup.Addon>
				<InputGroup.Addon align="inline-end"><Kbd.Root>/</Kbd.Root></InputGroup.Addon>
			</InputGroup.Root>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if all.loading}
			<div class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
				{#each { length: 6 }, i (i)}<Skeleton class="h-24 w-full" />{/each}
			</div>
		{:else if !servers.length}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon"><Server /></Empty.Media>
					<Empty.Title>{query ? 'No server matches' : 'No servers for you yet'}</Empty.Title>
					<Empty.Description>
						{query ? 'Try a name, host or account.' : 'An admin grants you an account on a target.'}
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
				{#each visible as t (t.id)}
					{@const shell = all.canShell(t)}
					<div
						class="flex min-w-0 flex-col gap-2 rounded-lg border p-3 transition-colors hover:bg-muted/40"
					>
						<div class="flex min-w-0 items-center gap-2">
							<StatusDot tone={shell ? 'success' : 'muted'} />
							<span class="truncate font-medium">{t.name}</span>
							{#if !t.daemonId}<Badge variant="muted" class="ml-auto">nk sync</Badge>{/if}
						</div>
						<span class="truncate font-mono text-xs text-muted-foreground">
							{t.metadata?.hostname || t.endpoints[0] || 'no address yet'}
						</span>
						<div class="flex flex-wrap gap-1">
							{#each t.usernames as username (username)}
								<Tooltip.Root>
									<Tooltip.Trigger>
										{#snippet child({ props })}
											<Button
												{...props}
												size="xs"
												variant="secondary"
												class="font-mono"
												disabled={connect.pending}
												onclick={() =>
													shell ? connect.shell(t, username) : connect.copy(t, username)}
											>
												{username}
											</Button>
										{/snippet}
									</Tooltip.Trigger>
									<Tooltip.Content>
										{shell ? 'Open a shell in the browser' : `Copy ssh ${username}@${t.name}`}
									</Tooltip.Content>
								</Tooltip.Root>
							{/each}
						</div>
					</div>
				{/each}
			</div>
			{#if !query && servers.length > LIMIT}
				<p class="mt-3 text-xs text-muted-foreground">
					{servers.length - LIMIT} more, filter to find them{#if showAll}, or
						<a href="/infrastructure/targets" class="text-primary hover:underline"
							>see all targets</a
						>{/if}.
				</p>
			{/if}
		{/if}
	</Card.Content>
</Card.Root>
