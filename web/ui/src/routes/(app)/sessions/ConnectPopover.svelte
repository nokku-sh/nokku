<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { getSessions, removeSession } from '$lib/api/terminal.svelte';
	import StatusDot from '$lib/components/blocks/StatusDot.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { activeSessionID } from '$lib/store.svelte';
	import { ChevronRight, Plus, SquareTerminal, User, X } from '@lucide/svelte';

	let { target }: { target: Target } = $props();

	const usernames = $derived((target.principals ?? []).map((p) => p.username).filter(Boolean));
	const mine = $derived(
		[...getSessions().entries()].filter(([, s]) => s.daemonID === target.daemonId)
	);

	const createSession = daemon.createSession();

	function connect(username: string) {
		createSession.mutate({ daemonId: target.daemonId, username });
	}
</script>

<Collapsible.Root open={mine.length > 0}>
	<div class="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/50">
		<StatusDot tone="success" class="size-1.5" />
		<Collapsible.Trigger class="min-w-0 flex-1 text-left" disabled={!mine.length}>
			<p class="truncate text-xs font-medium">{target.name}</p>
			{#if target.metadata?.hostname}
				<p class="truncate font-mono text-2xs text-muted-foreground">{target.metadata.hostname}</p>
			{/if}
		</Collapsible.Trigger>
		{#if mine.length}
			<Badge variant="secondary">{mine.length}</Badge>
		{/if}

		{#if usernames.length > 1}
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}
						<Button
							{...props}
							variant="ghost"
							size="icon-xs"
							aria-label={`Connect to ${target.name}`}
							disabled={createSession.isPending}
						>
							{#if createSession.isPending}<Spinner />{:else}<Plus />{/if}
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content side="right" align="start" class="w-48">
					<DropdownMenu.Group>
						<DropdownMenu.Label>Connect as</DropdownMenu.Label>
						{#each usernames as username (username)}
							<DropdownMenu.Item class="font-mono text-xs" onSelect={() => connect(username)}>
								<User />
								{username}
							</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Group>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		{:else if usernames.length === 1}
			<Button
				variant="ghost"
				size="icon-xs"
				aria-label={`Connect to ${target.name} as ${usernames[0]}`}
				disabled={createSession.isPending}
				onclick={() => connect(usernames[0])}
			>
				{#if createSession.isPending}<Spinner />{:else}<Plus />{/if}
			</Button>
		{/if}

		{#if mine.length}
			<ChevronRight
				class="size-4 text-muted-foreground transition-transform in-data-[state=open]:rotate-90"
			/>
		{/if}
	</div>

	<Collapsible.Content>
		<div class="ml-3 flex flex-col border-l py-1 pl-2">
			{#each mine as [id, session] (id)}
				<div class="group flex items-center gap-1">
					<Button
						variant="ghost"
						size="sm"
						class={[
							'h-7 flex-1 justify-start font-mono text-xs',
							id === activeSessionID.current ? 'text-foreground' : 'text-muted-foreground'
						]}
						onclick={() => (activeSessionID.current = id)}
					>
						<SquareTerminal data-icon="inline-start" />
						{session.username}
					</Button>
					<Button
						variant="ghost"
						size="icon-xs"
						class="opacity-0 group-hover:opacity-100 focus-visible:opacity-100"
						aria-label={`Close ${session.username}`}
						onclick={() => removeSession(id)}
					>
						<X />
					</Button>
				</div>
			{/each}
		</div>
	</Collapsible.Content>
</Collapsible.Root>
