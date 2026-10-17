<script lang="ts">
	import { useConnect } from '#lib/api/connect.svelte.js';
	import { getSessions, removeSession } from '#lib/api/terminal.svelte.js';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { activeSessionID } from '#lib/store.svelte.js';
	import { ChevronRight, Copy, Plus, SquareTerminal, User, X } from '@lucide/svelte';

	interface Props {
		target: Target;
		/** Why a web shell does not work, unset when it does. The row then copies the ssh command. */
		why: string | undefined;
	}

	let { target, why }: Props = $props();

	const shell = $derived(!why);

	const usernames = $derived(target.usernames);
	const mine = $derived(
		[...getSessions().entries()].filter(([, s]) => !!s.daemonID && s.daemonID === target.daemonId)
	);

	const connect = useConnect();
	const run = (username: string) =>
		shell ? connect.shell(target, username) : connect.copy(target, username);
	const label = (username: string) =>
		shell ? `Open a shell on ${target.name} as ${username}` : `Copy ssh ${username}@${target.name}`;
</script>

{#snippet actionIcon()}
	{#if connect.pending}<Spinner />{:else if shell}<Plus />{:else}<Copy />{/if}
{/snippet}

<Collapsible.Root open={mine.length > 0}>
	<div class="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/50">
		<StatusDot tone={shell ? 'success' : 'muted'} class="size-1.5" />
		<Collapsible.Trigger class="min-w-0 flex-1 text-left" disabled={!mine.length}>
			<p class={['truncate text-xs font-medium', !shell && 'text-muted-foreground']}>
				{target.name}
			</p>
			<p class="truncate font-mono text-2xs text-muted-foreground">
				{shell ? target.metadata?.hostname || target.endpoints[0] : why}
			</p>
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
							aria-label={shell ? `Open a shell on ${target.name}` : `Copy ssh for ${target.name}`}
							disabled={connect.pending}
						>
							{@render actionIcon()}
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content side="right" align="start" class="w-48">
					<DropdownMenu.Group>
						<DropdownMenu.Label>{shell ? 'Open a shell as' : 'Copy SSH command'}</DropdownMenu.Label
						>
						{#each usernames as username (username)}
							<DropdownMenu.Item class="font-mono text-xs" onSelect={() => run(username)}>
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
				aria-label={label(usernames[0])}
				title={label(usernames[0])}
				disabled={connect.pending}
				onclick={() => run(usernames[0])}
			>
				{@render actionIcon()}
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
