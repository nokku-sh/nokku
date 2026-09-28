<script lang="ts">
	import * as Popover from '$lib/components/ui/popover';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { ChevronRight, DotIcon, Plus, TerminalIcon, User, XIcon } from '@lucide/svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { daemon } from '$lib/api/daemons.svelte';
	import { activeSessionID } from '$lib/store.svelte';
	import { getSessions } from '$lib/api/terminal.svelte';
	import { onMount } from 'svelte';

	interface Props {
		target: Target;
	}
	let { target }: Props = $props();

	let sessions = getSessions();
	let principals = $derived(target?.principals || []);

	const createSession = daemon.createSession();
	const closeSession = daemon.closeSession();

	let popoverOpen = $state(false);

	function connectDefault() {
		const username = principals[0].username;
		if (username) {
			createSession.mutate({ daemonId: target.daemonId, username });
		}
	}

	function connectAs(username: string) {
		createSession.mutate({ daemonId: target.daemonId, username });
		popoverOpen = false;
	}

	onMount(() => {
		daemon.listSessions(target.daemonId);
	});
</script>

<Collapsible.Root class="rounded-xl" open={sessions.size > 0}>
	<div
		class="group relative z-10 flex w-full items-center gap-1 rounded-xl bg-background px-2 shadow-md"
	>
		<Collapsible.Trigger
			class="flex min-w-0 flex-1 items-center gap-1 py-1.5 text-left text-sm"
			disabled={sessions.size === 0}
		>
			<DotIcon size={28} class="shrink-0 text-emerald-500" />
			<div class="min-w-0 flex-1">
				<p class="truncate text-xs font-medium">{target?.name}</p>
				{#if target?.metadata?.hostname}
					<p class="truncate text-[10px] text-muted-foreground">{target.metadata.hostname}</p>
				{/if}
			</div>
		</Collapsible.Trigger>

		<!-- Right side: session count + connect button -->
		<div class="flex shrink-0 items-center gap-1.5">
			{#if sessions.size > 0}
				<Badge variant="secondary" class="text-[10px]">{sessions.size}</Badge>
			{/if}

			{#if principals.length > 1}
				<Popover.Root bind:open={popoverOpen}>
					<Popover.Trigger>
						{#if createSession.isPending}
							<Spinner class="size-3.5" />
						{:else}
							<Button variant="ghost" size="icon" class="size-7">
								<Plus size={14} />
							</Button>
						{/if}
					</Popover.Trigger>
					<Popover.Content side="right" align="start" class="w-48 p-1">
						<p class="px-2 py-1.5 text-xs font-medium text-muted-foreground">Connect as</p>
						{#each principals.map((p) => p.username) || [] as username}
							<Button
								variant="ghost"
								size="sm"
								class="w-full justify-start gap-2 text-xs"
								disabled={createSession.isPending}
								onclick={() => connectAs(username)}
							>
								<User class="size-3" />
								{username}
							</Button>
						{/each}
					</Popover.Content>
				</Popover.Root>
			{:else}
				<Button
					variant="ghost"
					size="icon"
					class="size-7"
					disabled={createSession.isPending}
					onclick={connectDefault}
				>
					{#if createSession.isPending}
						<Spinner class="size-3.5" />
					{:else}
						<Plus size={14} />
					{/if}
				</Button>
			{/if}

			{#if sessions.size > 0}
				<ChevronRight class="transition-transform group-has-[state=open]:rotate-90" size={16} />
			{/if}
		</div>
	</div>

	<Collapsible.Content class="-mt-2 rounded-b-xl bg-card text-sm transition-all duration-300">
		<div class="ml-6 border-l border-border pt-4 pb-2" hidden={sessions.size === 0}>
			{#each getSessions().entries() as [id, session]}
				<div class="flex items-center justify-between rounded-lg px-4 py-2 hover:bg-muted">
					<button
						class="flex w-full items-center gap-1.5 rounded text-[11px] text-muted-foreground"
						onclick={() => (activeSessionID.current = id)}
					>
						<TerminalIcon size={14} />
						<span class="truncate">{session.username}</span>
					</button>

					<button
						class="hover:text-destructive"
						onclick={() => closeSession.mutate({ daemonId: target.daemonId, sessionId: id })}
					>
						<XIcon size={14} />
					</button>
				</div>
			{/each}
		</div>
	</Collapsible.Content>
</Collapsible.Root>
