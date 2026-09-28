<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { getSessions, type ConnectionState } from '$lib/api/terminal.svelte';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { activeSessionID } from '$lib/store.svelte';
	import { X } from '@lucide/svelte';

	const sessions = $derived(getSessions());

	const closeSession = daemon.closeSession();
	function stateColor(state?: ConnectionState): string {
		switch (state) {
			case 'connected':
				return 'bg-success';
			case 'connecting':
				return 'bg-warning animate-pulse';
			case 'disconnected':
				return 'bg-gray-400';
			case 'error':
				return 'bg-destructive';
			default:
				return 'bg-gray-400';
		}
	}

	function stateLabel(state?: ConnectionState): string {
		switch (state) {
			case 'connected':
				return 'Connected';
			case 'connecting':
				return 'Connecting...';
			case 'disconnected':
				return 'Disconnected';
			case 'error':
				return 'Error';
			default:
				return 'Unknown';
		}
	}
</script>

{#if sessions.size > 0}
	<div class="flex items-center gap-0.5 border-b bg-muted/30 px-1">
		{#each sessions.entries() as [id, session]}
			{@const isActive = id === activeSessionID.current}
			<div class="group relative flex items-center">
				<button
					class="flex items-center gap-1.5 border-b-2 px-3 py-1.5 text-xs transition-colors {isActive
						? 'border-primary bg-background text-foreground'
						: 'border-transparent text-muted-foreground hover:bg-accent hover:text-foreground'}"
					onclick={() => (activeSessionID.current = id)}
				>
					<Tooltip.Provider>
						<Tooltip.Root>
							<Tooltip.Trigger>
								<span class="size-1.5 rounded-full {stateColor(session.state)}"></span>
							</Tooltip.Trigger>
							<Tooltip.Content>
								<p class="text-xs">{stateLabel(session.state)}</p>
							</Tooltip.Content>
						</Tooltip.Root>
					</Tooltip.Provider>
					<span class="max-w-30 truncate">{session.daemonName}@{session.username}</span>
				</button>
				<button
					class="ml-0.5 rounded p-0.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:bg-accent hover:text-foreground {isActive
						? 'opacity-100'
						: ''}"
					onclick={(e) => {
						e.stopPropagation();
						closeSession.mutate({ daemonId: session.daemonID, sessionId: id });
					}}
				>
					<X class="size-3" />
				</button>
			</div>
		{/each}
	</div>
{/if}
