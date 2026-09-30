<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { getSessions, type TerminalSession } from '$lib/api/terminal.svelte';
	import StatusDot from '$lib/components/blocks/StatusDot.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { confirm } from '$lib/hooks';
	import { activeSessionID } from '$lib/store.svelte';
	import { statusTone } from '$lib/tone';
	import { X } from '@lucide/svelte';

	const sessions = $derived(getSessions());
	const closeSession = daemon.closeSession();

	const stateLabel: Record<string, string> = {
		connected: 'Connected',
		connecting: 'Connecting',
		disconnected: 'Disconnected',
		error: 'Error'
	};

	function close(id: string, session: TerminalSession) {
		void confirm({
			title: `Close ${session.username}@${session.daemonName}?`,
			description: 'The shell ends and anything still running in it stops.',
			confirmText: 'Close session',
			onConfirm: () => closeSession.mutateAsync({ daemonId: session.daemonID, sessionId: id })
		});
	}
</script>

{#if sessions.size > 0}
	<div class="no-scrollbar flex items-center gap-1 overflow-x-auto" role="tablist">
		{#each sessions.entries() as [id, session] (id)}
			{@const active = id === activeSessionID.current}
			<div
				class={[
					'group flex shrink-0 items-center rounded-md border',
					active ? 'border-border bg-background' : 'border-transparent'
				]}
			>
				<Button
					variant="ghost"
					size="sm"
					role="tab"
					aria-selected={active}
					class={['h-7 gap-2 font-mono text-xs', !active && 'text-muted-foreground']}
					onclick={() => (activeSessionID.current = id)}
				>
					<Tooltip.Root>
						<Tooltip.Trigger>
							{#snippet child({ props })}
								<span {...props}>
									<StatusDot
										tone={statusTone(session.state)}
										live={session.state === 'connecting'}
									/>
								</span>
							{/snippet}
						</Tooltip.Trigger>
						<Tooltip.Content>{stateLabel[session.state ?? ''] ?? 'Unknown'}</Tooltip.Content>
					</Tooltip.Root>
					<span class="max-w-40 truncate">{session.username}@{session.daemonName}</span>
				</Button>
				<Button
					variant="ghost"
					size="icon-xs"
					class={[
						'mr-0.5',
						!active && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100'
					]}
					aria-label={`Close ${session.username}@${session.daemonName}`}
					onclick={() => close(id, session)}
				>
					<X />
				</Button>
			</div>
		{/each}
	</div>
{/if}
