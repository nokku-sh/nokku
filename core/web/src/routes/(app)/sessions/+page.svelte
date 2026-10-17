<script lang="ts">
	import { getSessions } from '#lib/api/terminal.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import ServerList from './ServerList.svelte';
	import TerminalTabs from './TerminalTabs.svelte';
	import TerminalView from './TerminalView.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ext/empty/index.js';
	import { activeSessionID } from '#lib/store.svelte.js';
	import { PanelLeftClose, PanelLeftOpen, Terminal } from '@lucide/svelte';

	const plan = workspace.plan();

	let panelOpen = $state(true);
</script>

<svelte:head>
	<title>Sessions · Nokku</title>
</svelte:head>

<div class="flex flex-1 overflow-hidden">
	{#if panelOpen}
		<div class="flex w-64 shrink-0 flex-col border-r bg-background">
			<ServerList />
		</div>
	{/if}

	<div class="flex min-w-0 flex-1 flex-col">
		<div class="flex items-center gap-2 border-b px-2 py-1">
			<Button
				variant="ghost"
				size="icon-sm"
				aria-label={panelOpen ? 'Hide servers' : 'Show servers'}
				onclick={() => (panelOpen = !panelOpen)}
			>
				{#if panelOpen}<PanelLeftClose />{:else}<PanelLeftOpen />{/if}
			</Button>
			<div class="flex-1">
				<TerminalTabs />
			</div>
		</div>

		<div class="relative min-h-0 flex-1">
			{#if getSessions().size === 0}
				<Empty.Root class="h-full">
					<Empty.Header>
						<Empty.Media variant="icon">
							<Terminal />
						</Empty.Media>
						<Empty.Title>No open sessions</Empty.Title>
						<Empty.Description>
							{plan.data?.inactive
								? 'Shells open again once the workspace has a plan.'
								: 'Pick a server to open a shell right here, or list them from your own terminal.'}
						</Empty.Description>
					</Empty.Header>
					<Empty.Content>
						{#if !panelOpen}
							<Button variant="outline" onclick={() => (panelOpen = true)}>
								<PanelLeftOpen data-icon="inline-start" />
								Show servers
							</Button>
						{/if}
						<Empty.Command>nk list</Empty.Command>
					</Empty.Content>
				</Empty.Root>
			{:else}
				{#each getSessions() as [id, session] (id)}
					<TerminalView {session} visible={id === activeSessionID.current} />
				{/each}
			{/if}
		</div>
	</div>
</div>
