<script lang="ts">
	import { getSessions } from '$lib/api/terminal.svelte';
	import ServerList from './ServerList.svelte';
	import TerminalTabs from './TerminalTabs.svelte';
	import TerminalView from './TerminalView.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Empty from '$lib/components/ui/empty';
	import { activeSessionID } from '$lib/store.svelte';
	import { PanelLeftClose, PanelLeftOpen, Terminal } from '@lucide/svelte';

	let panelOpen = $state(true);
</script>

<svelte:head>
	<title>Sessions</title>
</svelte:head>

<div class="flex flex-1 overflow-hidden">
	{#if panelOpen}
		<div class="flex w-64 shrink-0 flex-col border-r bg-background">
			<ServerList />
		</div>
	{/if}

	<div class="flex min-w-0 flex-1 flex-col">
		<div class="flex items-center gap-2 border-b px-2 py-1">
			<Button variant="ghost" size="icon" class="size-7" onclick={() => (panelOpen = !panelOpen)}>
				{#if panelOpen}
					<PanelLeftClose class="size-4" />
				{:else}
					<PanelLeftOpen class="size-4" />
				{/if}
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
						<Empty.Title>No Active Sessions</Empty.Title>
						<Empty.Description>
							{#if panelOpen}
								Select a server from the panel to start a terminal session.
							{:else}
								Open the server panel to connect to a server.
							{/if}
						</Empty.Description>
					</Empty.Header>
					{#if !panelOpen}
						<Empty.Content>
							<Button variant="outline" onclick={() => (panelOpen = true)}>
								<PanelLeftOpen class="mr-2 size-4" />
								Open Server Panel
							</Button>
						</Empty.Content>
					{/if}
				</Empty.Root>
			{:else}
				{#each getSessions() as [id, session]}
					<TerminalView {session} visible={id === activeSessionID.current} />
				{/each}
			{/if}
		</div>
	</div>
</div>
