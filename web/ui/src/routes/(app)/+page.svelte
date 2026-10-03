<script lang="ts">
	import { dashboard } from '#lib/api/dashboard.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import GetStarted from '#lib/components/dashboard/GetStarted.svelte';
	import LiveNow from '#lib/components/dashboard/LiveNow.svelte';
	import NeedsYou from '#lib/components/dashboard/NeedsYou.svelte';
	import Pulse from '#lib/components/dashboard/Pulse.svelte';
	import SetupWorkspace from '#lib/components/dashboard/SetupWorkspace.svelte';
	import StatusLine from '#lib/components/dashboard/StatusLine.svelte';
	import YourServers from '#lib/components/dashboard/YourServers.svelte';
	import { issuesOf } from '#lib/components/dashboard/issues.js';
	import JoinModal from '#lib/components/modals/JoinModal.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { atLeast } from '#lib/roles.js';
	import { workspaceID } from '#lib/store.svelte.js';
	import { SquareTerminal } from '@lucide/svelte';

	const me = user.self();
	const ws = workspace.get();
	const role = $derived(ws.data?.role);
	// Members only see their own servers, the overview needs viewer rights.
	const canView = $derived(atLeast(role, 'viewer'));
	const canEdit = $derived(atLeast(role, 'editor'));

	const data = dashboard.get(() => canView);
	const issues = $derived(data.data ? issuesOf(data.data) : []);
	const fresh = $derived(!!data.data && data.data.targets === 0 && data.data.daemons === 0);

	const greeting = $derived.by(() => {
		const h = new Date().getHours();
		return h < 5 ? 'Up late' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
	});
	const first = $derived(me.data?.name?.split(' ')[0]);
</script>

<JoinModal />

{#if !workspaceID.current}
	<SetupWorkspace />
{:else}
	<PageHeader
		title={`${greeting}${first ? `, ${first}` : ''}`}
		description={ws.data ? `Here is how ${ws.data.name} is doing` : undefined}
	>
		<Button href="/sessions">
			<SquareTerminal data-icon="inline-start" />
			Open a shell
		</Button>
	</PageHeader>

	{#if canView}
		<div class="grid gap-6 lg:grid-cols-3">
			<div class="lg:col-span-2">
				<StatusLine
					data={data.data}
					{issues}
					workspace={ws.data?.name ?? ''}
					updatedAt={data.dataUpdatedAt}
				/>
			</div>
			<NeedsYou {issues} loading={data.isLoading} {canEdit} />
		</div>
	{/if}

	{#if fresh}
		<GetStarted workspace={ws.data?.name ?? ''} members={data.data?.members ?? 0} {canEdit} />
	{:else}
		<div class="grid gap-6 lg:grid-cols-3">
			<div class="lg:col-span-2">
				<YourServers showAll={canView} />
			</div>
			{#if canView}
				<LiveNow sessions={data.data?.liveSessions ?? []} loading={data.isLoading} />
			{/if}
		</div>
		{#if canView}
			<Pulse data={data.data} />
		{/if}
	{/if}
{/if}
