<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { dashboard } from '#lib/api/dashboard.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import GetIn from '#lib/components/dashboard/GetIn.svelte';
	import GetStarted from '#lib/components/dashboard/GetStarted.svelte';
	import LiveNow from '#lib/components/dashboard/LiveNow.svelte';
	import NeedsYou from '#lib/components/dashboard/NeedsYou.svelte';
	import Pulse from '#lib/components/dashboard/Pulse.svelte';
	import StatusLine from '#lib/components/dashboard/StatusLine.svelte';
	import YourServers from '#lib/components/dashboard/YourServers.svelte';
	import { isFresh, issuesOf } from '#lib/components/dashboard/issues.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { atLeast } from '#lib/roles.js';
	import { SquareTerminal } from '@lucide/svelte';

	const me = user.self();
	const ws = workspace.get();
	const role = $derived(me.data?.role);
	// Members only see their own servers, the overview needs viewer rights.
	const canView = $derived(atLeast(role, WorkspaceRole.VIEWER));
	const canEdit = $derived(atLeast(role, WorkspaceRole.EDITOR));

	const data = dashboard.get(() => canView);
	const issues = $derived(data.data ? issuesOf(data.data) : []);
	// Until something is enrolled, setup is the whole dashboard.
	const fresh = $derived(isFresh(data.data));

	const greeting = $derived.by(() => {
		const h = new Date().getHours();
		return h < 5 ? 'Up late' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
	});
	const first = $derived(me.data?.name?.split(' ')[0]);
</script>

<PageHeader
	title={`${greeting}${first ? `, ${first}` : ''}`}
	description={ws.data ? `Here is how ${ws.data.name} is doing` : undefined}
>
	{#if !fresh}
		<Button href="/sessions">
			<SquareTerminal data-icon="inline-start" />
			Open a shell
		</Button>
	{/if}
</PageHeader>

{#if fresh}
	<GetStarted workspace={ws.data?.name ?? ''} connected={false} users={data.data?.users ?? 0} />
{:else}
	{#if canView}
		<div class="grid gap-6 lg:grid-cols-3">
			<div class="min-w-0 lg:col-span-2">
				<StatusLine
					data={data.data}
					{issues}
					workspace={ws.data?.name ?? ''}
					updatedAt={data.dataUpdatedAt}
				/>
			</div>
			<div class="min-w-0">
				<NeedsYou {issues} loading={data.isLoading} {canEdit} />
			</div>
		</div>
		{#if data.data}
			<GetStarted workspace={ws.data?.name ?? ''} connected users={data.data.users} />
		{/if}
	{:else if me.data}
		<GetIn />
	{/if}

	<div class="grid gap-6 lg:grid-cols-3">
		<div class="min-w-0 lg:col-span-2">
			<YourServers showAll={canView} />
		</div>
		{#if canView}
			<div class="min-w-0">
				<LiveNow sessions={data.data?.liveSessions ?? []} loading={data.isLoading} />
			</div>
		{/if}
	</div>
	{#if canView}
		<Pulse data={data.data} />
	{/if}
{/if}
