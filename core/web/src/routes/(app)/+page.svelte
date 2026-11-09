<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { dashboard } from '#lib/api/dashboard.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { useWaitingRequests } from '#lib/components/access/requests.svelte.js';
	import { openGrant } from '#lib/components/access/grant.svelte.js';
	import EndingSoon from '#lib/components/dashboard/EndingSoon.svelte';
	import GetStarted from '#lib/components/dashboard/GetStarted.svelte';
	import LiveNow from '#lib/components/dashboard/LiveNow.svelte';
	import MemberHome from '#lib/components/dashboard/MemberHome.svelte';
	import NeedsYou from '#lib/components/dashboard/NeedsYou.svelte';
	import Pulse from '#lib/components/dashboard/Pulse.svelte';
	import StatusLine from '#lib/components/dashboard/StatusLine.svelte';
	import { isFresh, issuesOf } from '#lib/components/dashboard/issues.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { atLeast } from '#lib/roles.js';
	import { Plus, SquareTerminal } from '@lucide/svelte';

	const me = user.self();
	const ws = workspace.get();
	// Without a plan nothing signs, so the ways in stay hidden until the owner activates a license key.
	const plan = workspace.plan();
	const inactive = $derived(!!plan.data?.inactive);
	const role = $derived(me.data?.role);
	// Members only see their own servers, the overview needs viewer rights.
	const canView = $derived(atLeast(role, WorkspaceRole.VIEWER));
	const canEdit = $derived(atLeast(role, WorkspaceRole.EDITOR));

	const data = dashboard.get(() => canView, true);
	const waiting = useWaitingRequests(true);
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
	description={ws.data
		? canView
			? `Here is how ${ws.data.name} is doing`
			: `Your servers in ${ws.data.name}, and the ways to reach them`
		: undefined}
>
	{#if !fresh && !inactive && canView}
		<Button variant="outline" href="/shell">
			<SquareTerminal data-icon="inline-start" />
			Open a shell
		</Button>
		{#if canEdit}
			<Button onclick={() => openGrant()}>
				<Plus data-icon="inline-start" />
				Grant access
			</Button>
		{/if}
	{/if}
</PageHeader>

{#if fresh}
	<GetStarted workspace={ws.data?.name ?? ''} connected={false} users={data.data?.users ?? 0} />
{:else if canView}
	<StatusLine
		data={data.data}
		{issues}
		requests={waiting.count}
		workspace={ws.data?.name ?? ''}
		updatedAt={data.dataUpdatedAt}
	/>
	{#if data.data}
		<GetStarted workspace={ws.data?.name ?? ''} connected users={data.data.users} />
	{/if}
	<div class="grid gap-6 lg:grid-cols-3">
		<div class="min-w-0 lg:col-span-2">
			<NeedsYou {issues} requests={waiting.list} loading={data.isLoading} {canEdit} />
		</div>
		<div class="flex min-w-0 flex-col gap-6">
			{#if data.data?.endingGrants.length}
				<EndingSoon grants={data.data.endingGrants} total={data.data.endingGrantsTotal} {canEdit} />
			{/if}
			<LiveNow sessions={data.data?.liveSessions ?? []} loading={data.isLoading} />
		</div>
	</div>
	<Pulse data={data.data} />
{:else if me.data}
	<MemberHome {inactive} />
{/if}
