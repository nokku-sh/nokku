<script lang="ts">
	import ExportMenu from '#lib/components/audit/ExportMenu.svelte';
	import EventRow from '#lib/components/audit/EventRow.svelte';
	import StatTile from '#lib/components/blocks/StatTile.svelte';
	import { page } from '$app/state';
	import { sessionMethodLabel, session } from '#lib/api/session.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { areas, setParams } from '#lib/components/audit/audit.js';
	import RangePicker, { currentRange } from '#lib/components/audit/RangePicker.svelte';
	import ActivitySheet from '#lib/components/sheets/ActivitySheet.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { describeAgent } from '#lib/agent.js';
	import { AuditOutcome, type EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { formatTs } from '#lib/utils.js';
	import { timestampDate, timestampFromDate } from '@bufbuild/protobuf/wkt';
	import {
		Activity,
		Layers2,
		LogIn,
		MonitorSmartphone,
		ShieldAlert,
		TriangleAlert
	} from '@lucide/svelte';

	const signIns = areas.find((a) => a.value === 'signins')!.actions;
	const changes = areas
		.filter((a) => !['signins', 'sessions'].includes(a.value))
		.flatMap((a) => a.actions);

	const views = [
		{ value: 'all', label: 'Everything' },
		{ value: 'signins', label: 'Sign-ins' },
		{ value: 'changes', label: 'Changes' },
		{ value: 'failed', label: 'Failed' }
	];

	const me = user.self();
	const enabled = $derived(!!me.data?.id);
	const view = $derived(page.url.searchParams.get('view') ?? 'all');
	const range = $derived(currentRange(false));
	const rangeFilter = $derived({ startDate: range.startDate, endDate: range.endDate });

	const feed = user.activityFeed(() => ({
		enabled,
		key: [view, page.url.searchParams.get('range') ?? '', page.url.searchParams.get('from') ?? ''],
		filter: {
			...rangeFilter,
			actions: view === 'signins' ? signIns : view === 'changes' ? changes : [],
			outcome: view === 'failed' ? AuditOutcome.FAILED : AuditOutcome.UNSPECIFIED
		}
	}));
	const events = $derived(feed.data?.pages.flatMap((p) => p.logs) ?? []);
	const total = $derived(feed.data?.pages[0]?.total ?? 0);

	// The summary looks at the last 90 days, independent of the timeline filters.
	const since = timestampFromDate(new Date(Date.now() - 90 * 24 * 3600_000));
	const lastLogin = user.activity(() => ({
		enabled,
		limit: 1,
		filter: { actions: ['Login'], outcome: AuditOutcome.SUCCEEDED, startDate: since }
	}));
	const failedLogins = user.activity(() => ({
		enabled,
		limit: 1,
		filter: { ...rangeFilter, actions: signIns, outcome: AuditOutcome.FAILED }
	}));
	const sessions = session.list();
	const workspaces = workspace.list();
	const workspaceName = $derived(new Map((workspaces.data ?? []).map((w) => [w.id, w.name])));

	const last = $derived(lastLogin.data?.logs[0]);
	const failed = $derived(failedLogins.data?.total ?? 0);

	function dayLabel(date: Date) {
		const yesterday = new Date(Date.now() - 24 * 3600_000);
		if (date.toDateString() === new Date().toDateString()) return 'Today';
		if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
		return date.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
	}

	const days = $derived.by(() => {
		const groups: { label: string; events: EventLog[] }[] = [];
		for (const e of events) {
			const label = e.timestamp ? dayLabel(timestampDate(e.timestamp)) : 'Unknown';
			const current = groups.at(-1);
			if (current?.label === label) current.events.push(e);
			else groups.push({ label, events: [e] });
		}
		return groups;
	});

	const method = (e: EventLog) => {
		const m = e.details?.['method'];
		return typeof m === 'string' && m ? sessionMethodLabel(m) : undefined;
	};

	let selected = $state<EventLog>();
</script>

<PageHeader
	title="Your activity"
	description="Your sign-ins and the changes you made, across all your workspaces"
>
	<ExportMenu filter={rangeFilter} workspaceId="" />
</PageHeader>

<ActivitySheet log={selected} onClose={() => (selected = undefined)} />

<div class="grid gap-3 md:grid-cols-3">
	<StatTile
		label="Last sign-in"
		icon={LogIn}
		loading={lastLogin.isLoading}
		hint={last ? `${describeAgent(last.userAgent)}${last.ip ? ` · ${last.ip}` : ''}` : undefined}
	>
		{#if last}
			<span class="flex items-center gap-2 text-sm font-medium">
				{formatTs(last.timestamp, 'relative')}
				{#if method(last)}<Badge variant="secondary">{method(last)}</Badge>{/if}
			</span>
		{:else}
			<span class="text-sm text-muted-foreground">None in the last 90 days</span>
		{/if}
	</StatTile>
	<StatTile
		label="Failed sign-ins"
		icon={ShieldAlert}
		href="/profile/security"
		value={failed}
		tone={failed ? 'destructive' : undefined}
		hint={range.label.toLowerCase()}
	/>
	<StatTile
		label="Signed in on"
		icon={MonitorSmartphone}
		href="/profile/security"
		value={sessions.data?.length ?? '–'}
		hint={`${sessions.data?.length === 1 ? 'device' : 'devices'}, manage them under Security`}
	/>
</div>

{#if failed}
	<Alert.Root variant="destructive">
		<TriangleAlert />
		<Alert.Title>Sign-in attempts failed</Alert.Title>
		<Alert.Description>
			If that wasn't you, change your password and sign out the devices you don't recognize.
		</Alert.Description>
		<Alert.Action>
			<Button size="sm" variant="outline" href="/profile/security">Review security</Button>
		</Alert.Action>
	</Alert.Root>
{/if}

<div class="flex flex-wrap items-center justify-between gap-3">
	<ToggleGroup.Root
		type="single"
		variant="outline"
		size="sm"
		value={view}
		onValueChange={(v) => v && setParams({ view: v === 'all' ? undefined : v })}
		aria-label="Show"
	>
		{#each views as v (v.value)}
			<ToggleGroup.Item value={v.value}>{v.label}</ToggleGroup.Item>
		{/each}
	</ToggleGroup.Root>
	<RangePicker utc={false} />
</div>

{#if feed.isLoading}
	<div class="flex flex-col gap-2">
		{#each { length: 5 }, i (i)}
			<Skeleton class="h-14 w-full rounded-xl" />
		{/each}
	</div>
{:else if !events.length}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon"><Activity /></Empty.Media>
			<Empty.Title>Nothing here</Empty.Title>
			<Empty.Description>No activity matches this view and range.</Empty.Description>
		</Empty.Header>
	</Empty.Root>
{:else}
	<div class="flex flex-col gap-5">
		{#each days as day (day.label)}
			<section class="flex flex-col gap-2">
				<h3 class="spec-label">
					{day.label}
				</h3>
				<div class="divide-y overflow-hidden rounded-xl border bg-card">
					{#each day.events as e (e.id)}
						<EventRow log={e} onclick={() => (selected = e)} meta={formatTs(e.timestamp, 'time')}>
							{#snippet badges()}
								{#if e.workspaceId && workspaceName.get(e.workspaceId)}
									<Badge variant="outline">
										<Layers2 data-icon="inline-start" />
										{workspaceName.get(e.workspaceId)}
									</Badge>
								{/if}
							{/snippet}
						</EventRow>
					{/each}
				</div>
			</section>
		{/each}

		<div class="flex justify-center">
			{#if feed.hasNextPage}
				<Button
					variant="outline"
					size="sm"
					disabled={feed.isFetchingNextPage}
					onclick={() => feed.fetchNextPage()}
				>
					{#if feed.isFetchingNextPage}<Spinner data-icon="inline-start" />{/if}
					Load more
				</Button>
			{:else}
				<p class="text-xs text-muted-foreground">
					That's all {total}
					{total === 1 ? 'event' : 'events'} in this range.
				</p>
			{/if}
		</div>
	</div>
{/if}
