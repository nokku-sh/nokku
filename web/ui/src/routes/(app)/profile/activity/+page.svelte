<script lang="ts">
	import { page } from '$app/state';
	import { sessionMethodLabel, session } from '$lib/api/session.svelte';
	import { user } from '$lib/api/user.svelte';
	import { util, workspace } from '$lib/api/workspaces.svelte';
	import { areaOf, areas, eventLabel, outcomeOf, setParams } from '$lib/components/audit/audit';
	import RangePicker, { currentRange } from '$lib/components/audit/RangePicker.svelte';
	import ActivitySheet from '$lib/components/sheets/ActivitySheet.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import * as Empty from '$lib/components/ui/empty';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { describeAgent } from '$lib/agent';
	import {
		AuditOutcome,
		ExportAuditLogsRequest_Format,
		type EventLog
	} from '$lib/gen/nokku/v1/util_pb';
	import { formatTs } from '$lib/utils';
	import { timestampDate, timestampFromDate } from '@bufbuild/protobuf/wkt';
	import {
		Activity,
		Download,
		KeyRound,
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

	const exportLogs = util.exportLogs();
	function exportAs(format: ExportAuditLogsRequest_Format) {
		exportLogs.mutate({
			format,
			workspaceId: '',
			filter: { ...rangeFilter, endDate: rangeFilter.endDate ?? timestampFromDate(new Date()) }
		});
	}

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
	icon={Activity}
	title="Your activity"
	description="Your sign-ins and the changes you made, across all your workspaces."
>
	<DropdownMenu.Root>
		<DropdownMenu.Trigger>
			{#snippet child({ props })}
				<Button {...props} variant="outline" disabled={exportLogs.isPending}>
					{#if exportLogs.isPending}
						<Spinner data-icon="inline-start" />
					{:else}
						<Download data-icon="inline-start" />
					{/if}
					Export
				</Button>
			{/snippet}
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align="end">
			<DropdownMenu.Group>
				<DropdownMenu.Item onclick={() => exportAs(ExportAuditLogsRequest_Format.CSV)}>
					CSV
				</DropdownMenu.Item>
				<DropdownMenu.Item onclick={() => exportAs(ExportAuditLogsRequest_Format.JSON)}>
					JSON
				</DropdownMenu.Item>
			</DropdownMenu.Group>
		</DropdownMenu.Content>
	</DropdownMenu.Root>
</PageHeader>

<ActivitySheet log={selected} onClose={() => (selected = undefined)} />

<div class="grid gap-3 md:grid-cols-3">
	<div class="flex flex-col gap-1 rounded-xl border bg-card p-4">
		<span class="flex items-center gap-1.5 text-xs text-muted-foreground">
			<LogIn class="size-3.5" /> Last sign-in
		</span>
		{#if lastLogin.isLoading}
			<Skeleton class="h-10 w-full" />
		{:else if last}
			<span class="flex items-center gap-2 text-sm font-medium">
				{formatTs(last.timestamp, 'relative')}
				{#if method(last)}<Badge variant="secondary">{method(last)}</Badge>{/if}
			</span>
			<span class="truncate text-xs text-muted-foreground">
				{describeAgent(last.userAgent)}{last.ip ? ` · ${last.ip}` : ''}
			</span>
		{:else}
			<span class="text-sm text-muted-foreground">None in the last 90 days</span>
		{/if}
	</div>

	<a
		href="/profile/security"
		class={[
			'flex flex-col gap-1 rounded-xl border bg-card p-4 transition-colors hover:bg-muted/40',
			failed && 'border-destructive/40'
		]}
	>
		<span class="flex items-center gap-1.5 text-xs text-muted-foreground">
			<ShieldAlert class={['size-3.5', failed && 'text-destructive']} /> Failed sign-ins
		</span>
		<span class={['text-xl font-semibold tabular-nums', failed && 'text-destructive']}>
			{failed}
		</span>
		<span class="text-xs text-muted-foreground">{range.label.toLowerCase()}</span>
	</a>

	<a
		href="/profile/security"
		class="flex flex-col gap-1 rounded-xl border bg-card p-4 transition-colors hover:bg-muted/40"
	>
		<span class="flex items-center gap-1.5 text-xs text-muted-foreground">
			<MonitorSmartphone class="size-3.5" /> Signed in on
		</span>
		<span class="text-xl font-semibold tabular-nums">{sessions.data?.length ?? '–'}</span>
		<span class="text-xs text-muted-foreground">
			{sessions.data?.length === 1 ? 'device' : 'devices'}, manage them under Security
		</span>
	</a>
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
				<h3 class="text-xs font-medium tracking-wide text-muted-foreground uppercase">
					{day.label}
				</h3>
				<div class="divide-y overflow-hidden rounded-xl border bg-card">
					{#each day.events as e (e.id)}
						{@const outcome = outcomeOf(e)}
						{@const Icon = areaOf(e.action)?.icon ?? KeyRound}
						<button
							type="button"
							class="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-muted/40"
							onclick={() => (selected = e)}
						>
							<div
								class={[
									'flex size-8 shrink-0 items-center justify-center rounded-lg',
									outcome === 'succeeded'
										? 'bg-muted text-muted-foreground'
										: 'bg-destructive/10 text-destructive'
								]}
							>
								<Icon class="size-4" />
							</div>
							<div class="flex min-w-0 flex-1 flex-col gap-0.5">
								<span class="flex flex-wrap items-center gap-1.5 text-sm font-medium">
									{eventLabel(e.action)}
									{#if method(e)}<Badge variant="secondary">{method(e)}</Badge>{/if}
									{#if outcome !== 'succeeded'}
										<Badge variant="destructive">{outcome === 'denied' ? 'Denied' : 'Failed'}</Badge
										>
									{/if}
									{#if e.workspaceId && workspaceName.get(e.workspaceId)}
										<Badge variant="outline">
											<Layers2 data-icon="inline-start" />
											{workspaceName.get(e.workspaceId)}
										</Badge>
									{/if}
								</span>
								<span class="truncate text-xs text-muted-foreground">
									{describeAgent(e.userAgent)}{e.ip ? ` · ${e.ip}` : ''}
								</span>
							</div>
							<span class="shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
								{e.timestamp
									? timestampDate(e.timestamp).toLocaleTimeString(undefined, {
											hour: '2-digit',
											minute: '2-digit'
										})
									: ''}
							</span>
						</button>
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
