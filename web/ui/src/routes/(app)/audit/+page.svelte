<script lang="ts">
	import { Badge } from '#lib/components/ext/badge/index.js';
	import ExportMenu from '#lib/components/audit/ExportMenu.svelte';
	import { page } from '$app/state';
	import { user } from '#lib/api/user.svelte.js';
	import { util, workspace } from '#lib/api/workspaces.svelte.js';
	import ActivitySheet from '#lib/components/sheets/ActivitySheet.svelte';
	import { DataTable, TableToolbar, createAppColumnHelper } from '#lib/components/tables/index.js';
	import { TextCell, TimeCell } from '#lib/components/tables/cells/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { AuditOutcome, type EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { usePagination } from '#lib/hooks/index.js';
	import { auditUTC } from '#lib/store.svelte.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import { Archive, FileClock, Radio, Target } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import ActorCell from './ActorCell.svelte';
	import ActorFilter from './ActorFilter.svelte';
	import {
		actorKinds,
		areas,
		csv,
		outcomes,
		quickViews,
		setParams
	} from '#lib/components/audit/audit.js';
	import EventCell from './EventCell.svelte';
	import RangePicker, { currentRange } from '#lib/components/audit/RangePicker.svelte';

	let selected = $state<EventLog>();

	const ws = workspace.get();
	const can = user.can();
	const pager = usePagination();
	const search = new Debounced(() => page.url.searchParams.get('q') ?? '', 300);
	const range = $derived(currentRange(auditUTC.current));

	// Everything on screen, the export sends the same filter.
	const filter = $derived({
		search: search.current,
		actorIds: csv('actor'),
		actorKinds: csv('kind'),
		actions: areas.filter((a) => csv('area').includes(a.value)).flatMap((a) => a.actions),
		target: page.url.searchParams.get('target') ?? '',
		outcome:
			outcomes.find((o) => o.value === page.url.searchParams.get('outcome'))?.enum ??
			AuditOutcome.UNSPECIFIED,
		startDate: range.startDate,
		endDate: range.endDate
	});

	const logs = util.getLogs(() => ({ ...pager.args, filter }));
	const target = $derived(page.url.searchParams.get('target'));
	const streaming = $derived(!!ws.data?.settings?.auditWebhookUrl);

	const activeView = $derived.by(() => {
		const active = ['q', 'area', 'outcome', 'kind', 'actor', 'target'].filter((p) =>
			page.url.searchParams.has(p)
		);
		return quickViews.find((v) => {
			const keys = Object.keys(v.params);
			return (
				keys.length === active.length &&
				keys.every((k) => page.url.searchParams.get(k) === v.params[k])
			);
		})?.label;
	});

	const columnHelper = createAppColumnHelper<EventLog>();
	const columns = columnHelper.columns([
		columnHelper.accessor('timestamp', {
			header: 'Time',
			cell: ({ row }) =>
				renderComponent(TimeCell, {
					ts: row.original.timestamp,
					precise: true,
					utc: auditUTC.current
				})
		}),
		columnHelper.accessor('action', {
			header: 'Event',
			cell: ({ row }) => renderComponent(EventCell, { log: row.original })
		}),
		columnHelper.accessor('actorName', {
			header: 'Actor',
			cell: ({ row }) => renderComponent(ActorCell, { log: row.original })
		}),
		columnHelper.accessor('ip', {
			header: 'Source',
			cell: ({ row }) => renderComponent(TextCell, { label: row.original.ip || '-', mono: true })
		})
	]);
</script>

<PageHeader
	title="Audit log"
	description="Every change and sign-in in this workspace, who did it and from where"
>
	{#if logs.data?.retentionDays}
		<Badge variant="outline">
			<Archive data-icon="inline-start" />
			Kept {logs.data.retentionDays} days
		</Badge>
	{/if}
	<!-- Other roles never learn the destination, so they can't tell either way. -->
	{#if can.admin}
		<Badge variant={streaming ? 'success' : 'outline'} href="/settings/audit">
			<Radio data-icon="inline-start" />
			{streaming ? 'Streaming to SIEM' : 'Not streaming'}
		</Badge>
	{/if}
	<ExportMenu {filter} />
</PageHeader>

<div class="flex flex-wrap items-center justify-between gap-3">
	<ToggleGroup.Root
		type="single"
		variant="outline"
		size="sm"
		value={activeView ?? ''}
		class="flex-wrap"
		aria-label="Quick views"
	>
		{#each quickViews as view (view.label)}
			<ToggleGroup.Item value={view.label} onclick={() => setParams(view.params, true)}>
				{view.label}
			</ToggleGroup.Item>
		{/each}
	</ToggleGroup.Root>

	<div class="flex items-center gap-2">
		<RangePicker utc={auditUTC.current} />
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			value={auditUTC.current ? 'utc' : 'local'}
			onValueChange={(v) => v && (auditUTC.current = v === 'utc')}
			aria-label="Time zone"
		>
			<ToggleGroup.Item value="local">Local</ToggleGroup.Item>
			<ToggleGroup.Item value="utc">UTC</ToggleGroup.Item>
		</ToggleGroup.Root>
	</div>
</div>

<ActivitySheet log={selected} onClose={() => (selected = undefined)} />

<DataTable
	data={logs.data?.logs ?? []}
	{columns}
	rowCount={logs.data?.total ?? 0}
	isLoading={logs.isLoading}
	onRowClick={(log) => (selected = log)}
	emptyState={{
		icon: FileClock,
		title: 'Nothing happened yet',
		description: 'Changes, sign-ins and sessions show up here as they happen.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			{table}
			search
			searchPlaceholder="Search events, actors, targets..."
			searchResultCount={logs.data?.total}
			extraParams={['actor', 'target']}
			filters={[
				{ title: 'Area', options: areas, param: 'area' },
				{ title: 'Outcome', options: outcomes, param: 'outcome', mode: 'single' },
				{ title: 'Actor type', options: actorKinds, param: 'kind' }
			]}
		>
			<ActorFilter />
			{#if target}
				<Chip
					label={target}
					mono
					title="Only events for this target"
					onRemove={() => setParams({ target: undefined })}
					removeLabel="Clear target filter"
				>
					{#snippet leading()}
						<Target class="ml-2 size-3 text-muted-foreground" />
					{/snippet}
				</Chip>
			{/if}
		</TableToolbar>
	{/snippet}
</DataTable>
