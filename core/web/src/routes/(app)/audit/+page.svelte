<script lang="ts">
	import { auditStreams } from '#lib/api/audit-streams.svelte.js';
	import { plural } from '#lib/api/bulk.js';
	import ExportMenu from '#lib/components/blocks/ExportMenu.svelte';
	import AuditStreams from '#lib/components/audit/AuditStreams.svelte';
	import { page } from '$app/state';
	import { util } from '#lib/api/workspaces.svelte.js';
	import ActivitySheet from '#lib/components/sheets/ActivitySheet.svelte';
	import { DataTable, TableToolbar, createAppColumnHelper } from '#lib/components/tables/index.js';
	import { MachineCell, TimeCell } from '#lib/components/tables/cells/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import {
		AuditOutcome,
		ExportAuditLogsRequest_Format,
		type EventLog
	} from '#lib/gen/nokku/v1/util_pb.js';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { usePagination } from '#lib/hooks/index.js';
	import { auditUTC } from '#lib/store.svelte.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import { Archive, FileClock, Lock, Radio, Target } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import ActorCell from './ActorCell.svelte';
	import ActorFilter from './ActorFilter.svelte';
	import {
		actorKinds,
		areas,
		csv,
		eventLabel,
		eventSource,
		outcomes,
		quickViews,
		setParams
	} from '#lib/components/audit/audit.js';
	import EventCell from './EventCell.svelte';
	import RangePicker, { currentRange } from '#lib/components/audit/RangePicker.svelte';

	let selected = $state<EventLog>();

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
	const streams = auditStreams.list();
	const live = $derived((streams.data ?? []).filter((s) => s.enabled));
	const failing = $derived(live.some((s) => s.lastError));
	const exportLogs = util.exportLogs();

	// Exports need both bounds, an open ended range ends now.
	function exportAs(format: ExportAuditLogsRequest_Format) {
		exportLogs.mutate({
			format,
			filter: { ...filter, endDate: filter.endDate ?? timestampFromDate(new Date()) }
		});
	}
	const target = $derived(page.url.searchParams.get('target'));

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
			meta: { hideBelow: 'md' },
			cell: ({ row }) => renderComponent(MachineCell, { value: eventSource(row.original) })
		})
	]);
</script>

<PageHeader
	title="Audit log"
	description="Every change and sign-in in this workspace, who did it and from where"
>
	<AuditStreams />
	<ExportMenu
		hint="Exactly what is on screen, up to 90 days"
		feature="audit_export"
		pending={exportLogs.isPending}
		onExport={exportAs}
	/>
</PageHeader>

<ul
	aria-label="About this log"
	class="flex flex-wrap gap-x-6 gap-y-1.5 text-sm text-muted-foreground"
>
	<li class="flex items-center gap-1.5">
		<Lock class="size-3.5" />
		Append-only, an event can't be changed or removed
	</li>
	{#if logs.data?.retentionDays}
		<li class="flex items-center gap-1.5">
			<Archive class="size-3.5" />
			Kept {logs.data.retentionDays} days
		</li>
	{/if}
	{#if streams.data}
		<li class={['flex items-center gap-1.5', failing && 'text-destructive']}>
			<Radio class="size-3.5" />
			{failing
				? 'A stream is failing, open Streaming'
				: live.length
					? `Streamed to ${plural(live.length, 'destination')} as it happens`
					: 'Not streamed anywhere'}
		</li>
	{/if}
</ul>

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
	error={logs.error}
	onRetry={logs.refetch}
	rowLabel={(log) => `${eventLabel(log.action)} by ${log.actorName || 'unknown'}`}
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
			searchPlaceholder="Search events, people, servers..."
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
					title="Only events about this"
					onRemove={() => setParams({ target: undefined })}
					removeLabel="Clear this filter"
				>
					{#snippet leading()}
						<Target class="ml-2 size-3 text-muted-foreground" />
					{/snippet}
				</Chip>
			{/if}
		</TableToolbar>
	{/snippet}
</DataTable>
