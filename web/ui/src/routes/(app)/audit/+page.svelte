<script lang="ts">
	import { page } from '$app/state';
	import { util, workspace } from '$lib/api/workspaces.svelte';
	import ActivitySheet from '$lib/components/sheets/ActivitySheet.svelte';
	import { DataTable, TableToolbar, createAppColumnHelper } from '$lib/components/tables';
	import { TextCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';
	import Chip from '$lib/components/utils/Chip.svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import {
		AuditOutcome,
		ExportAuditLogsRequest_Format,
		type EventLog
	} from '$lib/gen/nokku/v1/util_pb';
	import { usePagination } from '$lib/hooks';
	import { auditUTC } from '$lib/store.svelte';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { renderComponent } from '@tanstack/svelte-table';
	import { Archive, Download, FileClock, Radio, Target } from '@lucide/svelte';
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
	} from '$lib/components/audit/audit';
	import EventCell from './EventCell.svelte';
	import RangePicker, { currentRange } from '$lib/components/audit/RangePicker.svelte';
	import TimeCell from './TimeCell.svelte';

	let selected = $state<EventLog>();

	const ws = workspace.get();
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
	const exportLogs = util.exportLogs();

	// Exports need both bounds, an open ended preset ends now.
	function exportAs(format: ExportAuditLogsRequest_Format) {
		exportLogs.mutate({
			format,
			filter: { ...filter, endDate: filter.endDate ?? timestampFromDate(new Date()) }
		});
	}
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
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.timestamp })
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
			cell: ({ row }) => renderComponent(TextCell, { label: row.original.ip || '—', subLabel: '' })
		})
	]);
</script>

<div class="container mx-auto flex max-w-6xl flex-col gap-5 p-6">
	<PageHeader
		title="Audit log"
		description="Every change and sign-in in this workspace, who did it and from where."
		icon={FileClock}
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
			<DropdownMenu.Content align="end" class="w-60">
				<DropdownMenu.Group>
					<DropdownMenu.Label class="text-xs font-normal text-muted-foreground">
						Exactly what the table shows, up to 90 days
					</DropdownMenu.Label>
					<DropdownMenu.Item onclick={() => exportAs(ExportAuditLogsRequest_Format.CSV)}>
						CSV, for spreadsheets
					</DropdownMenu.Item>
					<DropdownMenu.Item onclick={() => exportAs(ExportAuditLogsRequest_Format.JSON)}>
						JSON, for tooling
					</DropdownMenu.Item>
				</DropdownMenu.Group>
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	</PageHeader>

	<div class="-mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
		{#if logs.data?.retentionDays}
			<span class="flex items-center gap-1.5">
				<Archive class="size-3.5" />
				Kept for {logs.data.retentionDays} days on your plan
			</span>
		{/if}
		<a href="/settings/audit" class="flex items-center gap-1.5 hover:text-foreground">
			<Radio class={['size-3.5', streaming && 'text-success']} />
			{streaming ? 'Streaming to your SIEM' : 'Not streaming to a SIEM yet'}
		</a>
	</div>

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
</div>
