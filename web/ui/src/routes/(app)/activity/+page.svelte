<script lang="ts">
	import { util } from '$lib/api/workspaces.svelte';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu/index.js';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import { ExportAuditLogsRequest_Format, type EventLog } from '$lib/gen/nokku/v1/util_pb';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { DateValueToTimestamp } from '$lib/utils';
	import { Activity, Download, InfoIcon } from '@lucide/svelte';
	import type { ColumnDef } from '@tanstack/table-core';
	import ActivityModal from '$lib/components/modals/ActivityModal.svelte';
	import type { DateRange } from 'bits-ui';
	import { getLocalTimeZone, today } from '@internationalized/date';
	import { SvelteSet } from 'svelte/reactivity';
	import ActivityToolbar from './ActivityToolbar.svelte';
	import { createModalState } from '$lib/hooks';
	import DateRangePicker from '$lib/components/utils/DateRangePicker.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import BadgeCell from '$lib/components/tables/cells/BadgeCell.svelte';
	import TextCell from '$lib/components/tables/cells/TextCell.svelte';
	import CheckCell from '$lib/components/tables/cells/CheckCell.svelte';

	// State
	const modal = createModalState<EventLog>({} as EventLog);
	let logRange = $state<DateRange>({
		start: today(getLocalTimeZone()).subtract({ days: 14 }),
		end: today(getLocalTimeZone())
	});

	const exportMutation = util.exportLogs();

	// Filter state
	let search = $state('');
	let selectedUsers = new SvelteSet<string>();
	let selectedActions = new SvelteSet<string>();
	let selectedActorTypes = new SvelteSet<string>();

	const logs = $derived(
		util.getLogs({
			search,
			actorIds: Array.from(selectedUsers),
			actions: Array.from(selectedActions),
			actorTypes: Array.from(selectedActorTypes),
			startDate: DateValueToTimestamp(logRange.start),
			endDate: DateValueToTimestamp(logRange.end)
		})
	);

	// Action colors for activity types
	const getActionColor = (action: string) => {
		const colors: Record<string, string> = {
			create: 'bg-chart-1',
			update: 'bg-chart-5',
			delete: 'bg-chart-2',
			sign: 'bg-chart-3'
		};
		return colors[action] ?? 'bg-primary';
	};

	const columns: ColumnDef<EventLog>[] = [
		{
			header: 'Action',
			accessorKey: 'action',
			cell: ({ row }) => {
				const label = row.original.action.split('/')[2];
				return renderComponent(BadgeCell, {
					value: label || 'Unknown',
					variant: 'secondary',
					class: `${getActionColor(row.original.action)} text-xs text-primary-foreground`
				});
			}
		},
		{
			header: 'Status',
			accessorKey: 'status_code',
			cell: ({ row }) => renderComponent(CheckCell, { checked: row.original.statusCode === '' })
		},
		{
			header: 'Actor',
			accessorKey: 'actorId',
			cell: ({ row }) =>
				renderComponent(TextCell, {
					label: row.original.actorType,
					subLabel: row.original.actorId
				})
		},
		{
			header: 'Source',
			accessorKey: 'ipAddress',
			cell: ({ row }) =>
				renderComponent(TextCell, {
					label: row.original.ipAddress || '',
					subLabel: row.original.userAgent || ''
				})
		},
		{
			header: 'Timestamp',
			accessorKey: 'timestamp',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.timestamp })
		},
		{
			id: 'actions',
			cell: ({ row }) => {
				return renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: InfoIcon,
							onClick: () => modal.openWith({ ...row.original })
						}
					]
				});
			}
		}
	];
</script>

<div class="container mx-auto max-w-6xl space-y-6 p-6">
	<PageHeader
		title="Activity Logs"
		description="Monitor all workspace activity and audit trails"
		icon={Activity}
	/>
	<ActivityModal log={modal.selected} bind:open={modal.open} />

	<div class="flex items-center justify-between">
		<ActivityToolbar
			bind:search
			{selectedActions}
			{selectedActorTypes}
			{selectedUsers}
			searchResults={logs.data?.total}
		/>

		<div class="flex items-center gap-2">
			<DateRangePicker bind:value={logRange} />
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					<Button variant="outline" disabled={logs.isPending}>
						<Download />
						Export
					</Button>
				</DropdownMenu.Trigger>
				<DropdownMenu.Content class="w-12" align="end">
					<DropdownMenu.Group>
						<DropdownMenu.Label>Export Format</DropdownMenu.Label>
						<DropdownMenu.Separator />
						<DropdownMenu.Item
							onclick={() =>
								exportMutation.mutate({
									format: ExportAuditLogsRequest_Format.CSV,
									startDate: DateValueToTimestamp(logRange.start),
									endDate: DateValueToTimestamp(logRange.end)
								})}
							disabled={logs.isPending}
						>
							CSV
						</DropdownMenu.Item>
						<DropdownMenu.Item
							onclick={() =>
								exportMutation.mutate({
									format: ExportAuditLogsRequest_Format.JSON,
									startDate: DateValueToTimestamp(logRange.start),
									endDate: DateValueToTimestamp(logRange.end)
								})}
							disabled={logs.isPending}
						>
							JSON
						</DropdownMenu.Item>
					</DropdownMenu.Group>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		</div>
	</div>

	<DataTable
		data={logs.data?.logs}
		{columns}
		rowCount={logs.data?.total}
		emptyState={{
			icon: Activity,
			title: 'No Activity Found',
			description: 'Activity will appear here as actions are performed'
		}}
	/>
</div>
