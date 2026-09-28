<script lang="ts">
	import { util } from '$lib/api/workspaces.svelte';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu/index.js';
	import { DataTable, createAppColumnHelper } from '$lib/components/tables';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import { ExportAuditLogsRequest_Format, type EventLog } from '$lib/gen/nokku/v1/util_pb';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { actionLabel, DateValueStartTs, DateValueToTimestamp } from '$lib/utils';
	import { Activity, Download, InfoIcon } from '@lucide/svelte';
	import ActivityModal from '$lib/components/modals/ActivityModal.svelte';
	import type { DateRange } from 'bits-ui';
	import { getLocalTimeZone, today } from '@internationalized/date';
	import { SvelteSet } from 'svelte/reactivity';
	import ActivityToolbar from './ActivityToolbar.svelte';
	import { createModalState } from '$lib/hooks';
	import DateRangePicker from '$lib/components/utils/DateRangePicker.svelte';
	import {
		ActionCell,
		BadgeCell,
		CheckCell,
		CopyCell,
		TextCell,
		TimeCell
	} from '$lib/components/tables/cells';

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
			actorKinds: Array.from(selectedActorTypes),
			startDate: DateValueStartTs(logRange.start),
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
		const verb = action.match(/^[A-Z][a-z]+/)?.[0].toLowerCase() ?? '';
		return colors[verb] ?? 'bg-primary';
	};

	const columnHelper = createAppColumnHelper<EventLog>();
	const columns = columnHelper.columns([
		columnHelper.display({
			id: 'ok',
			header: 'Status',
			cell: ({ row }) => renderComponent(CheckCell, { checked: row.original.ok })
		}),
		columnHelper.accessor('action', {
			header: 'Action',
			cell: ({ row }) => {
				return renderComponent(BadgeCell, {
					value: actionLabel(row.original.action),
					variant: 'secondary',
					class: `${getActionColor(row.original.action)} text-xs text-primary-foreground`
				});
			}
		}),
		columnHelper.accessor('target', {
			header: 'Target',
			cell: ({ row }) => renderComponent(CopyCell, { value: row.original.target })
		}),
		columnHelper.accessor('actorName', {
			header: 'Actor',
			cell: ({ row }) => {
				const log = row.original;
				return renderComponent(TextCell, {
					label:
						log.actorName ||
						(log.actorKind === 'user' && log.actorId
							? `${log.actorId.slice(0, 8)}…`
							: log.actorKind),
					subLabel: log.actorName ? log.actorKind : ''
				});
			}
		}),
		columnHelper.accessor('ip', {
			header: 'Source',
			cell: ({ row }) =>
				renderComponent(TextCell, {
					label: row.original.ip || '',
					subLabel: row.original.userAgent || ''
				})
		}),
		columnHelper.accessor('timestamp', {
			header: 'Timestamp',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.timestamp })
		}),
		columnHelper.display({
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
		})
	]);
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
