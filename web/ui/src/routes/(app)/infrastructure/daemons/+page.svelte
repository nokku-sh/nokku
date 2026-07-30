<script lang="ts">
	import { page } from '$app/state';
	import { daemon } from '$lib/api/daemons.svelte';
	import DaemonModal from '$lib/components/modals/DaemonModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import AvatarCell from '$lib/components/tables/cells/AvatarCell.svelte';
	import StatusCell from '$lib/components/tables/cells/StatusCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import type { BulkAction } from '$lib/components/tables/types';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { DaemonStatus, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { createModalState } from '$lib/hooks';
	import { pageIndex, pageSize } from '$lib/store.svelte';
	import { enumLabel } from '$lib/utils';
	import {
		Bot,
		BotOff,
		CircleCheckBig,
		Clock,
		ExternalLink,
		InfoIcon,
		Trash2,
		Wifi,
		WifiOff
	} from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';
	import { Debounced } from 'runed';

	const statusOptions = [
		{ label: 'Accepted', value: DaemonStatus.ACCEPTED.toString(), icon: CircleCheckBig },
		{ label: 'Pending', value: DaemonStatus.PENDING.toString(), icon: Clock }
	];

	const onlineOptions = [
		{ label: 'Online', value: 'true', icon: Wifi },
		{ label: 'Offline', value: 'false', icon: WifiOff }
	];

	// Modal state
	const daemonModal = createModalState<Daemon>({} as Daemon);

	// Data
	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const daemons = $derived(
		daemon.list(() => ({
			limit: pageSize.current,
			offset: pageIndex.current * pageSize.current,
			query: debounced.current,
			status: page.url.searchParams.get('status')
				? Number(page.url.searchParams.get('status'))
				: undefined,
			online: page.url.searchParams.get('online') === 'true' || undefined
		}))
	);

	const updateDaemon = daemon.update();
	const deleteDaemon = daemon.delete();

	const columns: ColumnDef<Daemon>[] = [
		{
			header: 'Name',
			accessorKey: 'name',
			cell: ({ row }) =>
				renderComponent(AvatarCell, {
					id: row.original.id,
					name: row.original.name
				})
		},
		{
			header: 'Status',
			accessorKey: 'status',
			cell: ({ row }) =>
				renderComponent(StatusCell, { status: enumLabel(DaemonStatus[row.original.status]) })
		},
		{
			header: 'Online',
			accessorKey: 'online',
			cell: ({ row }) =>
				renderComponent(StatusCell, { status: row.original.online ? 'Online' : 'Offline' })
		},
		{
			header: 'Updated',
			accessorKey: 'updatedAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.updatedAt })
		},
		{
			header: 'Created',
			accessorKey: 'createdAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.createdAt })
		},
		{
			id: 'actions',
			cell: ({ row }) => {
				return renderComponent(ActionCell, {
					inlineActions:
						row.original.status === DaemonStatus.PENDING
							? [
									{
										label: 'Approve',
										onClick: () => {
											updateDaemon.mutate({ id: row.original.id, status: DaemonStatus.ACCEPTED });
											daemons.refetch();
										}
									},
									{
										label: 'Reject',
										variant: 'destructive',
										onClick: () => deleteDaemon.mutate({ id: row.original.id })
									}
								]
							: [
									{
										icon: InfoIcon,
										onClick: () => daemonModal.openWith({ ...row.original })
									}
								],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to delete this daemon?',
						onDelete: () => deleteDaemon.mutate({ id: row.original.id })
					}
				});
			}
		}
	];

	const bulkActions: BulkAction<Daemon>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteDaemon.mutate({ id }))
		}
	];

	let table = $state<Table<Daemon>>();
</script>

<DaemonModal bind:open={daemonModal.open} bind:data={daemonModal.selected} />

<PageHeader title="Daemons" description="Manage your workspace daemons" icon={Bot}>
	<Button href="/settings/enrollment" variant="link">
		Enroll daemons
		<ExternalLink size={16} class="text-muted-foreground" />
	</Button>
</PageHeader>

<TableToolbar
	{table}
	search
	searchResultCount={daemons.data?.total}
	filters={[
		{
			title: 'Status',
			options: statusOptions,
			param: 'status',
			mode: 'single'
		},
		{
			title: 'Online',
			options: onlineOptions,
			param: 'online',
			mode: 'single'
		}
	]}
/>

<DataTable
	data={daemons.data?.daemons ?? []}
	rowCount={daemons.data?.total ?? 0}
	{columns}
	{bulkActions}
	onTableReady={(t) => (table = t)}
	emptyState={{
		icon: BotOff,
		title: 'No Daemons',
		description: 'Deploy daemons to your servers using a enrollment token to get started.'
	}}
></DataTable>
