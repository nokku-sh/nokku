<script lang="ts">
	import { page } from '$app/state';
	import { daemon } from '$lib/api/daemons.svelte';
	import DaemonModal from '$lib/components/modals/DaemonModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import { ActionCell, AvatarCell, StatusCell, TimeCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { DaemonStatus, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { createModalState } from '$lib/hooks';
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
			query: debounced.current,
			status: page.url.searchParams.get('status')
				? Number(page.url.searchParams.get('status'))
				: undefined,
			online: page.url.searchParams.get('online') === 'true' || undefined
		}))
	);

	const updateDaemon = daemon.update();
	const deleteDaemon = daemon.delete();

	const columnHelper = createAppColumnHelper<Daemon>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) =>
				renderComponent(AvatarCell, {
					id: row.original.id,
					name: row.original.name
				})
		}),
		columnHelper.display({
			id: 'recording',
			header: 'Recording',
			cell: ({ row }) =>
				renderComponent(StatusCell, {
					status: row.original.config?.recordSessions ? 'enabled' : 'disabled'
				})
		}),
		columnHelper.accessor('status', {
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(StatusCell, { status: enumLabel(DaemonStatus[row.original.status]) })
		}),
		columnHelper.accessor('online', {
			header: 'Online',
			cell: ({ row }) =>
				renderComponent(StatusCell, { status: row.original.online ? 'Online' : 'Offline' })
		}),
		columnHelper.accessor('updatedAt', {
			header: 'Updated',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.updatedAt })
		}),
		columnHelper.accessor('createdAt', {
			header: 'Created',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.createdAt })
		}),
		columnHelper.display({
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
		})
	]);

	const bulkActions: BulkAction<Daemon>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteDaemon.mutate({ id }))
		}
	];
</script>

<DaemonModal bind:open={daemonModal.open} bind:data={daemonModal.selected} />

<PageHeader title="Daemons" description="Manage your workspace daemons" icon={Bot}>
	<Button href="/settings/enrollment" variant="link">
		Enroll daemons
		<ExternalLink size={16} class="text-muted-foreground" />
	</Button>
</PageHeader>

<DataTable
	data={daemons.data?.daemons ?? []}
	rowCount={daemons.data?.total ?? 0}
	{columns}
	{bulkActions}
	emptyState={{
		icon: BotOff,
		title: 'No Daemons',
		description: 'Deploy daemons to your servers using a enrollment token to get started.'
	}}
>
	{#snippet toolbar(table)}
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
	{/snippet}
</DataTable>
