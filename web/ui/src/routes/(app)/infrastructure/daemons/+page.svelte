<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { page } from '$app/state';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import DaemonSheet from '#lib/components/sheets/DaemonSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		AvatarCell,
		DaemonStatusCell,
		RecordingCell,
		StatusCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { DaemonStatus, type Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { confirm, usePagination, useSheet } from '#lib/hooks/index.js';
	import EnrollSheet from '#lib/components/sheets/EnrollSheet.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { BotOff, CircleCheckBig, Clock, Rocket, Trash2, Wifi, WifiOff } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const statusOptions = [
		{ label: 'Accepted', value: DaemonStatus.ACCEPTED.toString(), icon: CircleCheckBig },
		{ label: 'Pending', value: DaemonStatus.PENDING.toString(), icon: Clock }
	];

	const onlineOptions = [
		{ label: 'Online', value: 'true', icon: Wifi },
		{ label: 'Offline', value: 'false', icon: WifiOff }
	];

	const sheet = useSheet();
	let enrollOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const daemons = daemon.list(() => ({
		...pager.args,
		query: debounced.current,
		status: page.url.searchParams.get('status')
			? Number(page.url.searchParams.get('status'))
			: undefined,
		online: page.url.searchParams.get('online') === 'true' || undefined
	}));

	const deleteDaemon = daemon.delete();
	const deleteDaemons = daemon.deleteMany();
	const approveDaemons = daemon.approveMany();

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
			cell: ({ row }) => renderComponent(RecordingCell, { daemon: row.original })
		}),
		columnHelper.accessor('status', {
			header: 'Status',
			cell: ({ row }) => renderComponent(DaemonStatusCell, { daemon: row.original })
		}),
		columnHelper.accessor('online', {
			header: 'Online',
			cell: ({ row }) =>
				renderComponent(StatusCell, { status: row.original.online ? 'Online' : 'Offline' })
		}),
		columnHelper.accessor('lastSeenAt', {
			header: 'Last seen',
			cell: ({ row }) =>
				renderComponent(TimeCell, {
					ts: row.original.lastSeenAt,
					fallback: 'Never',
					emphasize: 'relative'
				})
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
					deleteConfig: {
						itemName: row.original.name,
						description:
							'Targets behind this daemon become unreachable until another daemon serves them.',
						typeToConfirm: row.original.name,
						onDelete: () => deleteDaemon.mutateAsync({ id: row.original.id })
					}
				});
			}
		})
	]);

	const bulkActions: BulkAction<Daemon>[] = [
		{
			type: 'button',
			label: 'Approve',
			icon: CircleCheckBig,
			variant: 'default',
			confirm: (selected) => ({
				title: `Approve ${plural(selected.length, 'daemon')}?`,
				description: 'Approved daemons can register targets and open sessions.',
				destructive: false
			}),
			onClick: async (selected) => {
				const pending = selected.filter((d) => d.status === DaemonStatus.PENDING);
				if (!pending.length) return;
				await approveDaemons.mutateAsync(
					pending.map(({ id }) => ({ id, status: DaemonStatus.ACCEPTED }))
				);
			}
		},
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'daemon')}?`,
				description: 'This action cannot be undone.',
				confirmText: 'Delete'
			}),
			onClick: (selected) => deleteDaemons.mutateAsync(selected.map(({ id }) => ({ id })))
		}
	];
</script>

<DaemonSheet />
<EnrollSheet bind:open={enrollOpen} />

<PageHeader title="Daemons" description="Edge agents that connect your servers to Nokku">
	<Button onclick={() => (enrollOpen = true)}>
		<Rocket data-icon="inline-start" />
		Enroll a daemon
	</Button>
</PageHeader>

<DataTable
	data={daemons.data?.daemons ?? []}
	rowCount={daemons.data?.total ?? 0}
	isLoading={daemons.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(d) => sheet.show(d.id)}
	emptyState={{
		icon: BotOff,
		title: 'No daemons yet',
		description: 'Create an enrollment token, then run this on the server.',
		command: 'nokkud enroll'
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
