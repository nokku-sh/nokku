<script lang="ts">
	import { plural } from '$lib/api/bulk';
	import { page } from '$app/state';
	import { daemon } from '$lib/api/daemons.svelte';
	import DaemonSheet from '$lib/components/sheets/DaemonSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import {
		ActionCell,
		AvatarCell,
		DaemonStatusCell,
		RecordingCell,
		StatusCell,
		TimeCell
	} from '$lib/components/tables/cells';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { DaemonStatus, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { confirm, usePagination, useSheet } from '$lib/hooks';
	import EnrollSheet from './EnrollSheet.svelte';
	import { Button } from '$lib/components/ui/button';
	import {
		Bot,
		BotOff,
		CircleCheckBig,
		Clock,
		Rocket,
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
						description: 'Are you sure you want to delete this daemon?',
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
			onClick: async (selected) => {
				const ok = await confirm({
					title: `Delete ${plural(selected.length, 'daemon')}?`,
					description: 'This action cannot be undone.',
					confirmText: 'Delete'
				});
				if (ok) await deleteDaemons.mutateAsync(selected.map(({ id }) => ({ id })));
			}
		}
	];
</script>

<DaemonSheet />
<EnrollSheet bind:open={enrollOpen} />

<PageHeader title="Daemons" description="Edge agents that connect your servers to Nokku" icon={Bot}>
	<Button onclick={() => (enrollOpen = true)}>
		<Rocket data-icon="inline-start" />
		Enroll daemons
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
		title: 'No Daemons',
		description: 'Generate an enrollment token to deploy your first daemon.'
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
