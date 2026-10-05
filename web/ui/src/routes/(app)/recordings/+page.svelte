<script lang="ts">
	import { recordings } from '#lib/api/recordings.svelte.js';
	import RecordingPlayer from './RecordingPlayer.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import { page } from '$app/state';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import {
		ActionCell,
		StatusCell,
		TextCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import StorageQuotaPill from './StorageQuotaPill.svelte';
	import { confirm, createModalState, usePagination } from '#lib/hooks/index.js';
	import { plural } from '#lib/api/bulk.js';
	import { formatBytes } from '#lib/utils.js';
	import type { Recording } from '#lib/gen/nokku/v1/recordings_pb.js';
	import { Bot, Play, Trash2, Video } from '@lucide/svelte';

	const pager = usePagination();
	const list = recordings.list(() => ({
		...pager.args,
		daemonId: page.url.searchParams.get('daemon') || undefined,
		username: page.url.searchParams.get('user') || undefined
	}));
	const daemons = daemon.list();
	const daemonName = $derived(new Map((daemons.data?.daemons ?? []).map((d) => [d.id, d.name])));
	const daemonOptions = $derived(
		(daemons.data?.daemons ?? []).map((d) => ({ label: d.name, value: d.id, icon: Bot }))
	);
	const deleteRecording = recordings.delete();
	const deleteRecordings = recordings.deleteMany();

	const player = createModalState<Recording>({} as Recording);

	const bulkActions: BulkAction<Recording>[] = [
		{
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'recording')}?`,
				description: 'This permanently deletes the recordings.'
			}),
			onClick: (selected) =>
				deleteRecordings.mutateAsync(selected.map(({ id }) => ({ recordingId: id })))
		}
	];

	const columnHelper = createAppColumnHelper<Recording>();
	const columns = columnHelper.columns([
		columnHelper.accessor('startedAt', {
			header: 'Started',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.startedAt })
		}),
		columnHelper.accessor('daemonId', {
			header: 'Daemon',
			cell: ({ row }) =>
				renderComponent(TextCell, {
					label: daemonName.get(row.original.daemonId) ?? (row.original.daemonName || '—')
				})
		}),
		columnHelper.accessor('username', {
			header: 'User',
			cell: ({ row }) =>
				renderComponent(TextCell, { label: row.original.username || '—', mono: true })
		}),
		columnHelper.accessor('sizeBytes', {
			header: 'Size',
			cell: ({ row }) => formatBytes(Number(row.original.sizeBytes))
		}),
		columnHelper.accessor('complete', {
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(StatusCell, {
					status: row.original.complete ? 'complete' : 'truncated'
				})
		}),
		columnHelper.display({
			id: 'actions',
			cell: ({ row }) =>
				renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: Play,
							onClick: () => player.openWith({ ...row.original })
						}
					],
					deleteConfig: {
						itemName: `recording of ${row.original.username}`,
						description: 'This permanently deletes the recording.',
						onDelete: () => deleteRecording.mutateAsync({ recordingId: row.original.id })
					}
				})
		})
	]);
</script>

<PageHeader title="Recordings" description="Encrypted session recordings from your daemons">
	<StorageQuotaPill />
</PageHeader>

<DataTable
	data={list.data?.recordings ?? []}
	rowCount={list.data?.total ?? 0}
	isLoading={list.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(r) => player.openWith({ ...r })}
	emptyState={{
		icon: Video,
		title: 'No recordings yet',
		description: 'Turn on REC for a daemon, then every new session it serves lands here.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			search="user"
			searchPlaceholder="Exact account, e.g. deploy"
			{table}
			filters={[{ title: 'Daemon', options: daemonOptions, param: 'daemon', mode: 'single' }]}
		/>
	{/snippet}
</DataTable>

{#if player.selected.id}
	<RecordingPlayer
		recording={player.selected}
		open={player.open}
		onOpenChange={(o) => {
			player.open = o;
			if (!o) player.close();
		}}
	/>
{/if}
