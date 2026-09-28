<script lang="ts">
	import { recordings } from '$lib/api/recordings.svelte';
	import RecordingPlayer from './RecordingPlayer.svelte';
	import { DataTable, createAppColumnHelper, type BulkAction } from '$lib/components/tables';
	import { ActionCell, StatusCell, TimeCell } from '$lib/components/tables/cells';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import StorageQuotaPill from './StorageQuotaPill.svelte';
	import { confirm, createModalState, usePagination } from '$lib/hooks';
	import { plural } from '$lib/api/bulk';
	import { formatBytes } from '$lib/utils';
	import type { Recording } from '$lib/gen/nokku/v1/recordings_pb';
	import { Play, SearchX, Trash2, Video } from '@lucide/svelte';

	const pager = usePagination();
	const list = recordings.list(() => pager.args);
	const deleteRecording = recordings.delete();
	const deleteRecordings = recordings.deleteMany();

	const player = createModalState<Recording>({} as Recording);

	const bulkActions: BulkAction<Recording>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: async (selected) => {
				const ok = await confirm({
					title: `Delete ${plural(selected.length, 'recording')}?`,
					description: 'This permanently deletes the recordings.'
				});
				if (ok) await deleteRecordings.mutateAsync(selected.map(({ id }) => ({ recordingId: id })));
			}
		}
	];

	const columnHelper = createAppColumnHelper<Recording>();
	const columns = columnHelper.columns([
		columnHelper.accessor('startedAt', {
			header: 'Started',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.startedAt })
		}),
		columnHelper.accessor('username', {
			header: 'User',
			cell: ({ row }) => renderComponent(StatusCell, { status: row.original.username || '—' })
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

<PageHeader
	icon={Video}
	title="Recordings"
	description="Encrypted session recordings from your daemons."
>
	<StorageQuotaPill />
</PageHeader>

<DataTable
	data={list.data?.recordings ?? []}
	rowCount={list.data?.total ?? 0}
	isLoading={list.isLoading}
	{columns}
	{bulkActions}
	emptyState={{
		icon: SearchX,
		title: 'No recordings yet',
		description: 'Recordings appear here once a daemon records a session.'
	}}
></DataTable>

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
