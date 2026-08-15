<script lang="ts">
	import { recordings } from '$lib/api/recordings.svelte';
	import RecordingPlayer from './RecordingPlayer.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import StatusCell from '$lib/components/tables/cells/StatusCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { createModalState } from '$lib/hooks';
	import { formatBytes } from '$lib/crypto/recordings';
	import type { Recording } from '$lib/gen/nokku/v1/recordings_pb';
	import { MonitorPlay, SearchX } from '@lucide/svelte';
	import type { ColumnDef } from '@tanstack/table-core';

	const list = $derived(recordings.list());
	const deleteRecording = recordings.delete();

	const player = createModalState<Recording>({} as Recording);

	const columns: ColumnDef<Recording>[] = [
		{
			header: 'Started',
			accessorKey: 'startedAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.startedAt })
		},
		{
			header: 'User',
			accessorKey: 'username',
			cell: ({ row }) => renderComponent(StatusCell, { status: row.original.username || '—' })
		},
		{
			header: 'Size',
			accessorKey: 'sizeBytes',
			cell: ({ row }) => formatBytes(Number(row.original.sizeBytes))
		},
		{
			header: 'Status',
			accessorKey: 'complete',
			cell: ({ row }) =>
				renderComponent(StatusCell, {
					status: row.original.complete ? 'complete' : 'truncated'
				})
		},
		{
			id: 'actions',
			cell: ({ row }) =>
				renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: MonitorPlay,
							onClick: () => player.openWith({ ...row.original })
						}
					],
					deleteConfig: {
						itemName: `recording of ${row.original.username}`,
						description: 'This permanently deletes the recording.',
						onDelete: () => {
							deleteRecording.mutate({ recordingId: row.original.id });
						}
					}
				})
		}
	];
</script>

<PageHeader
	icon={MonitorPlay}
	title="Recordings"
	description="Session recordings streamed by your daemons. All recordings are encrypted and can only be viewed with the workspace private key."
/>

<DataTable
	data={list.data?.recordings ?? []}
	rowCount={list.data?.total ?? 0}
	{columns}
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
