<script lang="ts">
	import { recordings } from '$lib/api/recordings.svelte';
	import RecordingPlayer from './RecordingPlayer.svelte';
	import { DataTable, createAppColumnHelper } from '$lib/components/tables';
	import { ActionCell, StatusCell, TimeCell } from '$lib/components/tables/cells';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { createModalState } from '$lib/hooks';
	import { formatBytes } from '$lib/crypto/recordings';
	import type { Recording } from '$lib/gen/nokku/v1/recordings_pb';
	import { MonitorPlay, SearchX } from '@lucide/svelte';

	const list = $derived(recordings.list());
	const deleteRecording = recordings.delete();

	const player = createModalState<Recording>({} as Recording);

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
		})
	]);
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
