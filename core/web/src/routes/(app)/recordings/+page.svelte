<script lang="ts">
	import { legalHolds } from '#lib/api/legal-holds.svelte.js';
	import { recordings } from '#lib/api/recordings.svelte.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import RecordingPlayer from './RecordingPlayer.svelte';
	import WhoCell from './WhoCell.svelte';
	import {
		DataTable,
		bulkDelete,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import { page } from '$app/state';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import {
		ActionCell,
		MachineCell,
		StateCell,
		TextCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import StorageQuotaPill from './StorageQuotaPill.svelte';
	import { createModalState, usePagination } from '#lib/hooks/index.js';
	import { formatBytes } from '#lib/utils.js';
	import type { Recording } from '#lib/gen/nokku/v1/recordings_pb.js';
	import { timestampFromMs, timestampMs } from '@bufbuild/protobuf/wkt';
	import { Bot, Lock, Video } from '@lucide/svelte';

	const pager = usePagination();
	const can = user.can();
	const list = recordings.list(() => ({
		...pager.args,
		daemonId: page.url.searchParams.get('daemon') || undefined,
		username: page.url.searchParams.get('user') || undefined,
		subjectId: page.url.searchParams.get('subject') || undefined
	}));
	const daemons = daemon.list();
	const daemonName = $derived(new Map((daemons.data?.daemons ?? []).map((d) => [d.id, d.name])));
	const daemonOptions = $derived(
		(daemons.data?.daemons ?? []).map((d) => ({ label: d.name, value: d.id, icon: Bot }))
	);
	const deleteRecording = recordings.delete();
	const deleteRecordings = recordings.deleteMany();

	const has = useFeatures();
	const hold = legalHolds.create();

	// A hold of one second around the start keeps this recording and nothing much else.
	function keep(r: Recording) {
		if (!r.startedAt) return;
		const start = timestampMs(r.startedAt);
		void hold.mutateAsync({
			reason: `Recording of ${r.username} on ${daemonName.get(r.daemonId) ?? r.daemonName}`,
			startsAt: timestampFromMs(start),
			endsAt: timestampFromMs(start + 1000)
		});
	}

	const player = createModalState<Recording>({} as Recording);

	const bulkActions: BulkAction<Recording>[] = [
		bulkDelete<Recording>({
			noun: 'recording',
			description: 'This permanently deletes the recordings.',
			run: (selected) =>
				deleteRecordings.mutateAsync(selected.map(({ id }) => ({ recordingId: id })))
		})
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
					label: daemonName.get(row.original.daemonId) ?? (row.original.daemonName || '-')
				})
		}),
		columnHelper.accessor('subjectId', {
			header: 'Who',
			cell: ({ row }) =>
				renderComponent(WhoCell, {
					subjectId: row.original.subjectId,
					name: row.original.subjectName
				})
		}),
		columnHelper.accessor('username', {
			header: 'Account',
			cell: ({ row }) => renderComponent(MachineCell, { value: row.original.username })
		}),
		columnHelper.accessor('sizeBytes', {
			header: 'Size',
			meta: { hideBelow: 'md' },
			cell: ({ row }) => formatBytes(Number(row.original.sizeBytes))
		}),
		columnHelper.accessor('complete', {
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(StateCell, {
					label: row.original.held ? 'Held' : row.original.complete ? 'Complete' : 'Truncated'
				})
		}),
		columnHelper.display({
			id: 'actions',
			cell: ({ row }) =>
				// The row itself plays, so the menu only holds what the click can't do.
				renderComponent(ActionCell, {
					label: `recording of ${row.original.username}`,
					id: row.original.id,
					menuActions:
						can.admin && has('legal_hold') && !row.original.held
							? [
									{
										label: 'Keep under a legal hold',
										icon: Lock,
										onClick: () => keep(row.original)
									}
								]
							: [],
					deleteConfig:
						can.edit && !row.original.held
							? {
									itemName: `recording of ${row.original.username}`,
									description: 'This permanently deletes the recording.',
									onDelete: () => deleteRecording.mutateAsync({ recordingId: row.original.id })
								}
							: undefined
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
	error={list.error}
	onRetry={list.refetch}
	rowLabel={(r) => `recording of ${r.username || 'a session'}`}
	{columns}
	bulkActions={can.edit ? bulkActions : []}
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
