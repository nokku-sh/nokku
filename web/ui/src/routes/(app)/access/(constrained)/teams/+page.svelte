<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { team } from '$lib/api/team.svelte';
	import TeamModal from '$lib/components/modals/TeamModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import { createModalState } from '$lib/hooks';
	import type { BulkAction } from '$lib/components/tables/types';
	import { PencilIcon, PlusIcon, Trash2, Users, UsersIcon } from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';
	import { Debounced } from 'runed';
	import MemberCell from '$lib/components/tables/cells/MemberCell.svelte';
	import AvatarCell from '$lib/components/tables/cells/AvatarCell.svelte';

	// Modal states
	const teamModal = createModalState<Team>({} as Team);

	// Data
	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const teams = $derived(
		team.list(() => ({
			query: debounced.current
		}))
	);

	const deleteTeam = team.delete();

	const bulkActions: BulkAction<Team>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteTeam.mutate({ id }))
		}
	];

	// Columns
	const columns: ColumnDef<Team>[] = [
		{
			header: 'Name',
			accessorKey: 'name',
			cell: ({ row }) =>
				renderComponent(AvatarCell, {
					id: row.original.id,
					name: row.original.name,
					description: row.original.description
				})
		},
		{
			header: 'Members',
			accessorKey: 'members',
			cell: ({ row }) => renderComponent(MemberCell, { members: row.original.members })
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
					inlineActions: [
						{
							icon: PencilIcon,
							onClick: () => teamModal.openWith({ ...row.original })
						},
						{
							icon: PlusIcon,
							onClick: () =>
								goto(
									`/access/assign?type=${PrincipalType.TEAM}&id=${row.original.id}&name=${encodeURIComponent(row.original.name)}`
								)
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to delete this team?',
						onDelete: () => deleteTeam.mutate({ id: row.original.id })
					}
				});
			}
		}
	];

	let table = $state<Table<Team>>();
</script>

<PageHeader title="Teams" description="Manage your workspace teams" icon={UsersIcon}>
	<Button onclick={() => teamModal.openNew()}>
		<PlusIcon data-icon="inline-start" />
		Create Team
	</Button>
</PageHeader>

<TeamModal bind:open={teamModal.open} bind:data={teamModal.selected} />

<TableToolbar {table} search searchResultCount={teams.data?.total} />

<DataTable
	data={teams.data?.teams ?? []}
	rowCount={teams.data?.total ?? 0}
	{columns}
	{bulkActions}
	onTableReady={(t) => (table = t)}
	emptyState={{
		icon: Users,
		title: 'No Teams',
		description: 'Get started by creating your first team.'
	}}
/>
