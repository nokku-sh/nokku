<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { team } from '$lib/api/team.svelte';
	import TeamModal from '$lib/components/modals/TeamModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import { ActionCell, AvatarCell, MemberCell, TimeCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import { createModalState } from '$lib/hooks';
	import { PencilIcon, PlusIcon, Trash2, Users, UsersIcon } from '@lucide/svelte';
	import { Debounced } from 'runed';

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
	const columnHelper = createAppColumnHelper<Team>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) =>
				renderComponent(AvatarCell, {
					id: row.original.id,
					name: row.original.name,
					description: row.original.description
				})
		}),
		columnHelper.accessor('members', {
			header: 'Members',
			cell: ({ row }) => renderComponent(MemberCell, { members: row.original.members })
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
		})
	]);
</script>

<PageHeader title="Teams" description="Manage your workspace teams" icon={UsersIcon}>
	<Button onclick={() => teamModal.openNew()}>
		<PlusIcon data-icon="inline-start" />
		Create Team
	</Button>
</PageHeader>

<TeamModal bind:open={teamModal.open} bind:data={teamModal.selected} />

<DataTable
	data={teams.data?.teams ?? []}
	rowCount={teams.data?.total ?? 0}
	{columns}
	{bulkActions}
	emptyState={{
		icon: Users,
		title: 'No Teams',
		description: 'Get started by creating your first team.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar {table} search searchResultCount={teams.data?.total} />
	{/snippet}
</DataTable>
