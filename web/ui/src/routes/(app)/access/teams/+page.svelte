<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { page } from '$app/state';
	import { team } from '#lib/api/team.svelte.js';
	import CreateTeamModal from '#lib/components/modals/CreateTeamModal.svelte';
	import TeamSheet from '#lib/components/sheets/TeamSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		AvatarCell,
		MemberCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { Team } from '#lib/gen/nokku/v1/team_pb.js';
	import { confirm, usePagination, useSheet } from '#lib/hooks/index.js';
	import { PlusIcon, ShieldCheck, Trash2, Users } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	let createOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const teams = team.list(() => ({
		...pager.args,
		query: debounced.current
	}));

	const deleteTeam = team.delete();
	const deleteTeams = team.deleteMany();

	const bulkActions: BulkAction<Team>[] = [
		{
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'team')}?`,
				description: 'This action cannot be undone.',
				confirmText: 'Delete'
			}),
			onClick: (selected) => deleteTeams.mutateAsync(selected.map(({ id }) => ({ id })))
		}
	];

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
		columnHelper.accessor('memberCount', {
			header: 'Members',
			cell: ({ row }) =>
				renderComponent(MemberCell, {
					teamId: row.original.id,
					memberCount: row.original.memberCount
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
					menuActions: [
						{
							label: 'Manage access',
							icon: ShieldCheck,
							onClick: () => sheet.show(row.original.id, 'access')
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description:
							'Members keep their own access, but lose everything granted through this team.',
						typeToConfirm: row.original.name,
						onDelete: () => deleteTeam.mutateAsync({ id: row.original.id })
					}
				});
			}
		})
	]);
</script>

<PageHeader title="Teams" description="Groups of people who share access">
	<Button onclick={() => (createOpen = true)}>
		<PlusIcon data-icon="inline-start" />
		Create team
	</Button>
</PageHeader>

<CreateTeamModal bind:open={createOpen} />
<TeamSheet />

<DataTable
	data={teams.data?.teams ?? []}
	rowCount={teams.data?.total ?? 0}
	isLoading={teams.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(t) => sheet.show(t.id)}
	emptyState={{
		icon: Users,
		title: 'No teams yet',
		description: 'Group people, then grant access to the whole team at once.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar {table} search searchResultCount={teams.data?.total} />
	{/snippet}
</DataTable>
