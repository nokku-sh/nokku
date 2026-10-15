<script lang="ts">
	import { page } from '$app/state';
	import { team } from '#lib/api/team.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import CreateTeamModal from '#lib/components/modals/CreateTeamModal.svelte';
	import TeamSheet from '#lib/components/sheets/TeamSheet.svelte';
	import {
		DataTable,
		bulkDelete,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		IdentityCell,
		MemberCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { Team } from '#lib/gen/nokku/v1/team_pb.js';
	import { useCreate, usePagination, useSheet } from '#lib/hooks/index.js';
	import { PlusIcon, ShieldCheck, Users } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	const can = user.can();
	const create = useCreate();

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const teams = team.list(() => ({
		...pager.args,
		query: debounced.current
	}));

	const deleteTeam = team.delete();
	const deleteTeams = team.deleteMany();

	const bulkActions: BulkAction<Team>[] = [
		bulkDelete<Team>({
			noun: 'team',
			run: (selected) => deleteTeams.mutateAsync(selected.map(({ id }) => ({ id })))
		})
	];

	const columnHelper = createAppColumnHelper<Team>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) =>
				renderComponent(IdentityCell, {
					name: row.original.name,
					detail: row.original.description
				})
		}),
		columnHelper.accessor('memberCount', {
			header: 'Members',
			cell: ({ row }) => renderComponent(MemberCell, { memberCount: row.original.memberCount })
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
					label: row.original.name,
					id: row.original.id,
					link: true,
					menuActions: [
						{
							label: can.edit ? 'Manage access' : 'View access',
							icon: ShieldCheck,
							onClick: () => sheet.show(row.original.id, 'access')
						}
					],

					deleteConfig: can.edit
						? {
								itemName: row.original.name,
								description:
									'Members keep their own access, but lose everything granted through this team.',
								typeToConfirm: row.original.name,
								onDelete: () => deleteTeam.mutateAsync({ id: row.original.id })
							}
						: undefined
				});
			}
		})
	]);
</script>

<PageHeader title="Teams" description="Groups of people who share access">
	{#if can.edit}
		<Button onclick={() => (create.open = true)}>
			<PlusIcon data-icon="inline-start" />
			Create team
		</Button>
	{/if}
</PageHeader>

<CreateTeamModal bind:open={create.open} />
<TeamSheet />

<DataTable
	data={teams.data?.teams ?? []}
	rowCount={teams.data?.total ?? 0}
	isLoading={teams.isLoading}
	error={teams.error}
	onRetry={teams.refetch}
	rowLabel={(t) => t.name}
	{columns}
	bulkActions={can.edit ? bulkActions : []}
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
