<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { page } from '$app/state';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { roles } from '#lib/api/roles.svelte.js';
	import { roleIcon, roleLabel } from '#lib/roles.js';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import MemberSheet from '#lib/components/sheets/MemberSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import { ActionCell, RoleCell, TeamCell, UserCell } from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { type WorkspaceMember } from '#lib/gen/nokku/v1/workspace_pb.js';
	import { usePagination, useSheet } from '#lib/hooks/index.js';
	import { CircleUser, PlusIcon, ShieldCheck, Trash2 } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	let inviteOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const members = workspace.listMembers(() => ({
		...pager.args,
		query: debounced.current,
		roleName: page.url.searchParams.get('role') || undefined
	}));

	const removeMember = workspace.removeMember();
	const removeMembers = workspace.removeMembers();
	const updateMember = workspace.updateMember();

	const bulkActions: BulkAction<WorkspaceMember>[] = [
		{
			label: 'Remove',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Remove ${plural(selected.length, 'member')}?`,
				description: 'This action cannot be undone.',
				confirmText: 'Remove'
			}),
			onClick: (selected) => removeMembers.mutateAsync(selected.map(({ id }) => ({ userId: id })))
		}
	];

	const rolesQuery = roles.list();
	const roleOptions = $derived(
		(rolesQuery.data ?? []).map((r) => ({
			label: roleLabel(r.name),
			value: r.name,
			icon: roleIcon(r.name)
		}))
	);

	const columnHelper = createAppColumnHelper<WorkspaceMember>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) => {
				return renderComponent(UserCell, { user: row.original });
			}
		}),
		columnHelper.accessor('roleName', {
			header: 'Role',
			enableColumnFilter: true,
			cell: ({ row }) =>
				renderComponent(RoleCell, {
					roleName: row.original.roleName,
					update: (roleName) => updateMember.mutateAsync({ userId: row.original.id, roleName })
				})
		}),
		columnHelper.display({
			id: 'teams',
			header: 'Teams',
			cell: ({ row }) => renderComponent(TeamCell, { userId: row.original.id })
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
						title: `Remove ${row.original.name}?`,
						description: 'All their access here is revoked right away.',
						confirmText: 'Remove',
						typeToConfirm: row.original.email,
						onDelete: () => removeMember.mutateAsync({ userId: row.original.id })
					}
				});
			}
		})
	]);
</script>

<MemberSheet />
<InviteSheet bind:open={inviteOpen} />

<PageHeader title="Members" description="People in this workspace, their role and their teams">
	<Button onclick={() => (inviteOpen = true)}>
		<PlusIcon data-icon="inline-start" />
		Invite people
	</Button>
</PageHeader>

<DataTable
	data={members.data?.members ?? []}
	rowCount={members.data?.total ?? 0}
	isLoading={members.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(m) => sheet.show(m.id)}
	emptyState={{
		icon: CircleUser,
		title: 'No members yet',
		description: 'Invite people to this workspace.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			search
			searchResultCount={members.data?.total}
			{table}
			filters={[
				{
					title: 'Role',
					options: roleOptions,
					param: 'role',
					mode: 'single'
				}
			]}
		/>
	{/snippet}
</DataTable>
