<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { page } from '$app/state';
	import { users } from '#lib/api/workspaces.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { roles } from '#lib/api/roles.svelte.js';
	import { atLeast, roleIcon, roleLabel } from '#lib/roles.js';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import UserSheet from '#lib/components/sheets/UserSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		BadgeCell,
		RoleCell,
		TeamCell,
		UserCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';
	import { usePagination, useSheet } from '#lib/hooks/index.js';
	import { CircleUser, PlusIcon, ShieldCheck, Trash2, UserRoundX } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	let inviteOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const me = user.self();
	const canManage = $derived(atLeast(me.data?.role, 'admin'));

	const pager = usePagination();
	const list = users.list(() => ({
		...pager.args,
		query: debounced.current,
		role: page.url.searchParams.get('role') || undefined
	}));

	const remove = users.delete();
	const removeMany = users.deleteMany();
	const updateRole = users.updateRole();
	const setActive = users.setActive();

	// The owner and you are never in a bulk delete, the backend refuses both.
	const bulkActions: BulkAction<User>[] = [
		{
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'account')}?`,
				description: 'Their access ends right away. This cannot be undone.',
				confirmText: 'Delete'
			}),
			onClick: (selected) =>
				removeMany.mutateAsync(
					selected
						.filter((u) => u.role !== 'owner' && u.id !== me.data?.id)
						.map(({ id }) => ({ userId: id }))
				)
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

	const columnHelper = createAppColumnHelper<User>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) => renderComponent(UserCell, { user: row.original })
		}),
		columnHelper.accessor('role', {
			header: 'Role',
			enableColumnFilter: true,
			cell: ({ row }) =>
				renderComponent(RoleCell, {
					roleName: row.original.role,
					update:
						canManage && row.original.role !== 'owner' && row.original.id !== me.data?.id
							? (role) => updateRole.mutateAsync({ userId: row.original.id, role })
							: undefined
				})
		}),
		columnHelper.accessor('active', {
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(BadgeCell, {
					value: row.original.active ? 'Active' : 'Deactivated',
					variant: row.original.active ? 'secondary' : 'outline'
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
				const u = row.original;
				const protectedRow = u.role === 'owner' || u.id === me.data?.id || !canManage;
				return renderComponent(ActionCell, {
					menuActions: [
						{
							label: 'Manage access',
							icon: ShieldCheck,
							onClick: () => sheet.show(u.id, 'access')
						},
						...(protectedRow
							? []
							: [
									{
										label: u.active ? 'Deactivate' : 'Reactivate',
										icon: UserRoundX,
										onClick: () => setActive.mutate({ userId: u.id, active: !u.active })
									}
								])
					],
					deleteConfig: protectedRow
						? undefined
						: {
								title: `Delete ${u.name || u.email}?`,
								description: 'Their access ends right away. This cannot be undone.',
								confirmText: 'Delete',
								typeToConfirm: u.email,
								onDelete: () => remove.mutateAsync({ userId: u.id })
							}
				});
			}
		})
	]);
</script>

<UserSheet />
<InviteSheet bind:open={inviteOpen} />

<PageHeader title="Users" description="Everyone in this workspace, their role and their teams">
	{#if canManage}
		<Button onclick={() => (inviteOpen = true)}>
			<PlusIcon data-icon="inline-start" />
			Invite people
		</Button>
	{/if}
</PageHeader>

<DataTable
	data={list.data?.users ?? []}
	rowCount={list.data?.total ?? 0}
	isLoading={list.isLoading}
	{columns}
	bulkActions={canManage ? bulkActions : []}
	onRowClick={(u) => sheet.show(u.id)}
	emptyState={{
		icon: CircleUser,
		title: 'Nobody here yet',
		description: 'Invite people to this workspace.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			search
			searchResultCount={list.data?.total}
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
