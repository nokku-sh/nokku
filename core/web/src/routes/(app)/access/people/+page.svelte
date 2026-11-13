<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { page } from '$app/state';
	import { auth, whenFresh } from '#lib/api/auth.svelte.js';
	import { userDeleteWarning, users } from '#lib/api/workspaces.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { roles } from '#lib/api/roles.svelte.js';
	import { parseRole, roleIcon, roleLabel, roleSlug } from '#lib/roles.js';
	import AccessReportMenu from '#lib/components/access/AccessReportMenu.svelte';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import UserSheet from '#lib/components/sheets/UserSheet.svelte';
	import {
		DataTable,
		bulkDelete,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		RoleCell,
		StateCell,
		TeamCell,
		UserCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';
	import { confirm, useCreate, usePagination, useSheet } from '#lib/hooks/index.js';
	import { CircleUser, PlusIcon, ShieldCheck, UserRoundX } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	const create = useCreate({ fresh: true });

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const me = user.self();
	const can = user.can();
	// An invited account signs in without a provider, so a workspace that requires SSO takes none.
	// Passkeys are off exactly then.
	const options = auth.options();
	const canInvite = $derived(can.admin && !!options.data?.passkey);

	const pager = usePagination();
	const list = users.list(() => ({
		...pager.args,
		query: debounced.current,
		role: parseRole(page.url.searchParams.get('role'))
	}));

	const remove = users.delete();
	const removeMany = users.deleteMany();

	const setActive = users.setActive();

	// The owner and you are never in a bulk delete, the server refuses both.
	const bulkActions: BulkAction<User>[] = [
		bulkDelete<User>({
			noun: 'account',
			name: (u) => u.name || u.email,
			skip: (u) => u.role === WorkspaceRole.OWNER || u.id === me.data?.id,
			description: 'Their access ends right away. This cannot be undone.',
			run: (selected) => removeMany.mutateAsync(selected.map(({ id }) => ({ userId: id })))
		})
	];

	const rolesQuery = roles.list();
	const roleOptions = $derived(
		(rolesQuery.data ?? []).map((r) => ({
			label: roleLabel(r.role),
			value: roleSlug(r.role),
			icon: roleIcon(r.role)
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
			cell: ({ row }) => renderComponent(RoleCell, { role: row.original.role })
		}),
		columnHelper.accessor('active', {
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(StateCell, {
					label: row.original.active ? 'Active' : 'Deactivated',
					tone: row.original.active ? 'success' : 'muted'
				})
		}),
		columnHelper.display({
			id: 'teams',
			header: 'Teams',
			meta: { hideBelow: 'md' },
			cell: ({ row }) => renderComponent(TeamCell, { userId: row.original.id })
		}),
		columnHelper.display({
			id: 'actions',
			cell: ({ row }) => {
				const u = row.original;
				const protectedRow = u.role === WorkspaceRole.OWNER || u.id === me.data?.id || !can.admin;
				return renderComponent(ActionCell, {
					label: u.name || u.email,
					id: u.id,
					link: true,
					menuActions: [
						{
							label: can.edit ? 'Manage access' : 'View access',
							icon: ShieldCheck,
							onClick: () => sheet.show(u.id, 'access')
						},
						...(protectedRow
							? []
							: [
									{
										label: u.active ? 'Deactivate' : 'Reactivate',
										icon: UserRoundX,
										onClick: () =>
											u.active
												? confirm({
														title: `Deactivate ${u.name || u.email}?`,
														description:
															'Every session ends right away. You can reactivate them later.',
														confirmText: 'Deactivate',
														onConfirm: () => setActive.mutateAsync({ userId: u.id, active: false })
													})
												: whenFresh(() => setActive.mutate({ userId: u.id, active: true }))
									}
								])
					],
					deleteConfig: protectedRow
						? undefined
						: {
								title: `Delete ${u.name || u.email}?`,
								description: () => userDeleteWarning(u.id),
								confirmText: 'Delete',
								onDelete: () => remove.mutateAsync({ userId: u.id })
							}
				});
			}
		})
	]);
</script>

<UserSheet />
{#if canInvite}
	<InviteSheet bind:open={create.open} />
{/if}

<PageHeader title="People" description="Everyone in this workspace, their role and their teams">
	{#if can.view}
		<AccessReportMenu />
	{/if}
	{#if canInvite}
		<Button onclick={() => (create.open = true)}>
			<PlusIcon data-icon="inline-start" />
			Invite people
		</Button>
	{/if}
</PageHeader>

<DataTable
	data={list.data?.users ?? []}
	rowCount={list.data?.total ?? 0}
	isLoading={list.isLoading}
	error={list.error}
	onRetry={list.refetch}
	{columns}
	bulkActions={can.admin ? bulkActions : []}
	onRowClick={(u) => sheet.show(u.id)}
	rowLabel={(u) => u.name || u.email}
	emptyState={{
		icon: CircleUser,
		title: 'Nobody here yet',
		description: canInvite
			? 'Invite people to this workspace.'
			: 'People show up here once they are invited or sign in with single sign-on.'
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
