<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { team } from '$lib/api/team.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { roles } from '$lib/api/roles.svelte';
	import { roleIcon, roleLabel } from '$lib/roles';
	import InviteModal from '$lib/components/modals/InviteModal.svelte';
	import MemberModal from '$lib/components/modals/MemberModal.svelte';
	import TransferOwnerModal from '$lib/components/modals/TransferOwnerModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import RoleCell from '$lib/components/tables/cells/RoleCell.svelte';
	import TeamCell from '$lib/components/tables/cells/TeamCell.svelte';
	import UserCell from '$lib/components/tables/cells/UserCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import type { BulkAction } from '$lib/components/tables/types';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import { type WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import { createModalState } from '$lib/hooks';
	import {
		CircleUser,
		CircleUserIcon,
		CrownIcon,
		InfoIcon,
		PlusIcon,
		Trash2
	} from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';
	import { Debounced } from 'runed';

	// Modal states
	const memberModal = createModalState<WorkspaceMember>({} as WorkspaceMember);
	const inviteModal = createModalState();
	const transferOwnerModal = createModalState<WorkspaceMember>({} as WorkspaceMember);

	// Data
	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const members = $derived(
		workspace.listMembers(() => ({
			query: debounced.current,
			roleName: page.url.searchParams.get('role') || undefined
		}))
	);
	const teams = $derived(team.list());
	let table = $state<Table<WorkspaceMember>>();

	const removeMember = workspace.removeMember();
	const updateMember = workspace.updateMember();

	const bulkActions: BulkAction<WorkspaceMember>[] = [
		{
			type: 'button',
			label: 'Remove',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => removeMember.mutate({ userId: id }))
		}
	];

	const rolesQuery = $derived(roles.list());
	const roleOptions = $derived(
		(rolesQuery.data ?? []).map((r) => ({
			label: roleLabel(r.name),
			value: r.name,
			icon: roleIcon(r.name)
		}))
	);

	// Columns
	const columns: ColumnDef<WorkspaceMember>[] = [
		{
			header: 'Name',
			accessorKey: 'name',
			cell: ({ row }) => {
				return renderComponent(UserCell, { user: row.original });
			}
		},
		{
			accessorKey: 'username',
			header: 'Username',
			enableSorting: true,
			cell: ({ row }) => row.original.username
		},
		{
			header: 'Role',
			accessorKey: 'roleName',
			enableColumnFilter: true,
			cell: ({ row }) =>
				renderComponent(RoleCell, {
					roleName: row.original.roleName,
					update: (roleName) => updateMember.mutateAsync({ userId: row.original.id, roleName }),
					scope: 'users'
				})
		},
		{
			header: 'Teams',
			accessorKey: 'teams',
			enableColumnFilter: true,
			cell: ({ row }) => {
				const userTeams =
					teams.data?.teams?.filter((t) => t.members.find((m) => m.id === row.original.id)) ?? [];
				return renderComponent(TeamCell, { teams: userTeams });
			}
		},
		{
			id: 'actions',
			cell: ({ row }) => {
				return renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: InfoIcon,
							onClick: () => memberModal.openWith({ ...row.original })
						},
						{
							icon: PlusIcon,
							onClick: () =>
								goto(
									`/access/assign?type=${PrincipalType.USER}&id=${row.original.id}&name=${encodeURIComponent(row.original.name)}`
								)
						}
					],

					menuActions: [
						{
							label: 'Transfer Ownership',
							icon: CrownIcon,
							onClick: () => transferOwnerModal.openWith({ ...row.original })
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to remove this member from your workspace?',
						onDelete: () => removeMember.mutate({ userId: row.original.id }),
						requireTyping: true
					}
				});
			}
		}
	];
</script>

<MemberModal bind:open={memberModal.open} bind:data={memberModal.selected} />
<TransferOwnerModal
	bind:open={transferOwnerModal.open}
	targetMember={transferOwnerModal.selected}
/>
<InviteModal bind:open={inviteModal.open} />

<PageHeader title="Members" description="Manage your workspace members" icon={CircleUserIcon}>
	<Button onclick={() => inviteModal.openNew()}>
		<PlusIcon data-icon="inline-start" />
		Invite Member
	</Button>
</PageHeader>

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

<DataTable
	data={members.data?.members ?? []}
	rowCount={members.data?.total ?? 0}
	{columns}
	{bulkActions}
	emptyState={{
		icon: CircleUser,
		title: 'No Members',
		description: 'Get started by inviting a new member.'
	}}
	onTableReady={(t) => (table = t)}
/>
