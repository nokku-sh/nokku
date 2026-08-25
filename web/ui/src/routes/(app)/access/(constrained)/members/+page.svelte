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
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import { ActionCell, RoleCell, TeamCell, UserCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
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
	const columnHelper = createAppColumnHelper<WorkspaceMember>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) => {
				return renderComponent(UserCell, { user: row.original });
			}
		}),
		columnHelper.accessor('username', {
			header: 'Username',
			enableSorting: true,
			cell: ({ row }) => row.original.username
		}),
		columnHelper.accessor('roleName', {
			header: 'Role',
			enableColumnFilter: true,
			cell: ({ row }) =>
				renderComponent(RoleCell, {
					roleName: row.original.roleName,
					update: (roleName) => updateMember.mutateAsync({ userId: row.original.id, roleName }),
					scope: 'users'
				})
		}),
		columnHelper.display({
			id: 'teams',
			header: 'Teams',
			cell: ({ row }) => {
				const userTeams =
					teams.data?.teams?.filter((t) => t.members.find((m) => m.id === row.original.id)) ?? [];
				return renderComponent(TeamCell, { teams: userTeams });
			}
		}),
		columnHelper.display({
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
		})
	]);
</script>

<MemberModal bind:open={memberModal.open} data={memberModal.selected} />
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
