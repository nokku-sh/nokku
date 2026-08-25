<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import ServiceAccountModal from '$lib/components/modals/ServiceAccountModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import { ActionCell, AvatarCell, RoleCell, TimeCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import type { ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
	import { ServiceAccountSchema } from '$lib/gen/nokku/v1/service_account_pb';
	import { createEntityModalState } from '$lib/hooks';
	import { PencilIcon, PlusIcon, Trash2, Waypoints } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { roles } from '$lib/api/roles.svelte';
	import { roleIcon, roleLabel } from '$lib/roles';

	const modal = createEntityModalState(ServiceAccountSchema);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const saData = $derived(
		serviceAccount.list(() => ({
			query: debounced.current,
			roleName: page.url.searchParams.get('role') || undefined
		}))
	);

	const deleteSA = serviceAccount.delete();
	const updateSA = serviceAccount.update();

	const bulkActions: BulkAction<ServiceAccount>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteSA.mutate({ id }))
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

	const columnHelper = createAppColumnHelper<ServiceAccount>();
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
		columnHelper.accessor('roleName', {
			header: 'Role',
			cell: ({ row }) =>
				renderComponent(RoleCell, {
					roleName: row.original.roleName,
					update: (roleName) => updateSA.mutateAsync({ id: row.original.id, roleName }),
					scope: 'serviceAccounts'
				})
		}),
		columnHelper.accessor('expiresAt', {
			header: 'Expiry',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.expiresAt })
		}),
		columnHelper.accessor('lastUsedAt', {
			header: 'Last Used',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.lastUsedAt })
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
							onClick: () => modal.openEdit(row.original)
						},
						{
							icon: PlusIcon,
							onClick: () =>
								goto(
									`/access/assign?type=${PrincipalType.SERVICE_ACCOUNT}&id=${row.original.id}&name=${encodeURIComponent(row.original.name)}`
								)
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to delete this service account?',
						onDelete: () => deleteSA.mutate({ id: row.original.id })
					}
				});
			}
		})
	]);
</script>

<PageHeader
	title="Service Accounts"
	description="Manage service accounts for API access, automation and CI/CD workflows"
	icon={Waypoints}
>
	<Button onclick={() => modal.openNew()}>
		<PlusIcon data-icon="inline-start" />
		Add Service Account
	</Button>
</PageHeader>

<ServiceAccountModal bind:open={modal.open} draft={modal.draft} />

<DataTable
	data={saData.data?.serviceAccounts ?? []}
	rowCount={saData.data?.total ?? 0}
	{columns}
	{bulkActions}
	emptyState={{
		icon: Waypoints,
		title: 'No Service Accounts',
		description: 'Create your first service account to enable API access and automation'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			{table}
			search
			searchResultCount={saData.data?.total}
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
