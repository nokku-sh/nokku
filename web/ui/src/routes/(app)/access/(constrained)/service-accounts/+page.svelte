<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import ServiceAccountModal from '$lib/components/modals/ServiceAccountModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import type { ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
	import { createModalState } from '$lib/hooks';
	import { pageIndex, pageSize } from '$lib/store.svelte';
	import type { BulkAction } from '$lib/components/tables/types';
	import { PencilIcon, PlusIcon, Trash2, Waypoints } from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';
	import { Debounced } from 'runed';
	import AvatarCell from '$lib/components/tables/cells/AvatarCell.svelte';

	const modal = createModalState<ServiceAccount>({} as ServiceAccount);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const saData = $derived(
		serviceAccount.list(() => ({
			limit: pageSize.current,
			offset: pageIndex.current * pageSize.current,
			query: debounced.current
		}))
	);

	const deleteSA = serviceAccount.delete();

	const bulkActions: BulkAction<ServiceAccount>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteSA.mutate({ id }))
		}
	];

	const columns: ColumnDef<ServiceAccount>[] = [
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
			header: 'Expiry',
			accessorKey: 'expiresAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.expiresAt })
		},
		{
			header: 'Last Used',
			accessorKey: 'lastUsedAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.lastUsedAt })
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
							onClick: () => modal.openWith({ ...row.original })
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
		}
	];

	let table = $state<Table<ServiceAccount>>();
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

<ServiceAccountModal bind:open={modal.open} data={modal.selected} />

<TableToolbar {table} search searchResultCount={saData.data?.total} />

<DataTable
	data={saData.data?.serviceAccounts ?? []}
	rowCount={saData.data?.total ?? 0}
	{columns}
	{bulkActions}
	onTableReady={(t) => (table = t)}
	emptyState={{
		icon: Waypoints,
		title: 'No Service Accounts',
		description: 'Create your first service account to enable API access and automation'
	}}
/>
