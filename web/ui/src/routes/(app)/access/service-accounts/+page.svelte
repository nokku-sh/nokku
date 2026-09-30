<script lang="ts">
	import { plural } from '$lib/api/bulk';
	import { page } from '$app/state';
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import CreateServiceAccountModal from '$lib/components/modals/CreateServiceAccountModal.svelte';
	import ServiceAccountSheet from '$lib/components/sheets/ServiceAccountSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import { ActionCell, AvatarCell, RoleCell, TimeCell } from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/layout/PageHeader.svelte';
	import type { ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
	import { confirm, usePagination, useSheet } from '$lib/hooks';
	import { PlusIcon, ShieldCheck, Trash2, Waypoints } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { roles } from '$lib/api/roles.svelte';
	import { roleIcon, roleLabel } from '$lib/roles';

	const sheet = useSheet();
	let createOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const saData = serviceAccount.list(() => ({
		...pager.args,
		query: debounced.current,
		roleName: page.url.searchParams.get('role') || undefined
	}));

	const deleteSA = serviceAccount.delete();
	const deleteSAs = serviceAccount.deleteMany();
	const updateSA = serviceAccount.update();

	const bulkActions: BulkAction<ServiceAccount>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'service account')}?`,
				description: 'This action cannot be undone.',
				confirmText: 'Delete'
			}),
			onClick: (selected) => deleteSAs.mutateAsync(selected.map(({ id }) => ({ id })))
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
					update: (roleName) => updateSA.mutateAsync({ id: row.original.id, roleName })
				})
		}),
		columnHelper.accessor('expiresAt', {
			header: 'Expiry',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.expiresAt })
		}),
		columnHelper.accessor('lastUsedAt', {
			header: 'Last used',
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
					menuActions: [
						{
							label: 'Manage access',
							icon: ShieldCheck,
							onClick: () => sheet.show(row.original.id, 'access')
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Its token stops working right away and every grant is removed.',
						typeToConfirm: row.original.name,
						onDelete: () => deleteSA.mutateAsync({ id: row.original.id })
					}
				});
			}
		})
	]);
</script>

<PageHeader
	title="Service accounts"
	description="API identities for CI, Ansible and other automation"
>
	<Button onclick={() => (createOpen = true)}>
		<PlusIcon data-icon="inline-start" />
		Create service account
	</Button>
</PageHeader>

<CreateServiceAccountModal bind:open={createOpen} />
<ServiceAccountSheet />

<DataTable
	data={saData.data?.serviceAccounts ?? []}
	rowCount={saData.data?.total ?? 0}
	isLoading={saData.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(sa) => sheet.show(sa.id)}
	emptyState={{
		icon: Waypoints,
		title: 'No service accounts yet',
		description: 'Give CI and automation their own identity and token.'
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
