<script lang="ts">
	import { page } from '$app/state';
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import CreateServiceAccountModal from '#lib/components/modals/CreateServiceAccountModal.svelte';
	import ServiceAccountSheet from '#lib/components/sheets/ServiceAccountSheet.svelte';
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
		RoleCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { ServiceAccount } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { useCreate, usePagination, useSheet } from '#lib/hooks/index.js';
	import { PlusIcon, ShieldCheck, Waypoints } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { roles } from '#lib/api/roles.svelte.js';
	import {
		parseRole,
		roleIcon,
		roleLabel,
		roleSlug,
		SERVICE_ACCOUNT_MAX_ROLE
	} from '#lib/roles.js';

	const sheet = useSheet();
	const can = user.can();
	const create = useCreate();

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const saData = serviceAccount.list(() => ({
		...pager.args,
		query: debounced.current,
		role: parseRole(page.url.searchParams.get('role'))
	}));

	const deleteSA = serviceAccount.delete();
	const deleteSAs = serviceAccount.deleteMany();

	const bulkActions: BulkAction<ServiceAccount>[] = [
		bulkDelete<ServiceAccount>({
			noun: 'service account',
			run: (selected) => deleteSAs.mutateAsync(selected.map(({ id }) => ({ id })))
		})
	];

	const rolesQuery = roles.list();
	const roleOptions = $derived(
		(rolesQuery.data ?? [])
			.filter((r) => r.role <= SERVICE_ACCOUNT_MAX_ROLE)
			.map((r) => ({
				label: roleLabel(r.role),
				value: roleSlug(r.role),
				icon: roleIcon(r.role)
			}))
	);

	const columnHelper = createAppColumnHelper<ServiceAccount>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) =>
				renderComponent(IdentityCell, {
					name: row.original.name,
					detail: row.original.description
				})
		}),
		columnHelper.accessor('role', {
			header: 'Role',
			cell: ({ row }) => renderComponent(RoleCell, { role: row.original.role })
		}),
		columnHelper.accessor('lastUsedAt', {
			header: 'Last used',
			meta: { hideBelow: 'md' },
			cell: ({ row }) =>
				renderComponent(TimeCell, {
					ts: row.original.lastUsedAt,
					fallback: 'Never',
					emphasize: 'relative'
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
								description: 'Every token stops working right away and every grant is removed.',
								typeToConfirm: row.original.name,
								onDelete: () => deleteSA.mutateAsync({ id: row.original.id })
							}
						: undefined
				});
			}
		})
	]);
</script>

<PageHeader
	title="Service accounts"
	description="API identities for CI, Ansible and other automation"
>
	{#if can.edit}
		<Button onclick={() => (create.open = true)}>
			<PlusIcon data-icon="inline-start" />
			Create service account
		</Button>
	{/if}
</PageHeader>

<CreateServiceAccountModal bind:open={create.open} />
<ServiceAccountSheet />

<DataTable
	data={saData.data?.serviceAccounts ?? []}
	rowCount={saData.data?.total ?? 0}
	isLoading={saData.isLoading}
	error={saData.error}
	onRetry={saData.refetch}
	rowLabel={(sa) => sa.name}
	{columns}
	bulkActions={can.edit ? bulkActions : []}
	onRowClick={(sa) => sheet.show(sa.id)}
	emptyState={{
		icon: Waypoints,
		title: 'No service accounts yet',
		description: 'Give CI and automation their own identity and tokens.'
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
