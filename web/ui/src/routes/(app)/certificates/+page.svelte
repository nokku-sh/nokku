<script lang="ts">
	import { page } from '$app/state';
	import { ca } from '$lib/api/certificates.svelte';
	import { createModalState } from '$lib/hooks';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import CAModal from '$lib/components/modals/CAModal.svelte';
	import SignModal from '$lib/components/modals/SignModal.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import BadgeCell from '$lib/components/tables/cells/BadgeCell.svelte';
	import CANameCell from '$lib/components/tables/cells/CANameCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import CAStatusCell from '$lib/components/tables/cells/CAStatusCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import type { BulkAction } from '$lib/components/tables/types';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import {
		AuthorityType,
		CertificateKeyType,
		type CertificateAuthority
	} from '$lib/gen/nokku/v1/certificates_pb';
	import { enumLabel } from '$lib/utils';
	import { KeyRound, Pencil, Plus, Shield, ShieldAlert, Trash2 } from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';

	const caModal = createModalState<CertificateAuthority>({} as CertificateAuthority);
	const signModal = createModalState<CertificateAuthority>({} as CertificateAuthority);
	const deleteModal = createModalState<CertificateAuthority>({} as CertificateAuthority);
	const rolloverModal = createModalState<CertificateAuthority>({} as CertificateAuthority);

	const caData = $derived(ca.list());
	const deleteCA = ca.delete();
	const rolloverAction = ca.rollover();

	const search = $derived(page.url.searchParams.get('q') || '');
	const typeFilter = $derived(page.url.searchParams.get('type')?.split(',').filter(Boolean) || []);

	const filteredCAs = $derived(
		(caData.data || []).filter((c) => {
			if (
				search &&
				!c.name?.toLowerCase().includes(search.toLowerCase()) &&
				!c.description?.toLowerCase().includes(search.toLowerCase())
			)
				return false;
			if (typeFilter.length > 0) {
				const typeName = AuthorityType[c.authorityType];
				if (!typeFilter.includes(typeName)) return false;
			}
			return true;
		})
	);

	const authorityTypeOptions = [
		{ label: 'SSH', value: 'SSH', icon: KeyRound },
		{ label: 'X.509', value: 'X509', icon: Shield }
	];

	let table = $state<Table<CertificateAuthority>>();
	const columns: ColumnDef<CertificateAuthority>[] = [
		{
			header: 'Name',
			accessorKey: 'name',
			cell: ({ row }) => renderComponent(CANameCell, { ca: row.original })
		},
		{
			header: 'Type',
			accessorKey: 'authorityType',
			cell: ({ row }) =>
				renderComponent(BadgeCell, {
					value: enumLabel(AuthorityType[row.original.authorityType]).toUpperCase(),
					variant: row.original.authorityType === AuthorityType.SSH ? 'default' : 'secondary'
				})
		},
		{
			header: 'Status',
			accessorKey: 'isActive',
			cell: ({ row }) => renderComponent(CAStatusCell, { caItem: row.original })
		},
		{
			header: 'Key',
			accessorKey: 'keyType',
			cell: ({ row }) => {
				let label = enumLabel(CertificateKeyType[row.original.keyType]);
				if (row.original.keyType !== CertificateKeyType.ED25519 && row.original.keyBits) {
					label += ` ${row.original.keyBits}-bit`;
				}
				return renderComponent(BadgeCell, { value: label, variant: 'outline' });
			}
		},
		{
			header: 'Valid Until',
			accessorKey: 'notAfter',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.notAfter })
		},
		{
			header: 'Created',
			accessorKey: 'createdAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.createdAt })
		},
		{
			header: 'Updated',
			accessorKey: 'updatedAt',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.updatedAt })
		},
		{
			id: 'actions',
			cell: ({ row }) => {
				const item = row.original;
				return renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: Pencil,
							onClick: () => caModal.openWith({ ...row.original })
						},
						{
							icon: item.authorityType === AuthorityType.SSH ? KeyRound : Shield,
							onClick: () => signModal.openWith({ ...item })
						}
					],
					menuActions: [
						{
							label: 'Emergency Rollover',
							icon: ShieldAlert,
							isDestructive: true,
							onClick: () => rolloverModal.openWith({ ...item })
						}
					],
					deleteConfig: {
						itemName: row.original.name,
						title: 'Delete Certificate Authority',
						description:
							'This will permanently delete the CA and revoke all certificates signed by it. This action cannot be undone.',
						onDelete: () => deleteCA.mutate({ id: row.original.id }),
						requireTyping: true
					}
				});
			}
		}
	];

	const bulkActions: BulkAction<CertificateAuthority>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteCA.mutate({ id }))
		}
	];
</script>

<CAModal bind:open={caModal.open} data={caModal.selected} />
<SignModal bind:open={signModal.open} ca={signModal.selected} />

<DeleteConfirmationModal
	bind:open={deleteModal.open}
	title="Delete Certificate Authority"
	description="This will permanently delete the CA and revoke all certificates signed by it. This action cannot be undone."
	itemName={deleteModal.selected?.name}
	requireConfirmation={true}
	onConfirm={() => deleteCA.mutate({ id: deleteModal.selected.id })}
/>

<DeleteConfirmationModal
	bind:open={rolloverModal.open}
	title="{rolloverModal.selected?.name} - Emergency Rollover"
	description="This will instantly revoke the current CA and replace it with a new one. All active connections relying on the previous CA will fail until they receive the new CA. Are you absolutely sure?"
	itemName={rolloverModal.selected?.name}
	onConfirm={() => rolloverAction.mutate({ id: rolloverModal.selected.id })}
	submitText="Rollover"
/>

<div class="container mx-auto max-w-6xl space-y-6 p-6">
	<PageHeader
		title="Certificate Authorities"
		description="Manage SSH and X.509 certificate authorities and their signing policies"
		icon={Shield}
	>
		<Button onclick={() => caModal.openNew()}>
			<Plus size={16} />
			Create CA
		</Button>
	</PageHeader>

	<TableToolbar
		search
		searchResultCount={filteredCAs.length}
		{table}
		filters={[
			{
				title: 'Type',
				options: authorityTypeOptions,
				param: 'type'
			}
		]}
	/>

	<DataTable
		data={filteredCAs}
		{columns}
		{bulkActions}
		emptyState={{
			icon: Shield,
			title: 'No Certificate Authorities',
			description: 'Create your first CA to start signing certificates.'
		}}
		onTableReady={(t) => (table = t)}
	/>
</div>
