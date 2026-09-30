<script lang="ts">
	import { page } from '$app/state';
	import { ca } from '$lib/api/certificates.svelte';
	import { plural } from '$lib/api/bulk';
	import { confirm, createModalState, useSheet } from '$lib/hooks';
	import PageHeader from '$lib/components/layout/PageHeader.svelte';
	import CreateCAModal from '$lib/components/modals/CreateCAModal.svelte';
	import CASheet from '$lib/components/sheets/CASheet.svelte';
	import SignModal from '$lib/components/modals/SignModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import {
		ActionCell,
		BadgeCell,
		CANameCell,
		CAStatusCell,
		TimeCell
	} from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import {
		AuthorityType,
		CertificateKeyType,
		type CertificateAuthority
	} from '$lib/gen/nokku/v1/certificates_pb';
	import { enumLabel } from '$lib/utils';
	import { KeyRound, Plus, Shield, ShieldAlert, Trash2 } from '@lucide/svelte';

	const sheet = useSheet();
	let createOpen = $state(false);
	const signModal = createModalState<CertificateAuthority>({} as CertificateAuthority);

	const caData = ca.list();
	const deleteCA = ca.delete();
	const deleteCAs = ca.deleteMany();
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

	const columnHelper = createAppColumnHelper<CertificateAuthority>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) => renderComponent(CANameCell, { ca: row.original })
		}),
		columnHelper.accessor('authorityType', {
			header: 'Type',
			cell: ({ row }) =>
				renderComponent(BadgeCell, {
					value: enumLabel(AuthorityType[row.original.authorityType]).toUpperCase(),
					variant: row.original.authorityType === AuthorityType.SSH ? 'default' : 'secondary'
				})
		}),
		columnHelper.accessor('isActive', {
			header: 'Status',
			cell: ({ row }) => renderComponent(CAStatusCell, { caItem: row.original })
		}),
		columnHelper.accessor('keyType', {
			header: 'Key',
			cell: ({ row }) => {
				let label = enumLabel(CertificateKeyType[row.original.keyType]);
				if (row.original.keyType !== CertificateKeyType.ED25519 && row.original.keyBits) {
					label += ` ${row.original.keyBits}-bit`;
				}
				return renderComponent(BadgeCell, { value: label, variant: 'outline' });
			}
		}),
		columnHelper.accessor('notAfter', {
			header: 'Valid until',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.notAfter })
		}),
		columnHelper.accessor('createdAt', {
			header: 'Created',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.createdAt })
		}),
		columnHelper.accessor('updatedAt', {
			header: 'Updated',
			cell: ({ row }) => renderComponent(TimeCell, { ts: row.original.updatedAt })
		}),
		columnHelper.display({
			id: 'actions',
			cell: ({ row }) => {
				const item = row.original;
				return renderComponent(ActionCell, {
					inlineActions: [
						{
							icon: item.authorityType === AuthorityType.SSH ? KeyRound : Shield,
							onClick: () => signModal.openWith({ ...item })
						}
					],
					menuActions: [
						{
							label: 'Emergency rollover',
							icon: ShieldAlert,
							isDestructive: true,
							onClick: () =>
								confirm({
									title: `Emergency rollover of ${item.name}?`,
									description:
										'This instantly revokes the current CA and replaces it with a new one. Connections relying on the old CA fail until they receive the new one.',
									confirmText: 'Rollover',
									typeToConfirm: item.name,
									onConfirm: () => rolloverAction.mutateAsync({ id: item.id })
								})
						}
					],
					deleteConfig: {
						itemName: row.original.name,
						description: 'Every certificate it signed stops being trusted. This cannot be undone.',
						typeToConfirm: row.original.name,
						onDelete: () => deleteCA.mutateAsync({ id: row.original.id })
					}
				});
			}
		})
	]);

	const bulkActions: BulkAction<CertificateAuthority>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'certificate authority', 'certificate authorities')}?`,
				description: 'This revokes every certificate they signed. This action cannot be undone.'
			}),
			onClick: (selected) => deleteCAs.mutateAsync(selected.map(({ id }) => ({ id })))
		}
	];
</script>

<CreateCAModal bind:open={createOpen} />
<CASheet />
<SignModal bind:open={signModal.open} ca={signModal.selected} />

<PageHeader
	title="Certificate authorities"
	description="The SSH and X.509 CAs that sign every login, and their policies"
>
	<Button onclick={() => (createOpen = true)}>
		<Plus data-icon="inline-start" />
		Create CA
	</Button>
</PageHeader>

<DataTable
	data={filteredCAs}
	isLoading={caData.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(c) => sheet.show(c.id)}
	emptyState={{
		icon: Shield,
		title: 'No certificate authorities yet',
		description: 'Create your first CA to start signing certificates.'
	}}
>
	{#snippet toolbar(table)}
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
	{/snippet}
</DataTable>
