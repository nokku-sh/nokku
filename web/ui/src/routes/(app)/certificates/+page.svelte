<script lang="ts">
	import { page } from '$app/state';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { plural } from '#lib/api/bulk.js';
	import { confirm, createModalState, useCreate, useSheet } from '#lib/hooks/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import CreateCAModal from '#lib/components/modals/CreateCAModal.svelte';
	import CASheet from '#lib/components/sheets/CASheet.svelte';
	import SignModal from '#lib/components/modals/SignModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		BadgeCell,
		CANameCell,
		CAStatusCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import {
		CertificateKeyType,
		type CertificateAuthority
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { enumLabel } from '#lib/utils.js';
	import { KeyRound, Plus, Shield, ShieldAlert, Trash2 } from '@lucide/svelte';

	const sheet = useSheet();
	const can = user.can();
	const create = useCreate();
	const signModal = createModalState<CertificateAuthority>({} as CertificateAuthority);

	const caData = ca.list();
	const deleteCA = ca.delete();
	const deleteCAs = ca.deleteMany();
	const rolloverAction = ca.rollover();

	const search = $derived(page.url.searchParams.get('q') || '');

	const filteredCAs = $derived(
		(caData.data || []).filter((c) => {
			if (
				search &&
				!c.name?.toLowerCase().includes(search.toLowerCase()) &&
				!c.description?.toLowerCase().includes(search.toLowerCase())
			)
				return false;
			return true;
		})
	);

	const columnHelper = createAppColumnHelper<CertificateAuthority>();
	const columns = columnHelper.columns([
		columnHelper.accessor('name', {
			header: 'Name',
			cell: ({ row }) => renderComponent(CANameCell, { ca: row.original })
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
							label: 'Sign',
							icon: KeyRound,
							onClick: () => signModal.openWith({ ...item })
						}
					],
					menuActions: !can.edit
						? []
						: [
								{
									label: 'Emergency rollover',
									icon: ShieldAlert,
									isDestructive: true,
									onClick: () =>
										confirm({
											title: `Emergency rollover of ${item.name}?`,
											description:
												'The current key stops being trusted at once and a new one replaces it. People get a new certificate at their next connection. Servers without the daemon trust the old key until the next nk sync.',
											confirmText: 'Roll over',
											typeToConfirm: item.name,
											onConfirm: () =>
												rolloverAction.mutateAsync({ id: item.id, revokePrevious: true })
										})
								}
							],
					deleteConfig: can.edit
						? {
								itemName: row.original.name,
								description:
									'Every certificate it signed stops being trusted. This cannot be undone.',
								typeToConfirm: row.original.name,
								onDelete: () => deleteCA.mutateAsync({ id: row.original.id })
							}
						: undefined
				});
			}
		})
	]);

	const bulkActions: BulkAction<CertificateAuthority>[] = [
		{
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

<CreateCAModal bind:open={create.open} />
<CASheet />
<SignModal bind:open={signModal.open} ca={signModal.selected} />

<PageHeader
	title="Certificate authorities"
	description="The SSH and X.509 CAs that sign every login, and their policies"
>
	{#if can.edit}
		<Button onclick={() => (create.open = true)}>
			<Plus data-icon="inline-start" />
			Create CA
		</Button>
	{/if}
</PageHeader>

<DataTable
	data={filteredCAs}
	isLoading={caData.isLoading}
	{columns}
	bulkActions={can.edit ? bulkActions : []}
	onRowClick={(c) => sheet.show(c.id)}
	emptyState={{
		icon: Shield,
		title: 'No certificate authorities yet',
		description: 'Create your first CA to start signing certificates.'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar search searchResultCount={filteredCAs.length} {table} />
	{/snippet}
</DataTable>
