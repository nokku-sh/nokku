<script lang="ts">
	import { page } from '$app/state';
	import { ca } from '$lib/api/certificates.svelte';
	import { target } from '$lib/api/targets.svelte';
	import TargetModal from '$lib/components/modals/TargetModal.svelte';
	import ActionCell from '$lib/components/tables/cells/ActionCell.svelte';
	import AvatarCell from '$lib/components/tables/cells/AvatarCell.svelte';
	import PrincipalsCell from '$lib/components/tables/cells/PrincipalsCell.svelte';
	import TagsCell from '$lib/components/tables/cells/TagsCell.svelte';
	import TimeCell from '$lib/components/tables/cells/TimeCell.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import TableToolbar from '$lib/components/tables/TableToolbar.svelte';
	import type { BulkAction } from '$lib/components/tables/types';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '$lib/components/ui/data-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { type Target } from '$lib/gen/nokku/v1/target_pb';
	import { createModalState } from '$lib/hooks';
	import { PencilIcon, Plus, Server, TagIcon, Trash2, UserIcon, IdCard } from '@lucide/svelte';
	import type { ColumnDef, Table } from '@tanstack/table-core';
	import { Debounced } from 'runed';

	// Modal states
	const targetModal = createModalState<Target>({} as Target);

	let table = $state<Table<Target>>();

	// Data
	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const targets = $derived(
		target.list(() => ({
			query: debounced.current,
			caId: page.url.searchParams.get('ca') || undefined,
			tags: page.url.searchParams.get('tags')?.split(','),
			principals: page.url.searchParams.get('principals')?.split(',')
		}))
	);

	const caData = $derived(ca.list());

	const filterData = $derived(target.filters());

	const uniqueTags = $derived(
		(filterData.data?.tags ?? [])
			.slice()
			.sort()
			.map((tag) => ({ label: tag, value: tag, icon: TagIcon }))
	);

	const uniquePrincipals = $derived(
		(filterData.data?.principals ?? [])
			.slice()
			.sort()
			.map((username) => ({ label: username, value: username, icon: UserIcon }))
	);

	const deleteTarget = target.delete();

	const columns: ColumnDef<Target>[] = [
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
			header: 'CA',
			accessorKey: 'caId',
			cell: ({ row }) => {
				return caData.data?.find((c) => c.id === row.original.caId)?.name;
			}
		},
		{
			header: 'Principals',
			id: 'principals',
			cell: ({ row }) => {
				return renderComponent(PrincipalsCell, { targetId: row.original.id });
			}
		},
		{
			header: 'Tags',
			accessorKey: 'tags',
			cell: ({ row }) => {
				return renderComponent(TagsCell, { tags: row.original.tags });
			}
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
							onClick: () => targetModal.openWith({ ...row.original })
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to delete this target?',
						onDelete: () => deleteTarget.mutate({ id: row.original.id })
					}
				});
			}
		}
	];

	const bulkActions: BulkAction<Target>[] = [
		{
			type: 'button',
			label: 'Delete',
			icon: Trash2,
			variant: 'destructive',
			onClick: (selected) => selected.forEach(({ id }) => deleteTarget.mutate({ id }))
		}
	];
</script>

<TargetModal bind:open={targetModal.open} bind:data={targetModal.selected} />

<PageHeader title="Targets" description="Manage your workspace targets" icon={Server}>
	<Button onclick={() => targetModal.openNew()}>
		<Plus data-icon="inline-start" />
		Create Target
	</Button>
</PageHeader>

<TableToolbar
	search
	searchResultCount={targets.data?.total}
	{table}
	filters={[
		{
			title: 'CA',
			options: caData.data?.map((c) => ({ label: c.name, value: c.id, icon: IdCard })) ?? [],
			param: 'ca',
			mode: 'single'
		},
		{
			title: 'Tags',
			options: uniqueTags,
			param: 'tags'
		},
		{
			title: 'Principals',
			options: uniquePrincipals,
			param: 'principals'
		}
	]}
/>

<DataTable
	data={targets.data?.targets ?? []}
	rowCount={targets.data?.total ?? 0}
	{columns}
	{bulkActions}
	emptyState={{
		icon: Server,
		title: 'No Targets',
		description: "You haven't created any targets yet. Get started by creating your first target."
	}}
	onTableReady={(t) => (table = t)}
/>
