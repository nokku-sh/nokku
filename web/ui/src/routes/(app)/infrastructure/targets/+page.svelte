<script lang="ts">
	import { page } from '$app/state';
	import { ca } from '$lib/api/certificates.svelte';
	import { target } from '$lib/api/targets.svelte';
	import TargetModal from '$lib/components/modals/TargetModal.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '$lib/components/tables';
	import {
		ActionCell,
		AvatarCell,
		PrincipalsCell,
		TagsCell,
		TimeCell
	} from '$lib/components/tables/cells';
	import { Button } from '$lib/components/ui/button';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { type Target, TargetSchema } from '$lib/gen/nokku/v1/target_pb';
	import { createEntityModalState } from '$lib/hooks';
	import { PencilIcon, Plus, Server, TagIcon, Trash2, UserIcon, IdCard } from '@lucide/svelte';
	import { Debounced } from 'runed';

	// Modal states
	const targetModal = createEntityModalState(TargetSchema);

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

	const columnHelper = createAppColumnHelper<Target>();
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
		columnHelper.accessor('caId', {
			header: 'CA',
			cell: ({ row }) => {
				return caData.data?.find((c) => c.id === row.original.caId)?.name;
			}
		}),
		columnHelper.display({
			id: 'principals',
			header: 'Principals',
			cell: ({ row }) => {
				return renderComponent(PrincipalsCell, { targetId: row.original.id });
			}
		}),
		columnHelper.accessor('tags', {
			header: 'Tags',
			cell: ({ row }) => {
				return renderComponent(TagsCell, { tags: row.original.tags });
			}
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
							onClick: () => targetModal.openEdit(row.original)
						}
					],

					deleteConfig: {
						itemName: row.original.name,
						description: 'Are you sure you want to delete this target?',
						onDelete: () => deleteTarget.mutate({ id: row.original.id })
					}
				});
			}
		})
	]);

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

<TargetModal bind:open={targetModal.open} draft={targetModal.draft} />

<PageHeader title="Targets" description="Manage your workspace targets" icon={Server}>
	<Button onclick={() => targetModal.openNew()}>
		<Plus data-icon="inline-start" />
		Create Target
	</Button>
</PageHeader>

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
>
	{#snippet toolbar(table)}
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
	{/snippet}
</DataTable>
