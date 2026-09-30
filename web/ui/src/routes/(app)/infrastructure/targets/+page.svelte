<script lang="ts">
	import { plural } from '$lib/api/bulk';
	import { page } from '$app/state';
	import { ca } from '$lib/api/certificates.svelte';
	import { target } from '$lib/api/targets.svelte';
	import CreateTargetModal from '$lib/components/modals/CreateTargetModal.svelte';
	import TargetSheet from '$lib/components/sheets/TargetSheet.svelte';
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
	import PageHeader from '$lib/components/layout/PageHeader.svelte';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { confirm, usePagination, useSheet } from '$lib/hooks';
	import { IdCard, Plus, Server, ShieldCheck, TagIcon, Trash2, UserIcon } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	let createOpen = $state(false);

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const targets = target.list(() => ({
		...pager.args,
		query: debounced.current,
		caId: page.url.searchParams.get('ca') || undefined,
		tags: page.url.searchParams.get('tags')?.split(','),
		principals: page.url.searchParams.get('principals')?.split(',')
	}));

	const caData = ca.list();

	const filterData = target.filters();

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
	const deleteTargets = target.deleteMany();

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
					menuActions: [
						{
							label: 'Manage access',
							icon: ShieldCheck,
							onClick: () => sheet.show(row.original.id, 'access')
						}
					],
					deleteConfig: {
						itemName: row.original.name,
						description:
							'Everyone loses access to this target. Its login accounts and grants are removed.',
						typeToConfirm: row.original.name,
						onDelete: () => deleteTarget.mutateAsync({ id: row.original.id })
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
			confirm: (selected) => ({
				title: `Delete ${plural(selected.length, 'target')}?`,
				description: 'This action cannot be undone.',
				confirmText: 'Delete'
			}),
			onClick: (selected) => deleteTargets.mutateAsync(selected.map(({ id }) => ({ id })))
		}
	];
</script>

<CreateTargetModal bind:open={createOpen} />
<TargetSheet />

<PageHeader title="Targets" description="Servers people log in to, and who can use which account">
	<Button onclick={() => (createOpen = true)}>
		<Plus data-icon="inline-start" />
		Add target
	</Button>
</PageHeader>

<DataTable
	data={targets.data?.targets ?? []}
	rowCount={targets.data?.total ?? 0}
	isLoading={targets.isLoading}
	{columns}
	{bulkActions}
	onRowClick={(t) => sheet.show(t.id)}
	emptyState={{
		icon: Server,
		title: 'No targets yet',
		description: 'Add a server, then pick who can log in and as which account.',
		command: 'nk sync root@host'
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
