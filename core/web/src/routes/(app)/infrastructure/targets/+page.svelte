<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { page } from '$app/state';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import CreateTargetModal from '#lib/components/modals/CreateTargetModal.svelte';
	import TargetSheet from '#lib/components/sheets/TargetSheet.svelte';
	import {
		DataTable,
		TableToolbar,
		createAppColumnHelper,
		type BulkAction
	} from '#lib/components/tables/index.js';
	import {
		ActionCell,
		IdentityCell,
		TagsCell,
		TextCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { useCreate, usePagination, useSheet } from '#lib/hooks/index.js';
	import { IdCard, Plus, Server, ShieldCheck, TagIcon, Trash2, UserIcon } from '@lucide/svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	const can = user.can();
	const create = useCreate();

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const targets = target.list(() => ({
		...pager.args,
		query: debounced.current,
		caId: page.url.searchParams.get('ca') || undefined,
		tags: page.url.searchParams.get('tags')?.split(','),
		accounts: page.url.searchParams.get('accounts')?.split(',')
	}));

	const caData = ca.list();

	const filterData = target.filters();

	const uniqueTags = $derived(
		(filterData.data?.tags ?? [])
			.slice()
			.sort()
			.map((tag) => ({ label: tag, value: tag, icon: TagIcon }))
	);

	const uniqueAccounts = $derived(
		(filterData.data?.accounts ?? [])
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
				renderComponent(IdentityCell, {
					name: row.original.name,
					// The address people ssh to, so it is the line under the name.
					detail:
						row.original.metadata?.hostname ||
						row.original.endpoints[0] ||
						row.original.description,
					mono: !!(row.original.metadata?.hostname || row.original.endpoints[0])
				})
		}),
		columnHelper.accessor('caId', {
			header: 'CA',
			meta: { hideBelow: 'md' },
			cell: ({ row }) =>
				renderComponent(TextCell, {
					label: caData.data?.find((c) => c.id === row.original.caId)?.name ?? 'Default CA'
				})
		}),
		columnHelper.display({
			id: 'accounts',
			header: 'Accounts',
			cell: ({ row }) =>
				renderComponent(TagsCell, {
					tags: row.original.accounts.map((p) => p.username),
					mono: true,
					noun: 'accounts'
				})
		}),
		columnHelper.accessor('tags', {
			header: 'Tags',
			meta: { hideBelow: 'md' },
			cell: ({ row }) => renderComponent(TagsCell, { tags: row.original.tags })
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
								description:
									'Everyone loses access to this target. Its login accounts and grants are removed.',
								typeToConfirm: row.original.name,
								onDelete: () => deleteTarget.mutateAsync({ id: row.original.id })
							}
						: undefined
				});
			}
		})
	]);

	const bulkActions: BulkAction<Target>[] = [
		{
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

<CreateTargetModal bind:open={create.open} />
<TargetSheet />

<PageHeader title="Targets" description="Servers people log in to, and who can use which account">
	{#if can.edit}
		<Button onclick={() => (create.open = true)}>
			<Plus data-icon="inline-start" />
			Add target
		</Button>
	{/if}
</PageHeader>

<DataTable
	data={targets.data?.targets ?? []}
	rowCount={targets.data?.total ?? 0}
	isLoading={targets.isLoading}
	error={targets.error}
	onRetry={targets.refetch}
	rowLabel={(t) => t.name}
	{columns}
	bulkActions={can.edit ? bulkActions : []}
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
					title: 'Accounts',
					options: uniqueAccounts,
					param: 'accounts'
				}
			]}
		/>
	{/snippet}
</DataTable>
