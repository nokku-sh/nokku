<script lang="ts">
	import { page } from '$app/state';
	import { plural } from '#lib/api/bulk.js';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import { deleteWarning, target } from '#lib/api/targets.svelte.js';
	import { token } from '#lib/api/tokens.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import AddServerModal from '#lib/components/modals/AddServerModal.svelte';
	import CreateTargetModal from '#lib/components/modals/CreateTargetModal.svelte';
	import EnrollSheet from '#lib/components/sheets/EnrollSheet.svelte';
	import TargetSheet from '#lib/components/sheets/TargetSheet.svelte';
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
		TagsCell,
		TimeCell
	} from '#lib/components/tables/cells/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { DaemonStatus } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { renderComponent } from '@tanstack/svelte-table';
	import { TargetStatus, type Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { useCreate, usePagination, useSheet } from '#lib/hooks/index.js';
	import {
		CircleCheckBig,
		Clock,
		KeyRound,
		Plus,
		RefreshCw,
		Server,
		ShieldCheck,
		TagIcon,
		UserIcon,
		UserPlus,
		Wifi,
		WifiOff
	} from '@lucide/svelte';
	import { openGrant } from '#lib/components/access/grant.svelte.js';
	import ServerStatusCell from './ServerStatusCell.svelte';
	import { Debounced } from 'runed';

	const sheet = useSheet();
	const can = user.can();
	// Add server asks which way first, then opens the form for it.
	const add = useCreate();
	const manual = useCreate({ form: 'manual' });
	// An enroll token is a credential, so the form opens after a recent sign-in, like from the palette.
	const enroll = useCreate({ fresh: true, form: 'enroll' });
	let enrollTab = $state('new');
	const openEnroll = (tab: string) => {
		enrollTab = tab;
		enroll.open = true;
	};
	const tokens = token.list();
	// A server set up with nk sync that last synced before this refuses new certificates.
	const authority = ca.get();

	const statusOptions = [
		{ label: 'Waiting for approval', value: 'pending', icon: Clock, status: TargetStatus.PENDING },
		{ label: 'Online', value: 'online', icon: Wifi, status: TargetStatus.ONLINE },
		{ label: 'Offline', value: 'offline', icon: WifiOff, status: TargetStatus.OFFLINE },
		{ label: 'nk sync', value: 'manual', icon: RefreshCw, status: TargetStatus.MANUAL }
	];

	const debounced = new Debounced(() => page.url.searchParams.get('q') || undefined, 500);

	const pager = usePagination();
	const targets = target.list(
		() => ({
			...pager.args,
			query: debounced.current,
			tags: page.url.searchParams.get('tags')?.split(','),
			accounts: page.url.searchParams.get('accounts')?.split(','),
			status: statusOptions.find((o) => o.value === page.url.searchParams.get('status'))?.status
		}),
		undefined,
		true
	);

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

	const approveDaemons = daemon.approveMany();
	// The daemons of the picked servers that are not approved yet.
	const waiting = (picked: Target[]) =>
		picked.flatMap((t) =>
			t.daemon && t.daemon.status !== DaemonStatus.ACCEPTED ? [t.daemon.id] : []
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
		columnHelper.display({
			id: 'status',
			header: 'Status',
			cell: ({ row }) =>
				renderComponent(ServerStatusCell, {
					target: row.original,
					caRotatedAt: authority.data?.rotatedAt
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
						...(can.edit
							? [
									{
										label: 'Grant access',
										icon: UserPlus,
										onClick: () => openGrant({ servers: [row.original] })
									}
								]
							: []),
						{
							label: can.edit ? 'Manage access' : 'View access',
							icon: ShieldCheck,
							onClick: () => sheet.show(row.original.id, 'access')
						}
					],
					deleteConfig: can.edit
						? {
								itemName: row.original.name,
								description: deleteWarning(row.original),
								typeToConfirm: row.original.name,
								fresh: true,
								onDelete: () => deleteTarget.mutateAsync({ id: row.original.id })
							}
						: undefined
				});
			}
		})
	]);

	const bulkActions: BulkAction<Target>[] = [
		{
			label: 'Approve',
			icon: CircleCheckBig,
			variant: 'default',
			show: (selected) => waiting(selected).length > 0,
			confirm: (selected) => ({
				title: `Approve ${plural(waiting(selected).length, 'server')}?`,
				description: 'People can log in to them once approved.',
				destructive: false
			}),
			onClick: async (selected) => {
				await approveDaemons.mutateAsync(
					waiting(selected).map((id) => ({ id, status: DaemonStatus.ACCEPTED }))
				);
			}
		},
		{
			label: 'Grant access',
			icon: ShieldCheck,
			variant: 'default',
			onClick: (selected) => openGrant({ servers: selected })
		},
		bulkDelete<Target>({
			noun: 'server',
			name: (t) => t.name,
			typed: true,
			fresh: true,
			run: (selected) => deleteTargets.mutateAsync(selected.map(({ id }) => ({ id })))
		})
	];
</script>

<AddServerModal
	bind:open={add.open}
	canEnroll={can.admin}
	onDaemon={() => openEnroll('new')}
	onManual={() => (manual.open = true)}
/>
<CreateTargetModal bind:open={manual.open} />
<EnrollSheet bind:open={enroll.open} bind:tab={enrollTab} />
<TargetSheet />

<PageHeader
	title="Servers"
	description="Every server people log in to, through its daemon or set up with nk sync"
>
	{#if can.admin}
		<Button variant="outline" onclick={() => openEnroll('active')}>
			<KeyRound data-icon="inline-start" />
			Enrollment tokens
			{#if tokens.data?.tokens.length}
				<Badge variant="secondary" class="font-mono">{tokens.data.tokens.length}</Badge>
			{/if}
		</Button>
	{/if}
	{#if can.edit}
		<Button onclick={() => (add.open = true)}>
			<Plus data-icon="inline-start" />
			Add server
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
		title: 'No servers yet',
		description: 'Add one with its daemon, or set it up from your terminal with nk sync.',
		command: 'nk sync root@host'
	}}
>
	{#snippet toolbar(table)}
		<TableToolbar
			search
			searchResultCount={targets.data?.total}
			{table}
			filters={[
				{ title: 'Status', options: statusOptions, param: 'status', mode: 'single' },
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
