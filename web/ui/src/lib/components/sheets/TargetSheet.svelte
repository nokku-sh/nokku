<script lang="ts">
	import { ca } from '#lib/api/certificates.svelte.js';
	import { useConnect } from '#lib/api/connect.svelte.js';
	import { daemon as daemonApi } from '#lib/api/daemons.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { grantsOf } from '#lib/components/access/subjects.svelte.js';
	import TargetAccess from '#lib/components/access/TargetAccess.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { TargetSchema } from '#lib/gen/nokku/v1/target_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import { timestampDate, timestampFromDate } from '@bufbuild/protobuf/wkt';
	import {
		ChevronDown,
		Copy,
		Cpu,
		FileText,
		Globe,
		Info,
		Plus,
		RefreshCw,
		Server,
		Settings2,
		ShieldCheck,
		SquareTerminal
	} from '@lucide/svelte';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import DangerZone from './DangerZone.svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const can = user.can();
	const query = targetApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(TargetSchema, () => query.data);
	const model = $derived(draft.current);

	const daemonQuery = daemonApi.get(() => entity?.daemonId);
	const linkedDaemon = $derived(daemonQuery.data?.daemon);
	const cas = ca.list();
	const caList = $derived(cas.data ?? []);
	const tagFilters = targetApi.filters();

	const update = targetApi.update();
	const remove = targetApi.delete();
	const connect = useConnect();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	const isManual = $derived(!entity?.daemonId);
	const online = $derived(!!linkedDaemon?.online);
	const accounts = $derived(entity?.accounts ?? []);
	const withAccess = $derived(new Set(accounts.flatMap((p) => grantsOf(p).map((g) => g.id))).size);
	const lastSyncAt = $derived.by(() => {
		const at = new Date(entity?.metadata?.['last_manual_sync'] ?? '');
		return Number.isNaN(at.getTime()) ? undefined : at;
	});
	const lastSynced = $derived(
		lastSyncAt ? formatTs(timestampFromDate(lastSyncAt), 'relative-short') : ''
	);
	// The server only learns a new CA key from nk sync.
	const caRotated = $derived.by(() => {
		const rotatedAt = (caList.find((c) => c.id === entity?.caId) ?? caList.find((c) => c.isDefault))
			?.notBefore;
		return !!lastSyncAt && !!rotatedAt && timestampDate(rotatedAt) > lastSyncAt;
	});
	const syncCommand = $derived(`nk sync ${model?.name ?? '<name>'}`);
	const systemInfo = $derived(
		Object.entries(entity?.metadata ?? {})
			.filter(([key]) => key !== 'last_manual_sync' && key !== 'tags')
			.map(([key, value]) => ({ label: key.replace(/[-_]/g, ' '), value, mono: true }))
	);

	const glance = $derived([
		{ label: 'Login accounts', value: accounts.length, tab: 'access' },
		{ label: 'With access', value: withAccess, tab: 'access' },
		{ label: 'Endpoints', value: model?.endpoints.length ?? 0, tab: 'settings' }
	]);

	let newEndpoint = $state('');

	function addEndpoint() {
		const value = newEndpoint.trim();
		if (!model || !value || model.endpoints.includes(value)) return;
		model.endpoints = [...model.endpoints, value];
		newEndpoint = '';
		save();
	}

	function removeEndpoint(endpoint: string) {
		if (!model) return;
		model.endpoints = model.endpoints.filter((e) => e !== endpoint);
		save();
	}

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description:
				'Everyone loses access to this target. Its login accounts and grants are removed.',
			typeToConfirm: entity.name,
			onConfirm: async () => {
				await remove.mutateAsync({ id: entity.id });
				sheet.close();
			}
		});
	}
</script>

{#snippet connectMenu()}
	<DropdownMenu.Root>
		<DropdownMenu.Trigger>
			{#snippet child({ props })}
				<Button {...props} size="sm">
					<SquareTerminal data-icon="inline-start" />
					Connect
					<ChevronDown data-icon="inline-end" />
				</Button>
			{/snippet}
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align="start" class="w-60">
			<DropdownMenu.Group>
				<DropdownMenu.Label>
					{online ? 'Open a web terminal as' : 'Web terminal needs an online daemon'}
				</DropdownMenu.Label>
				{#each accounts as account (account.id)}
					<DropdownMenu.Item
						disabled={!online || connect.pending}
						onclick={() => entity && connect.shell(entity, account.username)}
					>
						<SquareTerminal />
						<span class="font-mono">{account.username}</span>
					</DropdownMenu.Item>
				{/each}
			</DropdownMenu.Group>
			<DropdownMenu.Separator />
			<DropdownMenu.Group>
				<DropdownMenu.Label>Copy SSH command</DropdownMenu.Label>
				{#each accounts as account (account.id)}
					<DropdownMenu.Item onclick={() => entity && connect.copy(entity, account.username)}>
						<Copy />
						<span class="truncate font-mono">ssh {account.username}@{entity?.name}</span>
					</DropdownMenu.Item>
				{/each}
			</DropdownMenu.Group>
		</DropdownMenu.Content>
	</DropdownMenu.Root>
{/snippet}

<EntitySheet
	open={sheet.open}
	onClose={() => sheet.close()}
	loading={!model}
	missing={query.isError}
	title={model?.name ?? ''}
	onRename={can.edit
		? (name) => {
				if (!model) return;
				model.name = name;
				save();
			}
		: undefined}
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'access', label: 'Access', icon: ShieldCheck, count: accounts.length },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	saveState={autoSave.saveState}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.edit}
	actions={accounts.length ? connectMenu : undefined}
	meta={{
		id: entity?.id,
		createdAt: entity?.createdAt,
		updatedAt: entity?.updatedAt,
		extra: [{ label: 'Daemon', value: entity?.daemonId, copy: true }]
	}}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<Server class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		{#if isManual}
			<Badge variant="outline"><RefreshCw data-icon="inline-start" />Manual sync</Badge>
		{:else}
			<span class="flex items-center gap-1.5">
				<StatusDot tone={online ? 'success' : 'muted'} live={online} />
				{online ? 'Online' : 'Offline'} via
				<a href={`/infrastructure/daemons?id=${entity?.daemonId}`} class="hover:underline">
					{linkedDaemon?.name ?? 'daemon'}
				</a>
			</span>
		{/if}
		{#each model?.tags ?? [] as tag (tag)}
			<Badge variant="secondary">{tag}</Badge>
		{/each}
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<div class="grid grid-cols-3 gap-2 pb-5">
				{#each glance as stat (stat.label)}
					<button
						type="button"
						onclick={() => (sheet.tab = stat.tab)}
						class="flex flex-col items-start rounded-lg border bg-card px-3 py-2 text-left transition-colors hover:bg-muted/50"
					>
						<span class="text-xl font-semibold tabular-nums">{stat.value}</span>
						<span class="text-xs text-muted-foreground">{stat.label}</span>
					</button>
				{/each}
			</div>

			{#if isManual}
				<Section
					title="Manual sync"
					icon={RefreshCw}
					description={lastSynced ? `Last synced ${lastSynced}.` : 'Not synced yet.'}
				>
					{#if caRotated}
						<p class="text-sm text-warning">
							The certificate authority was rotated after the last sync. Sync again, or this server
							rejects new certificates.
						</p>
					{/if}
					<div class="flex items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2">
						<SquareTerminal class="size-4 shrink-0 text-muted-foreground" />
						<CopyText value={syncCommand} mono class="text-sm" />
					</div>
					<p class="text-xs text-muted-foreground">
						Run it on the host. It installs the CA key and the principal files under
						/etc/ssh/nokku_principals, checks sshd and reloads it.
					</p>
				</Section>
			{/if}

			<Section title="System" icon={Cpu}>
				{#if systemInfo.length || entity.hostPublicKey}
					<DetailList
						items={[
							...systemInfo,
							{
								label: 'Host key',
								value: entity.hostPublicKey,
								mono: true,
								copy: true,
								wide: true
							}
						]}
					/>
				{:else}
					<Empty.Root class="border border-dashed p-6">
						<Empty.Header>
							<Empty.Media variant="icon"><Cpu /></Empty.Media>
							<Empty.Description>
								Host details show up once {isManual ? 'nk sync runs' : 'the daemon connects'}.
							</Empty.Description>
						</Empty.Header>
					</Empty.Root>
				{/if}
			</Section>
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section
				title="Endpoints"
				icon={Globe}
				count={model.endpoints.length}
				description="Tried in parallel with the relay. Leave empty to always use the relay."
			>
				{#if model.endpoints.length}
					<div class="flex flex-wrap gap-1.5">
						{#each model.endpoints as endpoint (endpoint)}
							<Chip
								label={endpoint}
								copy={endpoint}
								mono
								onRemove={can.edit ? () => removeEndpoint(endpoint) : undefined}
							/>
						{/each}
					</div>
				{/if}
				{#if can.edit}
					<form
						onsubmit={(e) => {
							e.preventDefault();
							addEndpoint();
						}}
					>
						<InputGroup.Root class="h-8">
							<InputGroup.Addon><Globe /></InputGroup.Addon>
							<InputGroup.Input
								bind:value={newEndpoint}
								placeholder="10.0.4.12 or web-1.internal:2222"
								aria-label="New endpoint"
								class="font-mono text-xs"
							/>
							<InputGroup.Addon align="inline-end">
								<!-- Never disabled, InputGroup greys out the whole field for a disabled child. -->
								<InputGroup.Button type="submit" variant="secondary" size="xs">
									<Plus data-icon="inline-start" />
									Add
								</InputGroup.Button>
							</InputGroup.Addon>
						</InputGroup.Root>
					</form>
				{/if}
			</Section>

			<Section title="Details" icon={FileText}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="target-description">Description</Field.Label>
						<Textarea
							id="target-description"
							bind:value={model.description}
							placeholder="Production web server, Frankfurt"
							rows={2}
							disabled={!can.edit}
							oninput={save}
						/>
					</Field.Field>
					<div class="grid gap-4 sm:grid-cols-2">
						<Field.Field>
							<Field.Label for="target-ca">Certificate authority</Field.Label>
							<Select.Root
								type="single"
								value={model.caId}
								disabled={!can.edit}
								onValueChange={(v) => {
									model.caId = v;
									save();
								}}
							>
								<Select.Trigger id="target-ca" class="w-full">
									{caList.find((c) => c.id === model.caId)?.name ?? 'Default CA'}
								</Select.Trigger>
								<Select.Content>
									<Select.Group>
										{#each caList as c (c.id)}
											<Select.Item value={c.id}>{c.name}</Select.Item>
										{/each}
									</Select.Group>
								</Select.Content>
							</Select.Root>
						</Field.Field>
						<Field.Field>
							<Field.Label for="target-tags">Tags</Field.Label>
							<TagsInput
								id="target-tags"
								value={model.tags}
								suggestions={tagFilters.data?.tags}
								disabled={!can.edit}
								onValueChange={(tags) => {
									model.tags = tags;
									save();
								}}
								placeholder="linux, prod"
							/>
						</Field.Field>
					</div>
				</Field.Group>
			</Section>

			{#if can.edit}
				<DangerZone
					actions={[
						{
							title: 'Delete target',
							description: 'Removes the target, its login accounts and every grant.',
							label: 'Delete',
							onClick: askDelete
						}
					]}
				/>
			{/if}
		</Tabs.Content>

		<Tabs.Content value="access">
			<TargetAccess targetId={entity.id} manual={isManual} />
		</Tabs.Content>
	{/if}
</EntitySheet>
