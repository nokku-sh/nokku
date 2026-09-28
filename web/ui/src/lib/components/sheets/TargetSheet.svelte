<script lang="ts">
	import { goto } from '$app/navigation';
	import { ca } from '$lib/api/certificates.svelte';
	import { daemon as daemonApi } from '$lib/api/daemons.svelte';
	import { target as targetApi } from '$lib/api/targets.svelte';
	import { grantsOf } from '$lib/components/access/subjects.svelte';
	import TargetAccess from '$lib/components/access/TargetAccess.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import * as InputGroup from '$lib/components/ui/input-group';
	import { TagsInput } from '$lib/components/ui/tags-input';
	import * as Select from '$lib/components/ui/select';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import Chip from '$lib/components/utils/Chip.svelte';
	import CopyText from '$lib/components/utils/CopyText.svelte';
	import { TargetSchema } from '$lib/gen/nokku/v1/target_pb';
	import { confirm, useAutoSave, useDraft, useSheet } from '$lib/hooks';
	import { timeAgo } from '$lib/time';
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
		ShieldCheck,
		SquareTerminal
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import DangerZone from './DangerZone.svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const query = targetApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(TargetSchema, () => query.data);
	const model = $derived(draft.current);

	const daemonQuery = daemonApi.get(() => entity?.daemonId);
	const linkedDaemon = $derived(daemonQuery.data?.daemon);
	const cas = ca.list();
	const tagFilters = targetApi.filters();

	const update = targetApi.update();
	const remove = targetApi.delete();
	const createSession = daemonApi.createSession();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	const isManual = $derived(!entity?.daemonId);
	const online = $derived(!!linkedDaemon?.online);
	const accounts = $derived(entity?.principals ?? []);
	const withAccess = $derived(new Set(accounts.flatMap((p) => grantsOf(p).map((g) => g.id))).size);
	const lastSynced = $derived(timeAgo(entity?.metadata?.['last_manual_sync']));
	const syncCommand = $derived(`nk sync ${model?.name ?? '<name>'}`);
	const systemInfo = $derived(
		Object.entries(entity?.metadata ?? {})
			.filter(([key]) => key !== 'last_manual_sync' && key !== 'tags')
			.map(([key, value]) => ({ label: key.replace(/[-_]/g, ' '), value, mono: true }))
	);

	const glance = $derived([
		{ label: 'Login accounts', value: accounts.length, tab: 'access' },
		{ label: 'With access', value: withAccess, tab: 'access' },
		{ label: 'Endpoints', value: model?.endpoints.length ?? 0 }
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

	async function openTerminal(username: string) {
		if (!entity?.daemonId) return;
		await createSession.mutateAsync({ daemonId: entity.daemonId, username });
		await goto('/sessions');
	}

	async function copySSH(username: string) {
		await navigator.clipboard.writeText(`ssh ${username}@${entity?.name}`);
		toast.success('SSH command copied', { description: 'Run nk login first on a new machine.' });
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

<EntitySheet
	open={sheet.open}
	onClose={() => sheet.close()}
	loading={!model}
	missing={query.isError}
	title={model?.name ?? ''}
	onRename={(name) => {
		if (!model) return;
		model.name = name;
		save();
	}}
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'access', label: 'Access', icon: ShieldCheck, count: accounts.length }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	saveState={autoSave.saveState}
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
				<span class="relative flex size-2">
					{#if online}
						<span class="absolute inline-flex size-full animate-ping rounded-full bg-success/60"
						></span>
					{/if}
					<span
						class={[
							'relative size-2 rounded-full',
							online ? 'bg-success' : 'bg-muted-foreground/40'
						]}
					></span>
				</span>
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

	{#snippet actions()}
		{#if accounts.length}
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
								disabled={!online || createSession.isPending}
								onclick={() => openTerminal(account.username)}
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
							<DropdownMenu.Item onclick={() => copySSH(account.username)}>
								<Copy />
								<span class="truncate font-mono">ssh {account.username}@{entity?.name}</span>
							</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Group>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		{/if}
		<Button variant="outline" size="sm" onclick={() => (sheet.tab = 'access')}>
			<ShieldCheck data-icon="inline-start" />
			Manage access
		</Button>
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<div class="grid grid-cols-3 gap-2 pb-5">
				{#each glance as stat (stat.label)}
					<button
						type="button"
						disabled={!stat.tab}
						onclick={() => stat.tab && (sheet.tab = stat.tab)}
						class="flex flex-col items-start rounded-lg border bg-card px-3 py-2 text-left transition-colors enabled:hover:bg-muted/50"
					>
						<span class="text-xl font-semibold tabular-nums">{stat.value}</span>
						<span class="text-xs text-muted-foreground">{stat.label}</span>
					</button>
				{/each}
			</div>

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
								onRemove={() => removeEndpoint(endpoint)}
							/>
						{/each}
					</div>
				{/if}
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
							<InputGroup.Button
								type="submit"
								variant="secondary"
								size="xs"
								disabled={!newEndpoint.trim()}
							>
								<Plus data-icon="inline-start" />
								Add
							</InputGroup.Button>
						</InputGroup.Addon>
					</InputGroup.Root>
				</form>
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
							oninput={save}
						/>
					</Field.Field>
					<div class="grid gap-4 sm:grid-cols-2">
						<Field.Field>
							<Field.Label for="target-ca">Certificate authority</Field.Label>
							<Select.Root
								type="single"
								value={model.caId}
								onValueChange={(v) => {
									model.caId = v;
									save();
								}}
							>
								<Select.Trigger id="target-ca" class="w-full">
									{cas.data?.find((c) => c.id === model.caId)?.name ?? 'Default CA'}
								</Select.Trigger>
								<Select.Content>
									<Select.Group>
										{#each cas.data ?? [] as c (c.id)}
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

			{#if isManual}
				<Section
					title="Manual sync"
					icon={RefreshCw}
					description={lastSynced ? `Last synced ${lastSynced}.` : 'Not synced yet.'}
				>
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
		</Tabs.Content>

		<Tabs.Content value="access">
			<TargetAccess targetId={entity.id} manual={isManual} />
		</Tabs.Content>
	{/if}
</EntitySheet>
