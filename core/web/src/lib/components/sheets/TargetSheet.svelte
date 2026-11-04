<script lang="ts">
	import { ca, manualKeyState } from '#lib/api/certificates.svelte.js';
	import { daemon as daemonApi, useDaemonReview } from '#lib/api/daemons.svelte.js';
	import { useConnect } from '#lib/api/connect.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { grantsOf } from '#lib/components/access/subjects.svelte.js';
	import TargetAccess from '#lib/components/access/TargetAccess.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import Monogram from '#lib/components/blocks/Monogram.svelte';
	import { daemonRules, type DaemonRule } from '#lib/daemon-rules.js';
	import { DaemonStatus } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { TargetSchema } from '#lib/gen/nokku/v1/target_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import {
		Ban,
		Bot,
		ChevronDown,
		Clock,
		Copy,
		Cpu,
		FileText,
		Globe,
		Info,
		Plus,
		RefreshCw,
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

	const linkedDaemon = $derived(entity?.daemon);
	const authority = ca.get();
	const tagFilters = targetApi.filters();

	const update = targetApi.update();
	const remove = targetApi.delete();
	const connect = useConnect();

	const autoSave = useAutoSave(() =>
		draft.save((changes) => update.mutateAsync({ ...changes, id: model?.id }))
	);
	const save = () => autoSave.save();

	const isManual = $derived(!entity?.daemonId);
	const online = $derived(!!linkedDaemon?.online);
	// Only an accepted daemon connects. Every other state gets the approve card.
	const accepted = $derived(linkedDaemon?.status === DaemonStatus.ACCEPTED);
	const pending = $derived(linkedDaemon?.status === DaemonStatus.PENDING);
	const accounts = $derived(entity?.accounts ?? []);
	const withAccess = $derived(new Set(accounts.flatMap((p) => grantsOf(p).map((g) => g.id))).size);
	const lastSynced = $derived(formatTs(entity?.lastSyncAt, 'relative-short'));
	const keyState = $derived(manualKeyState(authority.data, entity?.lastSyncAt));
	const syncCommand = $derived(`nk sync ${model?.name ?? '<name>'}`);
	const systemInfo = $derived(
		Object.entries(entity?.metadata ?? {})
			.filter(([key]) => key !== 'tags')
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

	const updateDaemon = daemonApi.update();
	const review = useDaemonReview();
	// A switch shows what was flipped until the server's copy catches up.
	let flipped = $state<Partial<Record<DaemonRule, boolean>>>({});
	const ruleOn = (key: DaemonRule) => flipped[key] ?? linkedDaemon?.config?.[key] ?? false;

	async function applyRule(key: DaemonRule, value: boolean) {
		const d = linkedDaemon;
		if (!d) return;
		flipped[key] = value;
		try {
			const config: Partial<Record<DaemonRule, boolean>> = { [key]: value };
			// Resolves after the refetch every change runs, so the switch never jumps back.
			await updateDaemon.mutateAsync({ id: d.id, config });
		} finally {
			delete flipped[key];
		}
	}

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description: entity.daemonId
				? 'Everyone loses access to this server. Its login accounts, grants and daemon are removed.'
				: 'Everyone loses access to this server. Its login accounts and grants are removed.',
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
		{ value: 'access', label: 'Access', icon: ShieldCheck },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	detail={entity?.metadata?.hostname || entity?.endpoints[0] || entity?.description}
	detailMono={!!(entity?.metadata?.hostname || entity?.endpoints[0])}
	saveState={autoSave.saveState}
	saveHint={sheet.tab === 'settings'}
	onRetry={autoSave.retry}
	readonly={!can.edit}
	actions={accounts.length ? connectMenu : undefined}
	meta={{
		id: entity?.id,
		createdAt: entity?.createdAt,
		updatedAt: entity?.updatedAt
	}}
>
	{#snippet media()}
		<Monogram name={entity?.name ?? ''} class="size-10 text-sm" />
	{/snippet}

	{#snippet subtitle()}
		{#if isManual}
			<Badge variant="outline"><RefreshCw data-icon="inline-start" />Manual sync</Badge>
		{:else if linkedDaemon}
			<span class="flex items-center gap-1.5">
				<StatusDot tone={online ? 'success' : 'warning'} live={online} />
				{#if linkedDaemon.behindSince}
					Behind since {formatTs(linkedDaemon.behindSince, 'relative')}, it may still let in access
					you revoked
				{:else if online}
					Online
				{:else}
					Offline, {linkedDaemon.lastSeenAt
						? `last seen ${formatTs(linkedDaemon.lastSeenAt, 'relative')}`
						: 'never connected'}
				{/if}
			</span>
			{#if pending}
				<Badge variant="warning">Waiting for approval</Badge>
			{:else if !accepted}
				<Badge variant="destructive">Rejected</Badge>
			{/if}
		{/if}
		{#each model?.tags ?? [] as tag (tag)}
			<Badge variant="outline" class="h-5 rounded-full px-2 font-normal">{tag}</Badge>
		{/each}
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			{#if linkedDaemon && !accepted}
				<div class="pb-5">
					<Alert.Root variant={pending ? 'warning' : 'destructive'}>
						{#if pending}<Clock />{:else}<Ban />{/if}
						<Alert.Title>
							{pending ? 'This server wants to join' : 'This server was rejected'}
						</Alert.Title>
						<Alert.Description>
							{#if !can.edit}
								Nobody can log in to it until an editor approves it.
							{:else if pending}
								Its daemon enrolled. Check that you expect this host before you approve it, people
								can log in once you do.
							{:else}
								Nobody can log in to it until you approve it.
							{/if}
						</Alert.Description>
						{#if can.edit}
							<div class="col-start-2 mt-2 flex gap-2">
								<Button
									size="sm"
									onclick={() => review.approve(linkedDaemon)}
									disabled={review.pending}>Approve</Button
								>
								<Button
									size="sm"
									variant="destructive"
									onclick={() => review.reject(linkedDaemon, () => sheet.close())}>Reject</Button
								>
							</div>
						{/if}
					</Alert.Root>
				</div>
			{/if}

			<div class="grid grid-cols-3 gap-2 py-5 first:pt-0">
				{#each glance as stat (stat.label)}
					<button
						type="button"
						onclick={() => (sheet.tab = stat.tab)}
						class="flex flex-col items-start rounded-lg border bg-card px-3 py-2 text-left transition-colors hover:bg-muted/50"
					>
						<span class="spec-label">{stat.label}</span>
						<span class="text-xl font-semibold tabular-nums">{stat.value}</span>
					</button>
				{/each}
			</div>

			{#if isManual}
				<Section
					title="Manual sync"
					icon={RefreshCw}
					description={lastSynced ? `Last synced ${lastSynced}.` : 'Not synced yet.'}
				>
					{#if keyState.rotated}
						<p class="text-sm text-warning">
							The certificate authority was rotated after the last sync. Sync again, or this server
							rejects new certificates.
						</p>
					{:else if keyState.oldKeyUntil}
						<p class="text-sm text-warning">
							This server still trusts the previous key of the certificate authority. Sync again
							after
							{formatTs(keyState.oldKeyUntil)}, it can't drop that key on its own.
						</p>
					{/if}
					<div class="flex items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2">
						<SquareTerminal class="size-4 shrink-0 text-muted-foreground" />
						<CopyText value={syncCommand} mono class="text-sm" />
					</div>
					<p class="text-xs text-muted-foreground">
						Run it on your own machine. It connects to the host as root, installs the CA key and an
						sshd rule for this server, checks sshd and reloads it. Access changes need no new sync.
					</p>
				</Section>
			{/if}

			{#if linkedDaemon}
				<Section title="Daemon" icon={Bot}>
					<DetailList
						items={[
							{ label: 'Version', value: linkedDaemon.version || 'unknown', mono: true },
							{
								label: 'Last seen',
								value: linkedDaemon.lastSeenAt
									? formatTs(linkedDaemon.lastSeenAt, 'relative')
									: 'Never'
							},
							{ label: 'Enrolled', value: formatTs(linkedDaemon.createdAt) },
							...(linkedDaemon.config?.ephemeral
								? [{ label: 'Ephemeral', value: 'Removed once its host is gone' }]
								: [])
						]}
					/>
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
			{#if linkedDaemon && accepted}
				<Section
					title="Session rules"
					icon={ShieldCheck}
					description="Its daemon takes them at its next sync. Running sessions keep the rules they started with."
				>
					<Item.Group class="divide-y rounded-lg border">
						{#each daemonRules as rule (rule.key)}
							<Item.Root size="sm" class="rounded-none">
								<Item.Content>
									<Item.Title>
										<label for={`rule-${rule.key}`}>{rule.title}</label>
									</Item.Title>
									<Item.Description>{rule.description}</Item.Description>
								</Item.Content>
								<Item.Actions>
									<Switch
										id={`rule-${rule.key}`}
										checked={ruleOn(rule.key)}
										onCheckedChange={(v) => void applyRule(rule.key, v)}
										disabled={!can.edit || rule.key in flipped}
									/>
								</Item.Actions>
							</Item.Root>
						{/each}
					</Item.Group>
				</Section>
			{/if}

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
				</Field.Group>
			</Section>

			{#if can.edit}
				<DangerZone
					actions={[
						{
							title: 'Delete server',
							description: linkedDaemon
								? 'Removes the server, its daemon, its login accounts and every grant.'
								: 'Removes the server, its login accounts and every grant.',
							label: 'Delete',
							onClick: askDelete
						}
					]}
				/>
			{/if}
		</Tabs.Content>

		<Tabs.Content value="access">
			<TargetAccess targetId={entity.id} name={entity.name} manual={isManual} />
		</Tabs.Content>
	{/if}
</EntitySheet>
