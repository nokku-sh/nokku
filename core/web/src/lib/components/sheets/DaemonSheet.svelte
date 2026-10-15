<script lang="ts">
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import { create } from '@bufbuild/protobuf';
	import { daemon as daemonApi } from '#lib/api/daemons.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import Monogram from '#lib/components/blocks/Monogram.svelte';
	import {
		DaemonConfigSchema,
		DaemonSchema,
		DaemonStatus,
		type DaemonConfig
	} from '#lib/gen/nokku/v1/daemon_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import { Ban, Clock, Cpu, Info, Server, Settings2, ShieldCheck } from '@lucide/svelte';
	import DangerZone from './DangerZone.svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';
	import Chip from '#lib/components/blocks/Chip.svelte';

	const sheet = useSheet();
	const can = user.can();
	const query = daemonApi.get(() => sheet.id);
	const entity = $derived(query.data?.daemon);
	const draft = useDraft(DaemonSchema, () => query.data?.daemon);
	const cfg = $derived(draft.current?.config);

	const targets = targetApi.list(() => ({ daemonId: sheet.id || undefined, limit: 40 }));
	const update = daemonApi.update();
	const remove = daemonApi.delete();

	// Only an accepted daemon connects. Every other state gets the approve card.
	const accepted = $derived(entity?.status === DaemonStatus.ACCEPTED);
	const pending = $derived(entity?.status === DaemonStatus.PENDING);

	const autoSave = useAutoSave(() =>
		update.mutateAsync({ id: sheet.id, config: create(DaemonConfigSchema, cfg ?? {}) })
	);

	type Rule = keyof Omit<DaemonConfig, '$typeName' | '$unknown'>;

	function applyRule(key: Rule, value: boolean) {
		const d = draft.current;
		if (!d) return;
		d.config = { ...(d.config ?? create(DaemonConfigSchema)), [key]: value };
		autoSave.save();
	}

	// Recording is a privacy change for everyone who logs in there, so it asks first.
	function setRule(key: Rule, value: boolean) {
		if (key !== 'recordSessions' || !value) return applyRule(key, value);
		void confirm({
			title: `Record sessions on ${entity?.name ?? 'this daemon'}?`,
			description:
				'Every new SSH session it serves is recorded and kept encrypted for playback. Let the people who log in there know.',
			confirmText: 'Start recording',
			destructive: false,
			onConfirm: () => applyRule(key, value)
		});
	}

	const policy: { key: Rule; title: string; description: string }[] = [
		{
			key: 'recordSessions',
			title: 'Record sessions',
			description: 'Keep an encrypted recording of every SSH session for playback.'
		},
		{
			key: 'allowForwarding',
			title: 'Port forwarding',
			description: 'Allow -L, -D and -R port forwards.'
		},
		{
			key: 'allowAgentForwarding',
			title: 'Agent forwarding',
			description: "Let sessions use the client's ssh-agent."
		},
		{
			key: 'gatewayPorts',
			title: 'Public remote forwards',
			description: 'Let -R forwards listen on addresses other than localhost.'
		}
	];

	async function approve() {
		await update.mutateAsync({ id: sheet.id, status: DaemonStatus.ACCEPTED });
	}

	function askDelete(reject = false) {
		if (!entity) return;
		void confirm({
			title: reject ? `Reject ${entity.name}?` : `Delete ${entity.name}?`,
			description: reject
				? 'The daemon is removed and has to enroll again.'
				: 'Targets behind this daemon become unreachable until another daemon serves them.',
			confirmText: reject ? 'Reject' : 'Delete',
			typeToConfirm: reject ? undefined : entity.name,
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
	loading={!entity}
	missing={query.isError}
	title={entity?.name ?? ''}
	saveState={accepted ? autoSave.saveState : undefined}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.edit}
	detail={entity?.metadata?.hostname}
	detailMono
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	onRetry={autoSave.retry}
	meta={{
		id: entity?.id,
		createdAt: entity?.createdAt,
		updatedAt: entity?.updatedAt,
		extra: [{ label: 'Last seen', value: formatTs(entity?.lastSeenAt, 'relative') }]
	}}
>
	{#snippet media()}
		<Monogram name={entity?.name ?? ''} class="size-10 text-sm" />
	{/snippet}

	{#snippet subtitle()}
		<span class="flex items-center gap-1.5">
			<!-- The same word and tone as the Online column in the table. -->
			<StatusDot tone={entity?.online ? 'success' : 'warning'} live={entity?.online} />
			{#if entity?.online}
				Online
			{:else}
				Offline, {entity?.lastSeenAt
					? `last seen ${formatTs(entity.lastSeenAt, 'relative')}`
					: 'never connected'}
			{/if}
		</span>
		{#if pending}
			<Badge variant="warning">Waiting for approval</Badge>
		{:else if entity && !accepted}
			<Badge variant="destructive">
				{entity.status === DaemonStatus.REJECTED ? 'Rejected' : 'Not accepted'}
			</Badge>
		{/if}
	{/snippet}

	{#if entity && draft.current}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			{#if !accepted}
				<div class="pb-5">
					<Alert.Root variant={pending ? 'warning' : 'destructive'}>
						{#if pending}<Clock />{:else}<Ban />{/if}
						<Alert.Title>
							{pending ? 'This daemon wants to join' : 'This daemon is not accepted'}
						</Alert.Title>
						<Alert.Description>
							{#if !can.edit}
								It cannot connect or serve targets until an editor approves it.
							{:else if pending}
								Check that you expect this host before you approve it. It can serve targets once
								approved.
							{:else}
								It cannot connect or serve targets until you approve it.
							{/if}
						</Alert.Description>
						{#if can.edit}
							<div class="col-start-2 mt-2 flex gap-2">
								<Button size="sm" onclick={approve} disabled={update.isPending}>Approve</Button>
								<Button size="sm" variant="destructive" onclick={() => askDelete(pending)}>
									{pending ? 'Reject' : 'Delete'}
								</Button>
							</div>
						{/if}
					</Alert.Root>
				</div>
			{/if}

			{#if Object.keys(entity.metadata ?? {}).length}
				<Section title="Host" icon={Cpu}>
					<DetailList
						items={Object.entries(entity.metadata).map(([key, value]) => ({
							label: key.replace(/[-_]/g, ' '),
							value,
							mono: true,
							copy: key === 'host'
						}))}
					/>
				</Section>
			{:else}
				<Section title="Host" icon={Cpu}>
					<Empty.Root class="border border-dashed p-6">
						<Empty.Header>
							<Empty.Media variant="icon"><Cpu /></Empty.Media>
							<Empty.Description>Host details show up once the daemon connects.</Empty.Description>
						</Empty.Header>
					</Empty.Root>
				</Section>
			{/if}

			{#if accepted}
				<Section title="Targets" icon={Server} count={targets.data?.total}>
					{#if targets.data?.targets.length}
						<div class="flex flex-wrap gap-1.5">
							{#each targets.data.targets as t (t.id)}
								<Chip
									label={t.name}
									href={`/infrastructure/targets?id=${t.id}`}
									title={t.description}
								>
									{#snippet leading()}
										<Server class="ml-2 size-3 text-muted-foreground" />
									{/snippet}
								</Chip>
							{/each}
							{#if targets.data.total > targets.data.targets.length}
								<Chip label={`+${targets.data.total - targets.data.targets.length} more`} muted />
							{/if}
						</div>
					{:else if !targets.isLoading}
						<Empty.Root class="border border-dashed p-6">
							<Empty.Header>
								<Empty.Media variant="icon"><Server /></Empty.Media>
								<Empty.Description>No targets behind this daemon yet.</Empty.Description>
							</Empty.Header>
						</Empty.Root>
					{/if}
				</Section>
			{/if}
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			{#if accepted}
				<Section
					title="Session policy"
					icon={ShieldCheck}
					description="Pushed to the daemon on its next sync. Running sessions keep their current rules."
				>
					<Item.Group class="divide-y rounded-lg border">
						{#each policy as rule (rule.key)}
							<Item.Root size="sm" class="rounded-none">
								<Item.Content>
									<Item.Title>
										<label for={`policy-${rule.key}`}>{rule.title}</label>
									</Item.Title>
									<Item.Description>{rule.description}</Item.Description>
								</Item.Content>
								<Item.Actions>
									<Switch
										id={`policy-${rule.key}`}
										bind:checked={() => cfg?.[rule.key] ?? false, (v) => setRule(rule.key, v)}
										disabled={!can.edit}
									/>
								</Item.Actions>
							</Item.Root>
						{/each}
					</Item.Group>
				</Section>
			{/if}

			{#if can.edit}
				<DangerZone
					actions={[
						{
							title: 'Delete daemon',
							description: 'Its targets stay, but nobody reaches them through this daemon anymore.',
							label: 'Delete',
							onClick: () => askDelete()
						}
					]}
				/>
			{/if}
		</Tabs.Content>
	{/if}
</EntitySheet>
