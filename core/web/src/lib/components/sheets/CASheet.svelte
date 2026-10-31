<script lang="ts">
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import Monogram from '#lib/components/blocks/Monogram.svelte';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import { CertificateAuthoritySchema } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import type { Duration } from '@bufbuild/protobuf/wkt';
	import {
		Ban,
		Clock,
		FileText,
		Fingerprint,
		History,
		Info,
		KeyRound,
		Server,
		Settings2
	} from '@lucide/svelte';
	import DangerZone from './DangerZone.svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const can = user.can();
	const query = caApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(CertificateAuthoritySchema, () => query.data);
	const model = $derived(draft.current);

	const update = caApi.update();
	const remove = caApi.delete();
	const rollover = caApi.rollover();

	const autoSave = useAutoSave(() =>
		draft.save((changes) => update.mutateAsync({ ...changes, id: model?.id }))
	);
	const save = () => autoSave.save();

	const lifetimes: {
		key: 'userDefaultTtl' | 'userMaxTtl' | 'hostTtl';
		label: string;
	}[] = [
		{ key: 'userDefaultTtl', label: 'Default' },
		{ key: 'userMaxTtl', label: 'Longest allowed' },
		{ key: 'hostTtl', label: 'Valid for' }
	];

	function setLifetime(key: (typeof lifetimes)[number]['key'], value: Duration) {
		if (!model) return;
		model[key] = value;
		save();
	}

	// A planned rotation keeps the old keys trusted for as long as a user certificate can live. Only daemons learn the
	// new keys on their own.
	function askRotate() {
		if (!entity) return;
		void confirm({
			title: `Rotate the keys of ${entity.name}?`,
			description:
				'New keys replace both. Servers with the daemon take them at once, and certificates already signed keep working until they run out. A server set up with nk sync refuses new certificates until you run nk sync on it again.',
			confirmText: 'Rotate',
			onConfirm: () => rollover.mutateAsync({ id: entity.id, revokePrevious: false })
		});
	}

	function askRollover() {
		if (!entity) return;
		void confirm({
			title: `Emergency rollover of ${entity.name}?`,
			description:
				'The current keys stop being trusted at once and new ones replace them. People get a new certificate at their next connection. Servers without the daemon trust the old key until the next nk sync.',
			confirmText: 'Roll over',
			typeToConfirm: entity.name,
			onConfirm: () => rollover.mutateAsync({ id: entity.id, revokePrevious: true })
		});
	}

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description: 'Every certificate it signed stops being trusted. This cannot be undone.',
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
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	detail={entity?.description}
	saveState={autoSave.saveState}
	onRetry={autoSave.retry}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.edit}
	missing={query.isError}
	meta={{ id: entity?.id, createdAt: entity?.createdAt, updatedAt: entity?.updatedAt }}
>
	{#snippet media()}
		<Monogram name={entity?.name ?? ''} class="size-10 text-sm" />
	{/snippet}

	{#snippet subtitle()}
		{#if model?.isDefault}
			<Badge variant="muted">Default</Badge>
		{/if}
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<Section
				title="User key"
				icon={KeyRound}
				description="Servers let in logins whose certificate this key signed. It is what sshd's TrustedUserCAKeys holds."
			>
				<CodeSnippet code={entity.publicKey} language="openssh" wrap />
			</Section>

			<Section
				title="Host key"
				icon={Server}
				description="People trust a daemon whose host certificate this key signed. It never signs a login."
			>
				<CodeSnippet code={entity.hostPublicKey} language="openssh" wrap />
			</Section>

			{#if entity.previousPublicKey}
				<Section
					title="Previous keys"
					icon={History}
					description={entity.previousTrustedUntil
						? `Replaced by a rollover. Still trusted until ${formatTs(entity.previousTrustedUntil)}.`
						: 'Replaced by a rollover.'}
				>
					<CodeSnippet code={entity.previousPublicKey} language="openssh" wrap />
					{#if entity.previousHostPublicKey}
						<CodeSnippet code={entity.previousHostPublicKey} language="openssh" wrap />
					{/if}
				</Section>
			{/if}

			<Section title="Identity" icon={Fingerprint}>
				<DetailList
					items={[
						{ label: 'Algorithm', value: 'Ed25519' },
						{ label: 'Keys made', value: formatTs(entity.rotatedAt) }
					]}
				/>
			</Section>
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section title="Details" icon={FileText}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="ca-description">Description</Field.Label>
						<Textarea
							id="ca-description"
							bind:value={model.description}
							placeholder="Signs production SSH certificates"
							disabled={!can.edit}
							oninput={save}
						/>
					</Field.Field>
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="ca-default">Default for new targets</Field.Label>
							<Field.Description
								>Picked automatically when a target doesn't name a CA.</Field.Description
							>
						</Field.Content>
						<Switch
							id="ca-default"
							checked={model.isDefault}
							disabled={!can.edit}
							onCheckedChange={(v) => {
								model.isDefault = v;
								save();
							}}
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<Section title="Certificate lifetime" icon={Clock}>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>User certificates</Field.Label>
						<div class="grid grid-cols-2 gap-2">
							{#each lifetimes.slice(0, 2) as l (l.key)}
								<div class="flex flex-col gap-1">
									<span class="text-xs text-muted-foreground">{l.label}</span>
									<DurationInput
										value={model[l.key]}
										disabled={!can.edit}
										onchange={(v) => setLifetime(l.key, v)}
									/>
								</div>
							{/each}
						</div>
					</Field.Field>
					<Field.Field>
						<Field.Label>Host certificates</Field.Label>
						<div class="grid grid-cols-2 gap-2">
							{#each lifetimes.slice(2) as l (l.key)}
								<div class="flex flex-col gap-1">
									<span class="text-xs text-muted-foreground">{l.label}</span>
									<DurationInput
										value={model[l.key]}
										disabled={!can.edit}
										onchange={(v) => setLifetime(l.key, v)}
									/>
								</div>
							{/each}
						</div>
					</Field.Field>
				</div>
				<Field.Description>
					Short user certificates are the safest, a server without the daemon only drops access when
					they expire. nk renews them on its own before each login. The CA keys themselves never
					expire, rotate them below.
				</Field.Description>
			</Section>

			<Section title="Restrictions" icon={Ban}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="ca-force-command">Force a command</Field.Label>
						<Input
							id="ca-force-command"
							class="font-mono"
							bind:value={model.forceCommand}
							disabled={!can.edit}
							oninput={save}
							placeholder="/usr/local/bin/backup"
						/>
						<Field.Description>Runs this instead of whatever the user asks for.</Field.Description>
					</Field.Field>
					<Field.Field>
						<Field.Label for="ca-source-address">Allowed source IPs</Field.Label>
						<Input
							id="ca-source-address"
							class="font-mono"
							bind:value={model.sourceAddress}
							disabled={!can.edit}
							oninput={save}
							placeholder="10.0.0.0/8, 192.168.1.10"
						/>
						<Field.Description>
							Addresses and CIDRs, separated by commas. Leave empty to allow any.
						</Field.Description>
					</Field.Field>
				</Field.Group>
			</Section>

			<DangerZone
				actions={can.edit
					? [
							{
								title: 'Rotate keys',
								description:
									'Replace both keys. Daemons take the new ones at once, run nk sync on the other servers.',
								label: 'Rotate',
								onClick: askRotate
							},
							{
								title: 'Emergency rollover',
								description: 'Revoke the keys now and replace them. Use when they may have leaked.',
								label: 'Roll over',
								onClick: askRollover
							},
							{
								title: 'Delete CA',
								description: 'Everything it signed stops being trusted.',
								label: 'Delete',
								onClick: askDelete
							}
						]
					: []}
			/>
		</Tabs.Content>
	{/if}
</EntitySheet>
