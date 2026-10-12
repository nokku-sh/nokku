<script lang="ts">
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import SignModal from '#lib/components/modals/SignModal.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import {
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { enumToArray, formatTs } from '#lib/utils.js';
	import type { Duration } from '@bufbuild/protobuf/wkt';
	import {
		Ban,
		Clock,
		FileText,
		Fingerprint,
		History,
		Info,
		KeyRound,
		PenLine,
		Settings2,
		Shield,
		Star
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

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	const keyTypes = enumToArray(CertificateKeyType);
	let signOpen = $state(false);

	const lifetimes: {
		key: 'userDefaultTtl' | 'userMaxTtl' | 'hostDefaultTtl' | 'hostMaxTtl';
		label: string;
	}[] = [
		{ key: 'userDefaultTtl', label: 'Default' },
		{ key: 'userMaxTtl', label: 'Longest allowed' },
		{ key: 'hostDefaultTtl', label: 'Default' },
		{ key: 'hostMaxTtl', label: 'Longest allowed' }
	];

	function setLifetime(key: (typeof lifetimes)[number]['key'] | 'lifetime', value: Duration) {
		if (!model) return;
		model[key] = value;
		save();
	}

	function setOption(key: string, value: string | undefined) {
		if (!model) return;
		const next = { ...model.userCriticalOptions };
		if (value === undefined || (value === '' && key !== 'verify-required')) delete next[key];
		else next[key] = value;
		model.userCriticalOptions = next;
		save();
	}

	function askRollover() {
		if (!entity) return;
		void confirm({
			title: `Emergency rollover of ${entity.name}?`,
			description:
				'The current key stops being trusted at once and a new one replaces it. People get a new certificate at their next connection. Servers without the daemon trust the old key until the next nk sync.',
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

{#if entity}
	<SignModal bind:open={signOpen} ca={entity} />
{/if}

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
	saveState={autoSave.saveState}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.edit}
	missing={query.isError}
	meta={{ id: entity?.id, createdAt: entity?.createdAt, updatedAt: entity?.updatedAt }}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<Shield class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		{#if model?.isDefault}
			<Badge variant="warning"><Star data-icon="inline-start" />Default</Badge>
		{/if}
		{#if model && !model.isActive}
			<Badge variant="destructive">Inactive</Badge>
		{/if}
	{/snippet}

	{#snippet actions()}
		<Button size="sm" onclick={() => (signOpen = true)}>
			<PenLine data-icon="inline-start" />
			Sign a certificate
		</Button>
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<Section
				title="Public key"
				icon={KeyRound}
				description="Servers trust certificates signed by this key."
			>
				<CodeSnippet code={entity.publicKey} language="openssh" wrap />
			</Section>

			{#if entity.previousPublicKey}
				<Section
					title="Previous key"
					icon={History}
					description={entity.previousTrustedUntil
						? `Replaced by a rollover. Still trusted until ${formatTs(entity.previousTrustedUntil)}.`
						: 'Replaced by a rollover.'}
				>
					<CodeSnippet code={entity.previousPublicKey} language="openssh" wrap />
				</Section>
			{/if}

			<Section title="Identity" icon={Fingerprint}>
				<DetailList
					items={[
						{
							label: 'Algorithm',
							value: `${CertificateKeyType[entity.keyType]}${entity.keyBits ? ` ${entity.keyBits}` : ''}`
						},
						{ label: 'Valid from', value: formatTs(entity.notBefore) },
						{ label: 'Valid until', value: formatTs(entity.notAfter) }
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
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="ca-active">Active</Field.Label>
							<Field.Description>An inactive CA signs no new certificates.</Field.Description>
						</Field.Content>
						<Switch
							id="ca-active"
							checked={model.isActive}
							disabled={!can.edit}
							onCheckedChange={(v) => {
								model.isActive = v;
								save();
							}}
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<Section
				title="Accepted client keys"
				icon={KeyRound}
				description="Only these key types can get a certificate from this CA."
			>
				<ToggleGroup.Root
					type="multiple"
					variant="outline"
					size="sm"
					aria-label="Accepted key types"
					disabled={!can.edit}
					value={model.allowedKeyTypes.map(String)}
					onValueChange={(v) => {
						model.allowedKeyTypes = v.map(Number) as CertificateKeyType[];
						save();
					}}
				>
					{#each keyTypes as k (k.value)}
						<ToggleGroup.Item value={String(k.value)}>{k.name}</ToggleGroup.Item>
					{/each}
				</ToggleGroup.Root>
			</Section>

			<Section title="Certificate lifetime" icon={Clock}>
				<Field.Field>
					<Field.Label>The CA itself expires after</Field.Label>
					<DurationInput
						value={model.lifetime}
						disabled={!can.edit}
						onchange={(v) => setLifetime('lifetime', v)}
					/>
				</Field.Field>
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
					Short user certificates are the safest. nk renews them on its own before each login.
				</Field.Description>
			</Section>

			<Section title="Restrictions" icon={Ban}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="ca-force-command">Force a command</Field.Label>
						<Input
							id="ca-force-command"
							class="font-mono"
							value={model.userCriticalOptions['force-command'] ?? ''}
							disabled={!can.edit}
							oninput={(e) => setOption('force-command', e.currentTarget.value)}
							placeholder="/usr/local/bin/backup"
						/>
						<Field.Description>Runs this instead of whatever the user asks for.</Field.Description>
					</Field.Field>
					<Field.Field>
						<Field.Label for="ca-source-address">Allowed source IPs</Field.Label>
						<Input
							id="ca-source-address"
							class="font-mono"
							value={model.userCriticalOptions['source-address'] ?? ''}
							disabled={!can.edit}
							oninput={(e) => setOption('source-address', e.currentTarget.value)}
							placeholder="10.0.0.0/8, 192.168.1.10"
						/>
						<Field.Description>Comma separated CIDRs. Leave empty to allow any.</Field.Description>
					</Field.Field>
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="ca-verify">Require PIN or biometrics</Field.Label>
							<Field.Description>For FIDO security keys, not just a touch.</Field.Description>
						</Field.Content>
						<Switch
							id="ca-verify"
							checked={model.userCriticalOptions['verify-required'] !== undefined}
							disabled={!can.edit}
							onCheckedChange={(v) => setOption('verify-required', v ? '' : undefined)}
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<DangerZone
				actions={can.edit
					? [
							{
								title: 'Emergency rollover',
								description: 'Revoke the key now and replace it. Use when it may have leaked.',
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
