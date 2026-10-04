<script lang="ts">
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import SignModal from '#lib/components/modals/SignModal.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import {
		AuthorityType,
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { enumToArray, formatTs } from '#lib/utils.js';
	import type { Duration } from '@bufbuild/protobuf/wkt';
	import {
		Ban,
		Clock,
		Copy,
		FileText,
		KeyRound,
		PenLine,
		Shield,
		ShieldCheck,
		Star
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import DangerZone from './DangerZone.svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const query = caApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(CertificateAuthoritySchema, () => query.data);
	const model = $derived(draft.current);

	const update = caApi.update();
	const remove = caApi.delete();
	const rollover = caApi.rollover();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	const isSSH = $derived(model?.authorityType === AuthorityType.SSH);
	const keyTypes = enumToArray(CertificateKeyType);
	let signOpen = $state(false);

	const extensions = [
		{ id: 'permit-pty', title: 'Interactive shell', description: 'Open a terminal (PTY).' },
		{
			id: 'permit-port-forwarding',
			title: 'Port forwarding',
			description: 'Tunnel ports with -L and -D.'
		},
		{
			id: 'permit-agent-forwarding',
			title: 'Agent forwarding',
			description: 'Use the local ssh-agent on the server.'
		},
		{ id: 'permit-X11-forwarding', title: 'X11 forwarding', description: 'Run GUI apps remotely.' },
		{
			id: 'permit-user-rc',
			title: 'Run ~/.ssh/rc',
			description: 'Execute the user rc file on login.'
		},
		{
			id: 'no-touch-required',
			title: 'Skip security key touch',
			description: 'FIDO keys sign without a tap.'
		}
	];

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

	function toggleExtension(id: string, on: boolean) {
		if (!model) return;
		const next = { ...model.userExtensions };
		if (on) next[id] = '';
		else delete next[id];
		model.userExtensions = next;
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

	async function copyPublicKey() {
		if (!entity?.publicKey) return;
		await navigator.clipboard.writeText(entity.publicKey);
		toast.success('Public key copied');
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
	onRename={(name) => {
		if (!model) return;
		model.name = name;
		save();
	}}
	saveState={autoSave.saveState}
	missing={query.isError}
	meta={{
		id: entity?.id,
		createdAt: entity?.createdAt,
		updatedAt: entity?.updatedAt,
		extra: [{ label: 'Serial', value: entity?.serialNumber, copy: true }]
	}}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<Shield class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		<Badge variant="outline">{isSSH ? 'SSH' : 'X.509'}</Badge>
		{#if model?.isDefault}
			<Badge variant="warning"><Star data-icon="inline-start" />Default</Badge>
		{/if}
		{#if entity?.notAfter}
			<span>Valid until {formatTs(entity.notAfter, 'short')}</span>
		{/if}
	{/snippet}

	{#snippet actions()}
		<Button size="sm" onclick={() => (signOpen = true)}>
			<PenLine data-icon="inline-start" />
			Sign a certificate
		</Button>
		{#if entity?.publicKey}
			<Button size="sm" variant="outline" onclick={copyPublicKey}>
				<Copy data-icon="inline-start" />
				Copy public key
			</Button>
		{/if}
	{/snippet}

	{#if model && entity}
		<div class="flex flex-col divide-y">
			<Section title="Details" icon={FileText}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="ca-description">Description</Field.Label>
						<Textarea
							id="ca-description"
							bind:value={model.description}
							placeholder="Signs production SSH certificates"
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
							onCheckedChange={(v) => {
								model.isDefault = v;
								save();
							}}
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<Section title="Key" icon={KeyRound}>
				<DetailList
					items={[
						{
							label: 'Algorithm',
							value: `${CertificateKeyType[entity.keyType]}${entity.keyBits ? ` ${entity.keyBits}` : ''}`
						},
						{ label: 'Subject', value: entity.subject, mono: true },
						{ label: 'Serial', value: entity.serialNumber, mono: true, copy: true },
						{ label: 'Valid from', value: formatTs(entity.notBefore) },
						{ label: 'Valid until', value: formatTs(entity.notAfter) },
						...(entity.previousTrustedUntil
							? [
									{
										label: 'Previous key trusted until',
										value: formatTs(entity.previousTrustedUntil)
									}
								]
							: [])
					]}
				/>
				<Field.Field>
					<Field.Label>Accepted {isSSH ? 'client' : 'requester'} keys</Field.Label>
					<ToggleGroup.Root
						type="multiple"
						variant="outline"
						size="sm"
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
					<Field.Description
						>Only these key types can get a certificate from this CA.</Field.Description
					>
				</Field.Field>
			</Section>

			<Section title="Certificate lifetime" icon={Clock}>
				<Field.Field>
					<Field.Label>The CA itself expires after</Field.Label>
					<DurationInput value={model.lifetime} onchange={(v) => setLifetime('lifetime', v)} />
				</Field.Field>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>{isSSH ? 'User' : 'Client'} certificates</Field.Label>
						<div class="grid grid-cols-2 gap-2">
							{#each lifetimes.slice(0, 2) as l (l.key)}
								<div class="flex flex-col gap-1">
									<span class="text-xs text-muted-foreground">{l.label}</span>
									<DurationInput value={model[l.key]} onchange={(v) => setLifetime(l.key, v)} />
								</div>
							{/each}
						</div>
					</Field.Field>
					<Field.Field>
						<Field.Label>{isSSH ? 'Host' : 'Server'} certificates</Field.Label>
						<div class="grid grid-cols-2 gap-2">
							{#each lifetimes.slice(2) as l (l.key)}
								<div class="flex flex-col gap-1">
									<span class="text-xs text-muted-foreground">{l.label}</span>
									<DurationInput value={model[l.key]} onchange={(v) => setLifetime(l.key, v)} />
								</div>
							{/each}
						</div>
					</Field.Field>
				</div>
				<Field.Description>
					Short user certificates are the safest. nk renews them on its own before each login.
				</Field.Description>
			</Section>

			{#if isSSH}
				<Section title="What user certificates allow" icon={ShieldCheck}>
					<Item.Group class="divide-y rounded-lg border">
						{#each extensions as ext (ext.id)}
							<Item.Root size="sm" class="rounded-none">
								<Item.Content>
									<Item.Title><label for={`ext-${ext.id}`}>{ext.title}</label></Item.Title>
									<Item.Description>{ext.description}</Item.Description>
								</Item.Content>
								<Item.Actions>
									<Switch
										id={`ext-${ext.id}`}
										checked={model.userExtensions[ext.id] !== undefined}
										onCheckedChange={(v) => toggleExtension(ext.id, v)}
									/>
								</Item.Actions>
							</Item.Root>
						{/each}
					</Item.Group>
				</Section>

				<Section title="Restrictions" icon={Ban}>
					<Field.Group class="gap-4">
						<Field.Field>
							<Field.Label for="ca-force-command">Force a command</Field.Label>
							<Input
								id="ca-force-command"
								class="font-mono"
								value={model.userCriticalOptions['force-command'] ?? ''}
								oninput={(e) => setOption('force-command', e.currentTarget.value)}
								placeholder="/usr/local/bin/backup"
							/>
							<Field.Description>Runs this instead of whatever the user asks for.</Field.Description
							>
						</Field.Field>
						<Field.Field>
							<Field.Label for="ca-source-address">Allowed source IPs</Field.Label>
							<Input
								id="ca-source-address"
								class="font-mono"
								value={model.userCriticalOptions['source-address'] ?? ''}
								oninput={(e) => setOption('source-address', e.currentTarget.value)}
								placeholder="10.0.0.0/8, 192.168.1.10"
							/>
							<Field.Description>Comma separated CIDRs. Leave empty to allow any.</Field.Description
							>
						</Field.Field>
						<Field.Field orientation="horizontal">
							<Field.Content>
								<Field.Label for="ca-verify">Require PIN or biometrics</Field.Label>
								<Field.Description>For FIDO security keys, not just a touch.</Field.Description>
							</Field.Content>
							<Switch
								id="ca-verify"
								checked={model.userCriticalOptions['verify-required'] !== undefined}
								onCheckedChange={(v) => setOption('verify-required', v ? '' : undefined)}
							/>
						</Field.Field>
					</Field.Group>
				</Section>
			{/if}

			<DangerZone
				actions={[
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
				]}
			/>
		</div>
	{/if}
</EntitySheet>
