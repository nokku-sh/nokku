<script lang="ts" module>
	import {
		AuthorityType,
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '$lib/gen/nokku/v1/certificates_pb';
	import type { CertificateAuthority } from '$lib/gen/nokku/v1/certificates_pb';
	import { secToD } from '$lib/utils';
	import type { MessageInitShape } from '@bufbuild/protobuf';

	/** Sensible starting point for a new CA, used by openNew(). */
	export function defaultCADraft(): MessageInitShape<typeof CertificateAuthoritySchema> {
		return {
			name: '',
			description: '',
			authorityType: AuthorityType.SSH,
			keyType: CertificateKeyType.ED25519,
			keyBits: 0,
			isDefault: false,
			lifetime: secToD(365 * 24 * 3600),
			userDefaultTtl: secToD(5 * 24 * 3600),
			userMaxTtl: secToD(7 * 24 * 3600),
			hostDefaultTtl: secToD(90 * 24 * 3600),
			hostMaxTtl: secToD(180 * 24 * 3600),
			allowedKeyTypes: [
				CertificateKeyType.RSA,
				CertificateKeyType.ECDSA,
				CertificateKeyType.ED25519
			],
			userExtensions: { 'permit-pty': '', 'permit-user-rc': '' },
			userCriticalOptions: {}
		};
	}
</script>

<script lang="ts">
	import {
		Clock,
		FileStack,
		Info,
		KeyRound,
		Server,
		Settings2,
		Shield,
		ShieldAlert,
		ShieldCheck,
		Star,
		User
	} from '@lucide/svelte';
	import { ca } from '$lib/api/certificates.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Item from '$lib/components/ui/item';
	import * as Select from '$lib/components/ui/select';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import { useAutoSave } from '$lib/hooks';
	import { enumLabel, enumToArray } from '$lib/utils';
	import DurationInput from '../utils/DurationInput.svelte';
	import FormModal from './FormModal.svelte';
	import MetaInfo from './MetaInfo.svelte';
	import ModalTabs from './ModalTabs.svelte';

	interface Props {
		draft: CertificateAuthority;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const isEdit = $derived(!!model.id);
	const isSSH = $derived(model.authorityType === AuthorityType.SSH);

	const createCA = ca.create();
	const updateCA = ca.update();

	const autoSave = useAutoSave(() => updateCA.mutateAsync({ ...model }));
	function save() {
		if (isEdit) autoSave.save();
	}

	function onSubmit() {
		createCA.mutate({ ...model });
		open = false;
	}

	const tabs = $derived(
		isSSH
			? [
					{ value: 'general', label: 'General', icon: Settings2 },
					{ value: 'keys', label: 'Keys', icon: KeyRound },
					{ value: 'lifecycle', label: 'Lifecycle', icon: Clock },
					{ value: 'policies', label: 'Policies', icon: ShieldCheck }
				]
			: [
					{ value: 'general', label: 'General', icon: Settings2 },
					{ value: 'keys', label: 'Keys', icon: KeyRound },
					{ value: 'lifecycle', label: 'Lifecycle', icon: Clock }
				]
	);

	function getKeyBitsOptions(keyType: CertificateKeyType) {
		if (keyType === CertificateKeyType.RSA) {
			return [
				{ value: 2048, label: '2048 bits' },
				{ value: 3072, label: '3072 bits' },
				{ value: 4096, label: '4096 bits', recommended: true }
			];
		}
		if (keyType === CertificateKeyType.ECDSA) {
			return [
				{ value: 256, label: 'P-256' },
				{ value: 384, label: 'P-384', recommended: true },
				{ value: 521, label: 'P-521' }
			];
		}
		return [];
	}

	let needsKeyBits = $derived(
		model.keyType === CertificateKeyType.RSA || model.keyType === CertificateKeyType.ECDSA
	);

	function toggleAllowedKey(keyType: CertificateKeyType) {
		const allowed = model.allowedKeyTypes ?? [];
		model.allowedKeyTypes = allowed.includes(keyType)
			? allowed.filter((t) => t !== keyType)
			: [...allowed, keyType];
		save();
	}

	function hasExtension(ext: string) {
		return model.userExtensions?.[ext] !== undefined;
	}

	function toggleExtension(ext: string) {
		const exts = { ...model.userExtensions };
		if (exts[ext] !== undefined) {
			delete exts[ext];
		} else {
			exts[ext] = '';
		}
		model.userExtensions = exts;
		save();
	}

	function getCriticalOption(key: string) {
		return model.userCriticalOptions?.[key] || '';
	}

	function hasCriticalOption(key: string) {
		return model.userCriticalOptions?.[key] !== undefined;
	}

	function updateCriticalOption(key: string, value: string | undefined) {
		const opts = { ...model.userCriticalOptions };
		if (
			value === undefined ||
			(value === '' && (key === 'source-address' || key === 'force-command'))
		) {
			delete opts[key];
		} else {
			opts[key] = value;
		}
		model.userCriticalOptions = opts;
		save();
	}

	const authorityTypeOptions = [
		{
			value: AuthorityType.SSH,
			label: 'SSH',
			desc: 'Signs SSH user and host certificates for key-based access.'
		},
		{
			value: AuthorityType.X509,
			label: 'X.509',
			desc: 'Signs X.509 certificates from CSRs for mTLS, HTTPS, and PKI.'
		}
	];

	const extensionOptions = [
		{ id: 'permit-pty', label: 'PTY', desc: 'Permit terminal allocation' },
		{
			id: 'permit-port-forwarding',
			label: 'Port Forwarding',
			desc: 'Permit local port forwarding'
		},
		{
			id: 'permit-agent-forwarding',
			label: 'Agent Forwarding',
			desc: 'Permit ssh-agent forwarding'
		},
		{ id: 'permit-X11-forwarding', label: 'X11 Forwarding', desc: 'Permit X11 GUI forwarding' },
		{ id: 'permit-user-rc', label: 'User RC', desc: 'Permit execution of ~/.ssh/rc' },
		{
			id: 'no-touch-required',
			label: 'No Touch Required',
			desc: 'Bypass touch requirement on FIDO keys'
		}
	];
</script>

<FormModal
	bind:open
	title={isEdit ? model.name : 'Create Certificate Authority'}
	description={isEdit
		? `${isSSH ? 'SSH' : 'X.509'} authority. Changes save automatically.`
		: `Configure a certificate authority for ${isSSH ? 'SSH' : 'X.509'} certificate signing.`}
	classModal="sm:max-w-xl"
	onSubmit={isEdit ? undefined : onSubmit}
	isLoading={createCA.isPending}
	saveState={autoSave.saveState}
>
	<ModalTabs {tabs}>
		<Tabs.Content value="general" class="space-y-4">
			{#if !isEdit}
				<Field.Field>
					<Field.Label>Certificate Authority Type</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={model.authorityType.toString()}
							onValueChange={(v) => (model.authorityType = parseInt(v) as AuthorityType)}
						>
							<Select.Trigger class="w-full">
								{enumLabel(AuthorityType[model.authorityType]).toUpperCase()}
							</Select.Trigger>
							<Select.Content>
								{#each authorityTypeOptions as opt (opt.value)}
									<Select.Item value={opt.value.toString()} class="px-4">
										<div class="flex flex-col gap-0.5">
											<span class="font-medium">{opt.label}</span>
											<span class="text-xs text-muted-foreground">{opt.desc}</span>
										</div>
									</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</Field.Content>
				</Field.Field>
			{:else}
				<div
					class="flex items-center gap-2 rounded-lg border bg-muted/50 p-3 text-sm text-muted-foreground"
				>
					<Info size={16} class="text-primary" />
					Type: {isSSH ? 'SSH' : 'X.509'} Certificate Authority
				</div>
			{/if}

			<Field.Field>
				<Field.Label for="ca-name">Name</Field.Label>
				<Field.Content>
					<Input
						id="ca-name"
						bind:value={model.name}
						placeholder="production-ca"
						required
						oninput={save}
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="ca-description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="ca-description"
						bind:value={model.description}
						placeholder={isSSH
							? 'Root CA for production SSH certificates'
							: 'Root CA for internal PKI and mTLS'}
						rows={3}
						oninput={save}
					/>
				</Field.Content>
			</Field.Field>

			<div
				class="flex items-start gap-3 rounded-lg border bg-muted/30 p-4 transition-colors hover:bg-muted/50"
			>
				<div
					class="rounded-full p-2 transition-colors {model.isDefault
						? 'bg-yellow-500/10 text-yellow-600'
						: 'bg-muted'}"
				>
					<Star class="{model.isDefault ? 'fill-yellow-500' : ''} transition-all" size={16} />
				</div>
				<div class="flex-1 space-y-1">
					<div class="flex items-center justify-between gap-4">
						<Label for="is-default" class="cursor-pointer font-medium">Set as Default CA</Label>
						<Switch
							id="is-default"
							checked={model.isDefault}
							onCheckedChange={(v) => {
								model.isDefault = v;
								save();
							}}
						/>
					</div>
					<p class="text-xs leading-relaxed text-muted-foreground">
						The default CA is used for new certificate templates and automatic signing.
					</p>
				</div>
			</div>

			{#if isEdit}
				<MetaInfo createdAt={model.createdAt} updatedAt={model.updatedAt} />
			{/if}
		</Tabs.Content>

		<Tabs.Content value="keys" class="space-y-4">
			{#if isEdit}
				<div
					class="flex items-center gap-2 rounded-lg border bg-muted/50 p-4 text-sm text-muted-foreground"
				>
					<Info size={16} class="text-primary" />
					Key configuration cannot be changed after creation.
				</div>
			{:else}
				<div class="mb-2 flex items-center gap-2 text-sm font-medium">
					<KeyRound class="text-muted-foreground" size={16} />
					Key Algorithm Configuration
				</div>

				<div class="grid gap-5">
					<Field.Field>
						<Field.Label for="key-type">Algorithm</Field.Label>
						<Field.Content>
							<Select.Root
								type="single"
								value={model.keyType.toString()}
								onValueChange={(v) => {
									model.keyType = parseInt(v) as CertificateKeyType;
									model.keyBits = 0;
								}}
							>
								<Select.Trigger class="w-full">
									{CertificateKeyType[model.keyType]}
								</Select.Trigger>
								<Select.Content>
									{#each enumToArray(CertificateKeyType) as keyType (keyType.value)}
										<Select.Item value={keyType.value.toString()} class="px-4">
											<span>{keyType.name}</span>
											{#if keyType.value === CertificateKeyType.ED25519}
												<Badge variant="secondary" class="text-xs font-normal">Recommended</Badge>
											{/if}
										</Select.Item>
									{/each}
								</Select.Content>
							</Select.Root>
						</Field.Content>
					</Field.Field>

					{#if needsKeyBits}
						<Field.Field>
							<Field.Label for="key-bits">Key Size</Field.Label>
							<Field.Content>
								<Select.Root
									type="single"
									value={model.keyBits.toString()}
									onValueChange={(v) => (model.keyBits = parseInt(v))}
								>
									<Select.Trigger class="w-full">
										{model.keyBits ? `${model.keyBits} bits` : 'Select size'}
									</Select.Trigger>
									<Select.Content>
										{#each getKeyBitsOptions(model.keyType) as opt (opt.value)}
											<Select.Item value={opt.value.toString()} class="px-4">
												<span>{opt.label}</span>
												{#if opt.recommended}
													<Badge variant="secondary" class="text-xs font-normal">Recommended</Badge>
												{/if}
											</Select.Item>
										{/each}
									</Select.Content>
								</Select.Root>
							</Field.Content>
						</Field.Field>
					{/if}
				</div>
			{/if}

			<div class="mt-8 space-y-4">
				<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
					<Shield class="text-muted-foreground" size={16} />
					Permitted {isSSH ? 'Client' : 'Leaf'} Key Types
				</div>
				<p class="text-xs text-muted-foreground">
					Select which key algorithms {isSSH ? 'clients' : 'certificate requestors'} are permitted to
					use when requesting certificates from this CA.
				</p>
				<div class="grid gap-3 sm:grid-cols-3">
					{#each enumToArray(CertificateKeyType) as keyType (keyType.value)}
						<Item.Root variant="outline" onclick={() => toggleAllowedKey(keyType.value)}>
							<Item.Content>
								<Item.Title>{keyType.name}</Item.Title>
							</Item.Content>
							<Item.Actions>
								<Checkbox
									id="allowed-key-{keyType.value}"
									checked={(model.allowedKeyTypes ?? []).includes(keyType.value)}
									onCheckedChange={() => toggleAllowedKey(keyType.value)}
								/>
							</Item.Actions>
						</Item.Root>
					{/each}
				</div>
			</div>
		</Tabs.Content>

		<Tabs.Content value="lifecycle" class="space-y-4">
			<Field.Field>
				<Field.Label>CA Validity Period</Field.Label>
				<Field.Content>
					<DurationInput
						value={model.lifetime}
						onchange={(v) => {
							model.lifetime = v;
							save();
						}}
					/>
					<Field.Description>
						How long the CA itself remains valid (minimum 1 month, maximum 10 years)
					</Field.Description>
				</Field.Content>
			</Field.Field>

			<div class="space-y-3">
				<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
					<User class="text-muted-foreground" size={16} />
					{isSSH ? 'User Certificates' : 'Client Certificates'}
				</div>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>Default TTL</Field.Label>
						<Field.Content>
							<DurationInput
								value={model.userDefaultTtl}
								onchange={(v) => {
									model.userDefaultTtl = v;
									save();
								}}
							/>
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label>Maximum TTL</Field.Label>
						<Field.Content>
							<DurationInput
								value={model.userMaxTtl}
								onchange={(v) => {
									model.userMaxTtl = v;
									save();
								}}
							/>
						</Field.Content>
					</Field.Field>
				</div>
			</div>

			<div class="space-y-3">
				<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
					<Server class="text-muted-foreground" size={16} />
					{isSSH ? 'Host Certificates' : 'Server Certificates'}
				</div>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>Default TTL</Field.Label>
						<Field.Content>
							<DurationInput
								value={model.hostDefaultTtl}
								onchange={(v) => {
									model.hostDefaultTtl = v;
									save();
								}}
							/>
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label>Maximum TTL</Field.Label>
						<Field.Content>
							<DurationInput
								value={model.hostMaxTtl}
								onchange={(v) => {
									model.hostMaxTtl = v;
									save();
								}}
							/>
						</Field.Content>
					</Field.Field>
				</div>
			</div>
		</Tabs.Content>

		{#if isSSH}
			<Tabs.Content value="policies" class="space-y-4">
				<div
					class="flex items-center gap-2 rounded-lg border bg-muted/50 p-3 text-xs text-muted-foreground"
				>
					<Info size={14} class="text-primary" />
					<span class="font-medium">
						These policies only apply to SSH <strong>user</strong> certificates. Host certificates ignore
						extensions and critical options.
					</span>
				</div>

				<div class="space-y-4 pt-2">
					<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
						<FileStack class="text-muted-foreground" size={16} />
						SSH Extensions
					</div>
					<p class="-mt-1 text-xs text-muted-foreground">
						Default extensions included in signed user certificates.
					</p>
					<div class="grid gap-4 sm:grid-cols-2">
						{#each extensionOptions as ext (ext.id)}
							<Item.Root variant="outline" onclick={() => toggleExtension(ext.id)}>
								<Item.Content>
									<Item.Title>{ext.label}</Item.Title>
									<Item.Description>{ext.desc}</Item.Description>
								</Item.Content>
								<Item.Actions>
									<Checkbox
										id="ext-{ext.id}"
										checked={hasExtension(ext.id)}
										onCheckedChange={() => toggleExtension(ext.id)}
									/>
								</Item.Actions>
							</Item.Root>
						{/each}
					</div>
				</div>

				<div class="space-y-4 pt-2">
					<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
						<ShieldAlert class="text-muted-foreground" size={16} />
						Critical Options
					</div>
					<p class="-mt-1 text-xs text-muted-foreground">
						Enforce restrictions on all user certificates signed by this CA.
					</p>

					<div class="space-y-5 rounded-md border bg-muted/20 p-4">
						<Field.Field>
							<Field.Label>Force Command</Field.Label>
							<Field.Content>
								<Input
									value={getCriticalOption('force-command')}
									oninput={(e) => updateCriticalOption('force-command', e.currentTarget.value)}
									placeholder="e.g. /bin/ls"
								/>
								<Field.Description
									>Forces execution of this specific command, ignoring client requests.</Field.Description
								>
							</Field.Content>
						</Field.Field>

						<Field.Field>
							<Field.Label>Source Address</Field.Label>
							<Field.Content>
								<Input
									value={getCriticalOption('source-address')}
									oninput={(e) => updateCriticalOption('source-address', e.currentTarget.value)}
									placeholder="e.g. 192.168.1.0/24,10.0.0.1"
								/>
								<Field.Description
									>Comma-separated list of CIDR addresses from which the certificate is considered
									valid.</Field.Description
								>
							</Field.Content>
						</Field.Field>

						<div class="flex items-center space-x-3 pt-2">
							<Switch
								id="verify-required"
								checked={hasCriticalOption('verify-required')}
								onCheckedChange={(checked) =>
									updateCriticalOption('verify-required', checked ? '' : undefined)}
							/>
							<div class="flex flex-col gap-1">
								<Label for="verify-required" class="cursor-pointer text-sm font-medium">
									User Verification Required
								</Label>
								<span class="text-xs text-muted-foreground">
									Require PIN/Biometric verification (for FIDO/U2F security keys) when using the
									certificate.
								</span>
							</div>
						</div>
					</div>
				</div>
			</Tabs.Content>
		{/if}
	</ModalTabs>
</FormModal>
