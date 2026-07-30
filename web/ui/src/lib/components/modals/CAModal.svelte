<script lang="ts">
	import { ca } from '$lib/api/certificates.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import { Label } from '$lib/components/ui/label';
	import * as Select from '$lib/components/ui/select';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import {
		AuthorityType,
		CertificateKeyType,
		type CertificateAuthority
	} from '$lib/gen/nokku/v1/certificates_pb';
	import { enumLabel, enumToArray, secToD } from '$lib/utils';
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
	import DurationInput from '../utils/DurationInput.svelte';
	import FormModal from './FormModal.svelte';

	interface Props {
		data?: CertificateAuthority;
		open?: boolean;
	}
	let { data, open = $bindable(false) }: Props = $props();

	function defaultForm() {
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
		} as unknown as CertificateAuthority;
	}

	let formData = $state(defaultForm());

	$effect(() => {
		if (data?.id) {
			formData = { ...data };
		}
	});

	$effect(() => {
		if (!open) {
			formData = defaultForm();
		}
	});

	const createCA = ca.create();
	const updateCA = ca.update();

	async function onSubmit() {
		if (data?.id) {
			updateCA.mutate({ ...formData });
		} else {
			createCA.mutate({ ...formData });
		}
		open = false;
	}

	let isSSH = $derived(formData.authorityType === AuthorityType.SSH);
	let isEditing = $derived(!!data?.id);

	function getKeyBitsOptions(keyType: CertificateKeyType) {
		if (keyType === CertificateKeyType.RSA) {
			return [
				{ value: 2048, label: '2048 bits', desc: 'Minimum (legacy)', recommended: false },
				{ value: 3072, label: '3072 bits', desc: 'Standard', recommended: false },
				{ value: 4096, label: '4096 bits', desc: 'Maximum security', recommended: true }
			];
		}
		if (keyType === CertificateKeyType.ECDSA) {
			return [
				{ value: 256, label: 'P-256', desc: 'Standard', recommended: false },
				{ value: 384, label: 'P-384', desc: 'Recommended', recommended: true },
				{ value: 521, label: 'P-521', desc: 'Maximum security', recommended: false }
			];
		}
		return [];
	}

	let isLoading = $derived(createCA.isPending || updateCA.isPending);
	let needsKeyBits = $derived(
		formData.keyType === CertificateKeyType.RSA || formData.keyType === CertificateKeyType.ECDSA
	);

	function isKeyAllowed(keyType: CertificateKeyType) {
		return formData.allowedKeyTypes?.includes(keyType) ?? false;
	}

	function toggleAllowedKey(keyType: CertificateKeyType) {
		if (!formData.allowedKeyTypes) formData.allowedKeyTypes = [];
		if (formData.allowedKeyTypes.includes(keyType)) {
			formData.allowedKeyTypes = formData.allowedKeyTypes.filter((t) => t !== keyType);
		} else {
			formData.allowedKeyTypes = [...formData.allowedKeyTypes, keyType];
		}
	}

	function hasExtension(ext: string) {
		return formData.userExtensions && formData.userExtensions[ext] !== undefined;
	}

	function toggleExtension(ext: string) {
		if (!formData.userExtensions) formData.userExtensions = {};
		const newExts = { ...formData.userExtensions };
		if (newExts[ext] !== undefined) {
			delete newExts[ext];
		} else {
			newExts[ext] = '';
		}
		formData.userExtensions = newExts;
	}

	function hasCriticalOption(key: string) {
		return formData.userCriticalOptions && formData.userCriticalOptions[key] !== undefined;
	}

	function getCriticalOption(key: string) {
		return formData.userCriticalOptions?.[key] || '';
	}

	function updateCriticalOption(key: string, value: string | undefined) {
		if (!formData.userCriticalOptions) formData.userCriticalOptions = {};
		const newOpts = { ...formData.userCriticalOptions };

		if (value === undefined) {
			delete newOpts[key];
		} else if (value === '' && (key === 'source-address' || key === 'force-command')) {
			delete newOpts[key];
		} else {
			newOpts[key] = value;
		}

		formData.userCriticalOptions = newOpts;
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
	title="{isEditing ? 'Edit' : 'Create'} Certificate Authority"
	description={isSSH
		? 'Configure a certificate authority for SSH certificate signing.'
		: 'Configure a certificate authority for X.509 certificate signing.'}
	submitLabel={isEditing ? 'Update' : 'Create CA'}
	classModal="sm:max-w-xl"
	{onSubmit}
	{isLoading}
>
	<Tabs.Root class="w-full">
		<Tabs.List
			class={formData.authorityType === AuthorityType.SSH
				? 'mb-4 grid w-full grid-cols-4'
				: 'mb-4 grid w-full grid-cols-3'}
		>
			<Tabs.Trigger value="general">
				<Settings2 />
				General
			</Tabs.Trigger>
			<Tabs.Trigger value="keys">
				<KeyRound />
				Keys
			</Tabs.Trigger>
			<Tabs.Trigger value="lifecycle">
				<Clock />
				Lifecycle
			</Tabs.Trigger>
			{#if isSSH}
				<Tabs.Trigger value="policies">
					<ShieldCheck />
					Policies
				</Tabs.Trigger>
			{/if}
		</Tabs.List>

		<Tabs.Content value="general" class="space-y-4">
			<!-- CA Type Selector (only on create) -->
			{#if !isEditing}
				<Field.Field>
					<Field.Label>Certificate Authority Type</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={formData.authorityType.toString()}
							onValueChange={(v) => (formData.authorityType = parseInt(v) as AuthorityType)}
						>
							<Select.Trigger class="w-full">
								{formData.authorityType
									? enumLabel(AuthorityType[formData.authorityType]).toUpperCase()
									: 'Select type'}
							</Select.Trigger>
							<Select.Content>
								{#each authorityTypeOptions as opt}
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
					Type: {formData.authorityType === AuthorityType.SSH ? 'SSH' : 'X.509'} Certificate Authority
				</div>
			{/if}

			<Field.Field>
				<Field.Label for="ca-name">Name *</Field.Label>
				<Field.Content>
					<Input id="ca-name" bind:value={formData.name} placeholder="production-ca" required />
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="ca-description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="ca-description"
						bind:value={formData.description}
						placeholder={isSSH
							? 'Root CA for production SSH certificates'
							: 'Root CA for internal PKI and mTLS'}
						rows={3}
					/>
				</Field.Content>
			</Field.Field>

			<!-- Default CA Toggle -->
			<div
				class="flex items-start gap-3 rounded-lg border bg-muted/30 p-4 transition-colors hover:bg-muted/50"
			>
				<div
					class="rounded-full p-2 transition-colors {formData.isDefault
						? 'bg-yellow-500/10 text-yellow-600'
						: 'bg-muted'}"
				>
					<Star class="{formData.isDefault ? 'fill-yellow-500' : ''} transition-all" size={16} />
				</div>
				<div class="flex-1 space-y-1">
					<div class="flex items-center justify-between gap-4">
						<Label for="is-default" class="cursor-pointer font-medium">Set as Default CA</Label>
						<Switch id="is-default" bind:checked={formData.isDefault} />
					</div>
					<p class="text-xs leading-relaxed text-muted-foreground">
						The default CA is used for new certificate templates and automatic signing.
					</p>
				</div>
			</div>
		</Tabs.Content>

		<Tabs.Content value="keys" class="space-y-4">
			{#if isEditing}
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
								value={formData.keyType.toString()}
								onValueChange={(v) => {
									formData.keyType = parseInt(v) as CertificateKeyType;
									formData.keyBits = 0;
								}}
							>
								<Select.Trigger class="w-full">
									{CertificateKeyType[formData.keyType]}
								</Select.Trigger>
								<Select.Content>
									{#each enumToArray(CertificateKeyType) as keyType}
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
							<Field.Label for="key-bits">Key Size *</Field.Label>
							<Field.Content>
								<Select.Root
									type="single"
									value={formData.keyBits.toString()}
									onValueChange={(v) => (formData.keyBits = parseInt(v))}
								>
									<Select.Trigger class="w-full">
										{formData.keyBits ? `${formData.keyBits} bits` : 'Select size'}
									</Select.Trigger>
									<Select.Content>
										{#each getKeyBitsOptions(formData.keyType) as opt}
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
					{#each enumToArray(CertificateKeyType) as keyType}
						<Item.Root variant="outline" onclick={() => toggleAllowedKey(keyType.value)}>
							<Item.Content>
								<Item.Title>{keyType.name}</Item.Title>
							</Item.Content>
							<Item.Actions>
								<Checkbox
									id="allowed-key-{keyType.value}"
									checked={isKeyAllowed(keyType.value)}
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
					<DurationInput bind:value={formData.lifetime} />
					<Field.Description>
						How long the CA itself remains valid (minimum 1 month — maximum 10 years)
					</Field.Description>
				</Field.Content>
			</Field.Field>

			<!-- User / Client Certificate TTLs -->
			<div class="space-y-3">
				<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
					<User class="text-muted-foreground" size={16} />
					{isSSH ? 'User Certificates' : 'Client Certificates'}
				</div>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>Default TTL</Field.Label>
						<Field.Content>
							<DurationInput bind:value={formData.userDefaultTtl} />
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label>Maximum TTL</Field.Label>
						<Field.Content>
							<DurationInput bind:value={formData.userMaxTtl} />
						</Field.Content>
					</Field.Field>
				</div>
			</div>

			<!-- Host / Server Certificate TTLs -->
			<div class="space-y-3">
				<div class="flex items-center gap-2 border-b pb-2 text-sm font-medium">
					<Server class="text-muted-foreground" size={16} />
					{isSSH ? 'Host Certificates' : 'Server Certificates'}
				</div>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label>Default TTL</Field.Label>
						<Field.Content>
							<DurationInput bind:value={formData.hostDefaultTtl} />
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label>Maximum TTL</Field.Label>
						<Field.Content>
							<DurationInput bind:value={formData.hostMaxTtl} />
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
						{#each extensionOptions as ext}
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
						<div class="flex items-center space-x-3 border-b pb-4">
							<Switch
								id="enable-recording"
								checked={hasCriticalOption('force-command')}
								onCheckedChange={(checked) =>
									updateCriticalOption('force-command', checked ? 'nokkud record' : undefined)}
							/>
							<div class="flex flex-col gap-1">
								<Label for="enable-recording" class="cursor-pointer text-sm font-medium">
									Enable Session Recording
								</Label>
								<span class="text-xs text-muted-foreground">
									Sets force-command to <code class="rounded bg-muted px-1 py-0.5 text-xs"
										>nokkud record</code
									>
									so the daemon records each session.
								</span>
							</div>
						</div>

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
	</Tabs.Root>
</FormModal>
