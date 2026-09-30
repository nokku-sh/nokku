<script lang="ts" module>
	import {
		AuthorityType,
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '$lib/gen/nokku/v1/certificates_pb';
	import { secToD } from '$lib/utils';
	import { create, type MessageInitShape } from '@bufbuild/protobuf';

	function defaultCADraft(): MessageInitShape<typeof CertificateAuthoritySchema> {
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
	import FormModal from '$lib/components/blocks/FormModal.svelte';
	import { ca as caApi } from '$lib/api/certificates.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as RadioGroup from '$lib/components/ui/radio-group';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as Stepper from '$lib/components/ui/stepper';
	import { Switch } from '$lib/components/ui/switch';
	import { Textarea } from '$lib/components/ui/textarea';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';
	import DurationInput from '$lib/components/blocks/DurationInput.svelte';
	import { useSheet } from '$lib/hooks';
	import { Check, Shield } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createCA = caApi.create();
	const uid = $props.id();

	let model = $state(create(CertificateAuthoritySchema, defaultCADraft()));
	let step = $state(1);
	const isSSH = $derived(model.authorityType === AuthorityType.SSH);

	const steps = [
		{ title: 'Basics', description: 'Type and name' },
		{ title: 'Key', description: 'Algorithm' },
		{ title: 'Lifetimes', description: 'How long certs last' }
	];

	const types = [
		{
			value: AuthorityType.SSH,
			title: 'SSH',
			description: 'Signs user and host certificates for SSH logins.'
		},
		{
			value: AuthorityType.X509,
			title: 'X.509',
			description: 'Signs certificates from CSRs for mTLS and internal HTTPS.'
		}
	];

	const algorithms = [
		{ value: CertificateKeyType.ED25519, label: 'Ed25519', recommended: true },
		{ value: CertificateKeyType.ECDSA, label: 'ECDSA' },
		{ value: CertificateKeyType.RSA, label: 'RSA' }
	];

	const sizes: Partial<Record<CertificateKeyType, { value: number; label: string }[]>> = {
		[CertificateKeyType.ECDSA]: [
			{ value: 256, label: 'P-256' },
			{ value: 384, label: 'P-384' },
			{ value: 521, label: 'P-521' }
		],
		[CertificateKeyType.RSA]: [
			{ value: 2048, label: '2048' },
			{ value: 3072, label: '3072' },
			{ value: 4096, label: '4096' }
		]
	};
	const recommendedBits: Partial<Record<CertificateKeyType, number>> = {
		[CertificateKeyType.ECDSA]: 384,
		[CertificateKeyType.RSA]: 4096
	};

	const canContinue = $derived(step !== 1 || model.name.trim().length > 0);

	function reset() {
		model = create(CertificateAuthoritySchema, defaultCADraft());
		step = 1;
	}

	// Enter moves through the steps, the last one creates the CA.
	async function next() {
		if (!canContinue) return false;
		if (step < steps.length) {
			step++;
			return false;
		}
		const res = await createCA.mutateAsync({ ...model });
		reset();
		if (res.certificateAuthority) sheet.show(res.certificateAuthority.id);
	}
</script>

<FormModal
	bind:open
	title="Create a certificate authority"
	description="The key is generated on the server and never leaves it."
	icon={Shield}
	classModal="sm:max-w-lg"
	onOpenChange={(v) => !v && reset()}
	onSubmit={next}
>
	{#snippet before()}
		<Stepper.Root bind:step>
			<Stepper.Nav class="mb-2">
				{#each steps as s, i (s.title)}
					<Stepper.Item>
						<Stepper.Trigger disabled={i + 1 > step && !canContinue} class="items-center gap-1.5">
							<Stepper.Indicator>
								{#if i + 1 < step}<Check />{:else}{i + 1}{/if}
							</Stepper.Indicator>
							<Stepper.Title class="text-xs">{s.title}</Stepper.Title>
						</Stepper.Trigger>
						{#if i < steps.length - 1}
							<Stepper.Separator />
						{/if}
					</Stepper.Item>
				{/each}
			</Stepper.Nav>
		</Stepper.Root>
	{/snippet}

	{#if step === 1}
		<Field.Set>
			<Field.Legend variant="label">What will it sign?</Field.Legend>
			<RadioGroup.Root
				value={String(model.authorityType)}
				onValueChange={(v) => (model.authorityType = Number(v) as AuthorityType)}
				class="grid gap-2 sm:grid-cols-2"
			>
				{#each types as t (t.value)}
					<Field.Label for={`${uid}-type-${t.value}`}>
						<Field.Field orientation="horizontal">
							<Field.Content>
								<Field.Title>{t.title}</Field.Title>
								<Field.Description>{t.description}</Field.Description>
							</Field.Content>
							<RadioGroup.Item value={String(t.value)} id={`${uid}-type-${t.value}`} />
						</Field.Field>
					</Field.Label>
				{/each}
			</RadioGroup.Root>
		</Field.Set>
		<Field.Field>
			<Field.Label for="new-ca-name">Name</Field.Label>
			<Input id="new-ca-name" bind:value={model.name} placeholder="production-ssh" required />
		</Field.Field>
		<Field.Field>
			<Field.Label for="new-ca-description">Description</Field.Label>
			<Textarea
				id="new-ca-description"
				bind:value={model.description}
				placeholder={isSSH ? 'Signs production SSH logins' : 'Internal PKI for service mTLS'}
				rows={2}
			/>
		</Field.Field>
	{:else if step === 2}
		<Field.Field>
			<Field.Label>Algorithm</Field.Label>
			<ToggleGroup.Root
				type="single"
				variant="outline"
				value={String(model.keyType)}
				onValueChange={(v) => {
					if (!v) return;
					model.keyType = Number(v) as CertificateKeyType;
					model.keyBits = recommendedBits[model.keyType] ?? 0;
				}}
				class="w-full"
			>
				{#each algorithms as a (a.value)}
					<ToggleGroup.Item value={String(a.value)} class="flex-1 gap-1.5">
						{a.label}
						{#if a.recommended}<Badge variant="success">Best</Badge>{/if}
					</ToggleGroup.Item>
				{/each}
			</ToggleGroup.Root>
			<Field.Description>
				Ed25519 is fast, small and supported by every modern OpenSSH. Pick RSA only for very old
				clients.
			</Field.Description>
		</Field.Field>
		{#if sizes[model.keyType]}
			<Field.Field>
				<Field.Label>Key size</Field.Label>
				<ToggleGroup.Root
					type="single"
					variant="outline"
					size="sm"
					value={String(model.keyBits)}
					onValueChange={(v) => v && (model.keyBits = Number(v))}
					class="w-full"
				>
					{#each sizes[model.keyType] ?? [] as s (s.value)}
						<ToggleGroup.Item value={String(s.value)} class="flex-1">{s.label}</ToggleGroup.Item>
					{/each}
				</ToggleGroup.Root>
			</Field.Field>
		{/if}
		<Field.Field orientation="horizontal">
			<Field.Content>
				<Field.Label for="new-ca-default">Make it the default</Field.Label>
				<Field.Description>New targets use it unless you pick another CA.</Field.Description>
			</Field.Content>
			<Switch id="new-ca-default" bind:checked={model.isDefault} />
		</Field.Field>
	{:else}
		<Field.Field>
			<Field.Label>The CA expires after</Field.Label>
			<DurationInput bind:value={model.lifetime} />
		</Field.Field>
		<div class="grid grid-cols-2 gap-4">
			<Field.Field>
				<Field.Label>{isSSH ? 'User' : 'Client'} certs by default</Field.Label>
				<DurationInput bind:value={model.userDefaultTtl} />
			</Field.Field>
			<Field.Field>
				<Field.Label>At most</Field.Label>
				<DurationInput bind:value={model.userMaxTtl} />
			</Field.Field>
			<Field.Field>
				<Field.Label>{isSSH ? 'Host' : 'Server'} certs by default</Field.Label>
				<DurationInput bind:value={model.hostDefaultTtl} />
			</Field.Field>
			<Field.Field>
				<Field.Label>At most</Field.Label>
				<DurationInput bind:value={model.hostMaxTtl} />
			</Field.Field>
		</div>
		<Field.Description>
			The defaults suit most teams. Everything here can be changed later.
		</Field.Description>
	{/if}

	{#snippet footer()}
		{#if step > 1}
			<Button type="button" variant="outline" onclick={() => step--}>Back</Button>
		{/if}
		<Button type="submit" disabled={!canContinue || createCA.isPending}>
			{#if createCA.isPending}<Spinner data-icon="inline-start" />{/if}
			{step < steps.length ? 'Continue' : 'Create CA'}
		</Button>
	{/snippet}
</FormModal>
