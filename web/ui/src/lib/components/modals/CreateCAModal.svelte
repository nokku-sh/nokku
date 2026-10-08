<script lang="ts" module>
	import {
		AuthorityType,
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { secToD } from '#lib/utils.js';
	import type { MessageInitShape } from '@bufbuild/protobuf';

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
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as RadioGroup from '#lib/components/ui/radio-group/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import { ChevronDown, Shield } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createCA = caApi.create();
	const uid = $props.id();

	let model = $state(newDraft(CertificateAuthoritySchema, defaultCADraft()));
	let advanced = $state(false);
	const isSSH = $derived(model.authorityType === AuthorityType.SSH);

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

	function reset() {
		model = newDraft(CertificateAuthoritySchema, defaultCADraft());
		advanced = false;
	}

	async function onSubmit() {
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
	submitLabel="Create CA"
	submitDisabled={!model.name.trim()}
	{onSubmit}
>
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
	<Field.Field orientation="horizontal">
		<Field.Content>
			<Field.Label for="new-ca-default">Make it the default</Field.Label>
			<Field.Description>New targets use it unless you pick another CA.</Field.Description>
		</Field.Content>
		<Switch id="new-ca-default" bind:checked={model.isDefault} />
	</Field.Field>

	<Collapsible.Root bind:open={advanced} class="group/advanced rounded-lg border">
		<Collapsible.Trigger
			class="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left text-sm"
		>
			<span class="flex flex-col">
				<span class="font-medium">Key and lifetimes</span>
				<span class="text-xs text-muted-foreground">
					{algorithms.find((a) => a.value === model.keyType)?.label}. The defaults suit most teams
					and can be changed later.
				</span>
			</span>
			<ChevronDown
				class="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]/advanced:rotate-180"
			/>
		</Collapsible.Trigger>
		<Collapsible.Content>
			<Field.Group class="gap-4 border-t p-3">
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
								<ToggleGroup.Item value={String(s.value)} class="flex-1">{s.label}</ToggleGroup.Item
								>
							{/each}
						</ToggleGroup.Root>
					</Field.Field>
				{/if}
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
			</Field.Group>
		</Collapsible.Content>
	</Collapsible.Root>
</FormModal>
