<script lang="ts">
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import {
		CertificateAuthoritySchema,
		CertificateKeyType
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import { ChevronDown, Shield } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createCA = caApi.create();

	// Only the key is chosen here. The lifetimes are the server's, so the two never drift.
	// A draft leaves what it is not given undefined, so every field the form reads is named.
	const blank = () =>
		newDraft(CertificateAuthoritySchema, {
			name: '',
			description: '',
			keyType: CertificateKeyType.ED25519,
			keyBits: 0,
			isDefault: false
		});
	let model = $state(blank());
	let advanced = $state(false);

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
		model = blank();
		advanced = false;
	}

	async function onSubmit() {
		const res = await createCA.mutateAsync({ ...model });
		reset();
		if (res.certificateAuthority) await sheet.show(res.certificateAuthority.id);
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
	<Field.Field>
		<Field.Label for="new-ca-name">Name</Field.Label>
		<Input id="new-ca-name" bind:value={model.name} placeholder="production-ssh" required />
	</Field.Field>
	<Field.Field>
		<Field.Label for="new-ca-description">Description</Field.Label>
		<Textarea
			id="new-ca-description"
			bind:value={model.description}
			placeholder="Signs production SSH logins"
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
				<span class="font-medium">Key</span>
				<span class="text-xs text-muted-foreground">
					{algorithms.find((a) => a.value === model.keyType)?.label}. Lifetimes start from the
					defaults, change them on the CA afterwards.
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
			</Field.Group>
		</Collapsible.Content>
	</Collapsible.Root>
</FormModal>
