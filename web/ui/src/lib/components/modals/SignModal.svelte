<script lang="ts">
	import { sign } from '#lib/api/certificates.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Field from '#lib/components/ui/field/index.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import {
		SignSSHCertificateRequestSchema,
		type CertificateAuthority
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { formatTs } from '#lib/utils.js';
	import { create } from '@bufbuild/protobuf';
	import { KeyRound, Server } from '@lucide/svelte';

	interface Props {
		open?: boolean;
		ca?: CertificateAuthority;
	}
	let { open = $bindable(false), ca }: Props = $props();

	let payload = $state(create(SignSSHCertificateRequestSchema));

	const signUser = sign.user();

	// A certificate is signed for one server of this CA.
	let targetId = $state('');
	const targets = target.list(
		() => ({ caId: ca?.id }),
		() => open
	);
	const servers = $derived(targets.data?.targets ?? []);

	function resetModal() {
		payload = create(SignSSHCertificateRequestSchema);
		targetId = '';
		signUser.reset?.();
	}

	$effect(() => {
		if (!open) resetModal();
	});

	// Stays open to show the signed certificate.
	async function handleSubmit() {
		payload.targetId = targetId;
		await signUser.mutateAsync(payload);
		return false;
	}

	function submitOnEnter(e: KeyboardEvent & { currentTarget: HTMLTextAreaElement }) {
		if (e.key !== 'Enter' || e.shiftKey) return;
		e.preventDefault();
		e.currentTarget.form?.requestSubmit();
	}

	const signed = $derived(signUser.data);
</script>

<FormModal
	bind:open
	title="Sign an SSH certificate"
	description="Paste a public key, get back a user certificate for your accounts on one server."
	icon={KeyRound}
	classModal="sm:max-w-xl"
	onSubmit={handleSubmit}
	submitLabel="Sign"
	submitDisabled={signUser.isPending || !targetId}
>
	<Field.Field>
		<Field.Label for="sign-target">Server</Field.Label>
		<Select.Root type="single" bind:value={targetId}>
			<Select.Trigger id="sign-target" class="w-full">
				{servers.find((t) => t.id === targetId)?.name ?? 'Pick a server'}
			</Select.Trigger>
			<Select.Content>
				<Select.Group>
					{#each servers as t (t.id)}
						<Select.Item value={t.id}>
							<Server />
							{t.name}
						</Select.Item>
					{/each}
				</Select.Group>
			</Select.Content>
		</Select.Root>
		<Field.Description>
			The certificate works on this server only, for the accounts you are granted there.
		</Field.Description>
	</Field.Field>
	<Field.Field>
		<Field.Label for="public-key">Public key</Field.Label>
		<Textarea
			id="public-key"
			bind:value={payload.publicKey}
			placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... you@laptop"
			class="min-h-20 font-mono text-xs break-all"
			onkeydown={submitOnEnter}
			required
			disabled={signUser.isPending}
		/>
	</Field.Field>
	<Field.Field>
		<Field.Label>Lifetime</Field.Label>
		<DurationInput bind:value={payload.ttl} />
		<Field.Description>Leave empty for the CA default.</Field.Description>
	</Field.Field>

	{#if signed}
		<Field.Separator />
		<Field.Field>
			<Field.Label>Signed certificate</Field.Label>
			<CodeSnippet
				code={signed.signedCertificate}
				language="openssh"
				wrap
				download={`${ca?.id}-cert.pub`}
			/>
			<Field.Description>Expires {formatTs(signed.expiresAt, 'withTime')}</Field.Description>
		</Field.Field>
	{/if}
</FormModal>
