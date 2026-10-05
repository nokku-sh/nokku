<script lang="ts">
	import { sign } from '#lib/api/certificates.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Field from '#lib/components/ui/field/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import {
		AuthorityType,
		SignSSHCertificateRequestSchema,
		SignX509CertificateRequest_X509Usage,
		SignX509CertificateRequestSchema,
		type CertificateAuthority
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { formatTs } from '#lib/utils.js';
	import { create } from '@bufbuild/protobuf';
	import { IdCard, KeyRound, Server, Shield, User } from '@lucide/svelte';

	interface Props {
		open?: boolean;
		ca?: CertificateAuthority;
	}
	let { open = $bindable(false), ca }: Props = $props();

	let sshPayload = $state(create(SignSSHCertificateRequestSchema));
	let x509Payload = $state(create(SignX509CertificateRequestSchema));

	let x509Usage = $state<SignX509CertificateRequest_X509Usage>(
		SignX509CertificateRequest_X509Usage.CLIENT_AUTH
	);

	const signUser = sign.user();
	const signX509 = sign.x509();

	let isSSH = $derived(ca?.authorityType === AuthorityType.SSH);

	let isPending = $derived(signUser.isPending || signX509.isPending);

	function resetModal() {
		sshPayload = create(SignSSHCertificateRequestSchema);
		x509Payload = create(SignX509CertificateRequestSchema);
		x509Usage = SignX509CertificateRequest_X509Usage.CLIENT_AUTH;
		signUser.reset?.();
		signX509.reset?.();
	}

	$effect(() => {
		if (!open) resetModal();
	});

	// Stays open to show the signed certificate.
	async function handleSubmit() {
		if (isSSH) {
			sshPayload.caId = ca?.id || '';
			await signUser.mutateAsync(sshPayload);
		} else {
			x509Payload.caId = ca?.id || '';
			x509Payload.usage = x509Usage;
			await signX509.mutateAsync(x509Payload);
		}
		return false;
	}

	function submitOnEnter(e: KeyboardEvent & { currentTarget: HTMLTextAreaElement }) {
		if (e.key !== 'Enter' || e.shiftKey) return;
		e.preventDefault();
		e.currentTarget.form?.requestSubmit();
	}

	const signed = $derived(
		signX509.data
			? {
					pem: signX509.data.certificate,
					chain: signX509.data.caChain,
					expiresAt: signX509.data.expiresAt
				}
			: signUser.data
				? {
						pem: signUser.data.signedCertificate,
						chain: '',
						expiresAt: signUser.data.expiresAt
					}
				: undefined
	);
</script>

<FormModal
	bind:open
	title={`Sign ${isSSH ? 'an SSH' : 'an X.509'} certificate`}
	description={isSSH
		? 'Paste a public key, get back a user certificate for your account signed by this CA.'
		: 'Paste a PKCS#10 CSR, get back a certificate signed by this CA.'}
	icon={isSSH ? KeyRound : Shield}
	classModal="sm:max-w-xl"
	onSubmit={handleSubmit}
	submitLabel="Sign"
	submitDisabled={isPending}
>
	{#if isSSH}
		<Field.Field>
			<Field.Label for="public-key">Public key</Field.Label>
			<Textarea
				id="public-key"
				bind:value={sshPayload.publicKey}
				placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... you@laptop"
				class="min-h-20 font-mono text-xs break-all"
				onkeydown={submitOnEnter}
				required
				disabled={isPending}
			/>
		</Field.Field>
	{:else}
		<Field.Field>
			<Field.Label for="x509-usage">Usage</Field.Label>
			<Select.Root
				type="single"
				value={x509Usage.toString()}
				onValueChange={(v) => (x509Usage = parseInt(v) as SignX509CertificateRequest_X509Usage)}
			>
				<Select.Trigger id="x509-usage" class="w-full">
					{#if x509Usage === SignX509CertificateRequest_X509Usage.CLIENT_AUTH}
						Client authentication
					{:else if x509Usage === SignX509CertificateRequest_X509Usage.SERVER_AUTH}
						Server authentication
					{:else}
						Client and server authentication
					{/if}
				</Select.Trigger>
				<Select.Content>
					<Select.Group>
						<Select.Item value={SignX509CertificateRequest_X509Usage.CLIENT_AUTH.toString()}>
							<User />
							Client authentication
						</Select.Item>
						<Select.Item value={SignX509CertificateRequest_X509Usage.SERVER_AUTH.toString()}>
							<Server />
							Server authentication
						</Select.Item>
						<Select.Item value={SignX509CertificateRequest_X509Usage.CLIENT_AND_SERVER.toString()}>
							<Shield />
							Client and server authentication
						</Select.Item>
					</Select.Group>
				</Select.Content>
			</Select.Root>
		</Field.Field>
		<Field.Field>
			<Field.Label for="csr">CSR (PKCS#10 PEM)</Field.Label>
			<Textarea
				id="csr"
				bind:value={x509Payload.csr}
				placeholder="-----BEGIN CERTIFICATE REQUEST-----"
				class="min-h-20 font-mono text-xs break-all"
				onkeydown={submitOnEnter}
				required
				disabled={isPending}
			/>
		</Field.Field>
	{/if}

	<Field.Field>
		<Field.Label>Lifetime</Field.Label>
		{#if isSSH}
			<DurationInput bind:value={sshPayload.ttl} />
		{:else}
			<DurationInput bind:value={x509Payload.ttl} />
		{/if}
		<Field.Description>Leave empty for the CA default.</Field.Description>
	</Field.Field>

	{#if signed}
		<Field.Separator />
		<InputGroupVariants
			variant="code-area"
			value={signed.pem}
			icon={IdCard}
			codeHeader={`Signed certificate · expires ${formatTs(signed.expiresAt, 'withTime')}`}
			downloadFilename={`${ca?.id}-cert.pem`}
		/>
		{#if signed.chain}
			<InputGroupVariants
				variant="code-area"
				value={signed.chain}
				icon={Shield}
				codeHeader="CA chain"
				downloadFilename={`${ca?.id}-chain.pem`}
			/>
		{/if}
	{/if}
</FormModal>
