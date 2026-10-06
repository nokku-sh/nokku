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
		AuthorityType,
		SignSSHCertificateRequestSchema,
		SignX509CertificateRequest_X509Usage,
		SignX509CertificateRequestSchema,
		type CertificateAuthority
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { formatTs } from '#lib/utils.js';
	import { create } from '@bufbuild/protobuf';
	import { KeyRound, Server, Shield, User } from '@lucide/svelte';

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

	// An SSH certificate is signed for one server of this CA.
	let targetId = $state('');
	const targets = target.list(
		() => ({ caId: ca?.id }),
		() => open && isSSH
	);
	const servers = $derived(targets.data?.targets ?? []);

	function resetModal() {
		sshPayload = create(SignSSHCertificateRequestSchema);
		x509Payload = create(SignX509CertificateRequestSchema);
		x509Usage = SignX509CertificateRequest_X509Usage.CLIENT_AUTH;
		targetId = '';
		signUser.reset?.();
		signX509.reset?.();
	}

	$effect(() => {
		if (!open) resetModal();
	});

	// Stays open to show the signed certificate.
	async function handleSubmit() {
		if (isSSH) {
			sshPayload.targetId = targetId;
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
		? 'Paste a public key, get back a user certificate for your accounts on one server.'
		: 'Paste a PKCS#10 CSR, get back a certificate signed by this CA.'}
	icon={isSSH ? KeyRound : Shield}
	classModal="sm:max-w-xl"
	onSubmit={handleSubmit}
	submitLabel="Sign"
	submitDisabled={isPending || (isSSH && !targetId)}
>
	{#if isSSH}
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
		<Field.Field>
			<Field.Label>Signed certificate</Field.Label>
			<CodeSnippet
				code={signed.pem}
				language={isSSH ? 'openssh' : 'pem'}
				wrap={isSSH}
				download={`${ca?.id}-cert.pem`}
			/>
			<Field.Description>Expires {formatTs(signed.expiresAt, 'withTime')}</Field.Description>
		</Field.Field>
		{#if signed.chain}
			<Field.Field>
				<Field.Label>CA chain</Field.Label>
				<CodeSnippet code={signed.chain} language="pem" download={`${ca?.id}-chain.pem`} />
			</Field.Field>
		{/if}
	{/if}
</FormModal>
