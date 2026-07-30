<script lang="ts">
	import { sign } from '$lib/api/certificates.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Field from '$lib/components/ui/field';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import * as Select from '$lib/components/ui/select';
	import Spinner from '$lib/components/ui/spinner/spinner.svelte';
	import { Textarea } from '$lib/components/ui/textarea';
	import DurationInput from '$lib/components/utils/DurationInput.svelte';
	import {
		AuthorityType,
		SignSSHCertificateRequest_CertificateType,
		SignSSHCertificateRequestSchema,
		SignX509CertificateRequest_X509Usage,
		SignX509CertificateRequestSchema,
		type CertificateAuthority
	} from '$lib/gen/nokku/v1/certificates_pb';
	import { formatTs } from '$lib/utils';
	import { create } from '@bufbuild/protobuf';
	import { CircleAlert, IdCard, KeyRound, Server, Shield, User } from '@lucide/svelte';

	interface Props {
		open?: boolean;
		ca?: CertificateAuthority;
	}
	let { open = $bindable(false), ca }: Props = $props();

	let sshPayload = $state(create(SignSSHCertificateRequestSchema));
	let x509Payload = $state(create(SignX509CertificateRequestSchema));

	let sshCertType = $state<SignSSHCertificateRequest_CertificateType>(
		SignSSHCertificateRequest_CertificateType.USER
	);
	let x509Usage = $state<SignX509CertificateRequest_X509Usage>(
		SignX509CertificateRequest_X509Usage.CLIENT_AUTH
	);

	const signUser = sign.user();
	const signHost = sign.host();
	const signX509 = sign.x509();

	let isSSH = $derived(ca?.authorityType === AuthorityType.SSH);

	let isPending = $derived(signUser.isPending || signHost.isPending || signX509.isPending);
	let isError = $derived(signUser.isError || signHost.isError || signX509.isError);
	let isSuccess = $derived(signUser.isSuccess || signHost.isSuccess || signX509.isSuccess);
	let errorMessage = $derived(
		signUser.error?.message || signHost.error?.message || signX509.error?.message
	);

	$effect(() => {
		if (ca?.id) {
			sshPayload.caId = ca.id;
			x509Payload.caId = ca.id;
		}
	});

	function resetModal() {
		sshPayload = create(SignSSHCertificateRequestSchema);
		x509Payload = create(SignX509CertificateRequestSchema);
		sshCertType = SignSSHCertificateRequest_CertificateType.USER;
		x509Usage = SignX509CertificateRequest_X509Usage.CLIENT_AUTH;
		signUser.reset?.();
		signHost.reset?.();
		signX509.reset?.();
	}

	$effect(() => {
		if (!open) resetModal();
	});

	function handleSubmit() {
		if (isSSH) {
			sshPayload.caId = ca?.id || '';
			if (sshCertType === SignSSHCertificateRequest_CertificateType.HOST) {
				signHost.mutate(sshPayload);
			} else {
				signUser.mutate(sshPayload);
			}
		} else {
			x509Payload.caId = ca?.id || '';
			x509Payload.usage = x509Usage;
			signX509.mutate(x509Payload);
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] overflow-x-hidden overflow-y-auto sm:max-w-xl">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				{#if isSSH}
					<KeyRound size={20} />
				{:else}
					<Shield size={20} />
				{/if}
				Sign {isSSH ? 'SSH' : 'X.509'} Certificate
			</Dialog.Title>
			<Dialog.Description>
				{#if isSSH}
					Paste your public key to receive a signed SSH certificate.
				{:else}
					Paste a PKCS#10 CSR to receive a signed X.509 certificate.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4">
			{#if isSSH}
				<Field.Field>
					<Field.Label for="ssh-cert-type">Certificate Type</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={sshCertType.toString()}
							onValueChange={(v) =>
								(sshCertType = parseInt(v) as SignSSHCertificateRequest_CertificateType)}
						>
							<Select.Trigger class="w-full">
								<div class="flex items-center gap-2">
									{#if sshCertType === SignSSHCertificateRequest_CertificateType.USER}
										<User size={14} />
										User Certificate
									{:else}
										<Server size={14} />
										Host Certificate
									{/if}
								</div>
							</Select.Trigger>
							<Select.Content>
								<Select.Item value={SignSSHCertificateRequest_CertificateType.USER.toString()}>
									<div class="flex items-center gap-2">
										<User size={14} />
										User Certificate
									</div>
								</Select.Item>
								<Select.Item value={SignSSHCertificateRequest_CertificateType.HOST.toString()}>
									<div class="flex items-center gap-2">
										<Server size={14} />
										Host Certificate
									</div>
								</Select.Item>
							</Select.Content>
						</Select.Root>
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="public-key">
						Public Key <span class="text-destructive">*</span>
					</Field.Label>
					<Field.Content>
						<Textarea
							id="public-key"
							bind:value={sshPayload.publicKey}
							placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbG... user@example.com"
							class="min-h-20 overflow-x-hidden font-mono text-xs break-all whitespace-pre-wrap"
							onkeydown={(e) => {
								if (e.key === 'Enter') {
									e.preventDefault();
									handleSubmit();
								}
							}}
							disabled={isPending}
						/>
					</Field.Content>
				</Field.Field>
			{:else}
				<Field.Field>
					<Field.Label for="x509-usage">Certificate Usage</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={x509Usage.toString()}
							onValueChange={(v) =>
								(x509Usage = parseInt(v) as SignX509CertificateRequest_X509Usage)}
						>
							<Select.Trigger class="w-full">
								{#if x509Usage === SignX509CertificateRequest_X509Usage.CLIENT_AUTH}
									Client Authentication
								{:else if x509Usage === SignX509CertificateRequest_X509Usage.SERVER_AUTH}
									Server Authentication
								{:else}
									Client & Server Authentication
								{/if}
							</Select.Trigger>
							<Select.Content>
								<Select.Item value={SignX509CertificateRequest_X509Usage.CLIENT_AUTH.toString()}>
									<div class="flex items-center gap-2">
										<User size={14} />
										Client Authentication
									</div>
								</Select.Item>
								<Select.Item value={SignX509CertificateRequest_X509Usage.SERVER_AUTH.toString()}>
									<div class="flex items-center gap-2">
										<Server size={14} />
										Server Authentication
									</div>
								</Select.Item>
								<Select.Item
									value={SignX509CertificateRequest_X509Usage.CLIENT_AND_SERVER.toString()}
								>
									<div class="flex items-center gap-2">
										<Shield size={14} />
										Client &amp; Server Authentication
									</div>
								</Select.Item>
							</Select.Content>
						</Select.Root>
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="csr">
						CSR (PKCS#10 PEM) <span class="text-destructive">*</span>
					</Field.Label>
					<Field.Content>
						<Textarea
							id="csr"
							bind:value={x509Payload.csr}
							placeholder="-----BEGIN CERTIFICATE REQUEST-----"
							class="min-h-20 overflow-x-hidden font-mono text-xs break-all whitespace-pre-wrap"
							onkeydown={(e) => {
								if (e.key === 'Enter') {
									e.preventDefault();
									handleSubmit();
								}
							}}
							disabled={isPending}
						/>
					</Field.Content>
				</Field.Field>
			{/if}

			<Field.Field>
				<Field.Label for="expiry">Certificate Lifetime (optional)</Field.Label>
				<Field.Content>
					{#if isSSH}
						<DurationInput bind:value={sshPayload.ttl} />
					{:else}
						<DurationInput bind:value={x509Payload.ttl} />
					{/if}
					<Field.Description>Leave empty to use the default lifetime</Field.Description>
				</Field.Content>
			</Field.Field>

			{#if isError}
				<Alert.Root variant="destructive">
					<CircleAlert size={16} />
					<Alert.Title>Failed to sign certificate</Alert.Title>
					<Alert.Description>
						{errorMessage ||
							'An error occurred while signing. Please verify your input and try again.'}
					</Alert.Description>
				</Alert.Root>
			{/if}

			{#if isSuccess}
				<Field.Separator class="my-4" />

				<div class="space-y-4">
					{#if signX509.isSuccess}
						<div class="group relative z-10 shadow-md">
							<InputGroupVariants
								variant="code-area"
								value={signX509.data?.certificate}
								icon={{ code: IdCard }}
								codeHeader={(ca?.name || 'CA') + ' - PEM'}
								downloadFilename={`${ca?.id}-cert.pub`}
							/>
							<p class="absolute right-4 bottom-2 text-xs text-muted-foreground">
								Expires: {formatTs(signX509.data?.expiresAt, 'withTime')}
							</p>
						</div>
						{#if signX509.data?.caChain}
							<div class="group relative z-10 shadow-md">
								<InputGroupVariants
									variant="code-area"
									value={signX509.data.caChain}
									icon={{ code: Shield }}
									codeHeader="CA Chain - PEM"
									downloadFilename={`${ca?.id}-chain.pem`}
								/>
							</div>
						{/if}
					{:else if signHost.isSuccess}
						<div class="group relative z-10 shadow-md">
							<InputGroupVariants
								variant="code-area"
								value={signHost.data?.signedCertificate}
								icon={{ code: IdCard }}
								codeHeader="Signed Certificate - PEM"
								downloadFilename={`${ca?.id}-cert.pem`}
							/>
							<p class="absolute right-4 bottom-2 text-xs text-muted-foreground">
								Expires: {formatTs(signHost.data?.expiresAt, 'withTime')}
							</p>
						</div>
					{:else if signUser.isSuccess}
						<div class="group relative z-10 shadow-md">
							<InputGroupVariants
								variant="code-area"
								value={signUser.data?.signedCertificate}
								icon={{ code: IdCard }}
								codeHeader="Signed Certificate - PEM"
								downloadFilename={`${ca?.id}-cert.pem`}
							/>
							<p class="absolute right-4 bottom-2 text-xs text-muted-foreground">
								Expires: {formatTs(signUser.data?.expiresAt, 'withTime')}
							</p>
						</div>
					{/if}
				</div>
			{/if}

			<Button onclick={handleSubmit} disabled={isPending} class="w-full">
				{#if isPending}
					<Spinner />
					Signing...
				{:else}
					Sign
				{/if}
			</Button>
		</div>
	</Dialog.Content>
</Dialog.Root>
