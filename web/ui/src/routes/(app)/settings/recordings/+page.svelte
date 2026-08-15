<script lang="ts">
	import { billing } from '$lib/api/billing.svelte';
	import { recordings } from '$lib/api/recordings.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { parseBillingCapabilities } from '$lib/billing-capabilities';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import { Label } from '$lib/components/ui/label';
	import * as Alert from '$lib/components/ui/alert';
	import { Progress } from '$lib/components/ui/progress';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import {
		clearPrivateKey,
		getPrivateKey,
		formatBytes,
		generateKeyPair,
		privateKeyMatches,
		setPrivateKey,
		bytesToBase64
	} from '$lib/crypto/recordings';
	import { toDate } from '$lib/utils';
	import { Download, KeyRound, Lock, RefreshCw, Database } from '@lucide/svelte';

	const ws = $derived(workspace.get());
	const list = $derived(recordings.list());
	const billingData = $derived(billing.get());
	const capabilities = $derived(parseBillingCapabilities(billingData.data?.metadata));

	const settings = $derived(ws.data?.settings);
	const recordingQuota = $derived(capabilities.limit('recordings_storage'));
	const totalBytes = $derived(list.data?.totalBytes ?? 0);
	const hasQuota = $derived(recordingQuota !== undefined && recordingQuota.hard > 0);

	const setKey = recordings.setRecordingKey();
	const clearKey = recordings.clearRecordingKey();

	let keyDialogOpen = $state(false);
	let keyPair = $state<ReturnType<typeof generateKeyPair> | null>(null);
	let privateKeyB64 = $derived(keyPair ? bytesToBase64(keyPair.secretKey) : '');
	let disableKeyOpen = $state(false);
	let saveError = $state('');

	// Whether the private key stored in this browser matches the workspace
	// key: a stale key from an older key generation is a common trap.
	let keyState = $state<'none' | 'mismatch' | 'match'>('none');
	$effect(() => {
		const fp = settings?.recordingKeyFingerprint ?? '';
		if (!fp || !getPrivateKey()) {
			keyState = 'none';
			return;
		}
		let cancelled = false;
		void privateKeyMatches(fp).then((matches) => {
			if (!cancelled) keyState = matches ? 'match' : 'mismatch';
		});
		return () => {
			cancelled = true;
		};
	});

	function openKeyDialog() {
		keyPair = generateKeyPair();
		saveError = '';
		keyDialogOpen = true;
	}

	async function enableEncryption() {
		if (!keyPair) return;
		// The local key is only saved once the server confirmed the new
		// public key: otherwise a failed call would leave a local key that
		// matches nothing.
		const pubB64 = bytesToBase64(keyPair.publicKey);
		setKey.mutate(
			{ workspaceId: ws.data?.id, publicKey: pubB64 },
			{
				onSuccess: () => {
					setPrivateKey(keyPair!.secretKey);
					keyDialogOpen = false;
				},
				onError: () => {
					saveError = 'Saving the key failed. Try again.';
				}
			}
		);
	}

	function disableEncryption() {
		clearKey.mutate({ workspaceId: ws.data?.id }, { onSuccess: () => clearPrivateKey() });
	}

	function downloadKey() {
		const blob = new Blob([privateKeyB64], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download = `nokku-recording-key.txt`;
		link.click();
		URL.revokeObjectURL(url);
	}
</script>

<PageHeader
	icon={KeyRound}
	title="Session Recordings"
	description="Every recording is sealed on the daemon with the workspace key and never stored in plaintext. Until a key is set, daemons keep recordings locally and upload nothing."
/>

<!-- Storage usage -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Database size={18} />
			Storage Usage
		</Card.Title>
	</Card.Header>
	<Card.Content class="space-y-3">
		{#if hasQuota}
			<div class="flex items-baseline justify-between">
				<span class="text-sm text-muted-foreground">
					{formatBytes(Number(totalBytes))} of {formatBytes(recordingQuota!.hard)} used
				</span>
				<span class="text-sm font-medium">
					{Math.min(100, Math.round((Number(totalBytes) / recordingQuota!.hard) * 100))}%
				</span>
			</div>
			<Progress value={Math.min(100, (Number(totalBytes) / recordingQuota!.hard) * 100)} />
			{#if Number(totalBytes) >= recordingQuota!.hard}
				<Alert.Root variant="destructive">
					<Alert.Description>
						Storage limit reached. The oldest recordings are deleted automatically to keep new
						recordings flowing. Delete recordings or upgrade your plan to keep them longer.
					</Alert.Description>
				</Alert.Root>
			{/if}
		{:else}
			<p class="text-sm text-muted-foreground">
				{formatBytes(Number(totalBytes))} stored
				{#if recordingQuota === undefined}
					— unlimited on your plan
				{/if}
			</p>
		{/if}
		<p class="text-xs text-muted-foreground">
			Recordings are uploaded by your daemons and stored in this instance's storage.
		</p>
	</Card.Content>
</Card.Root>

<!-- Encryption -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Lock size={18} />
			Encryption
		</Card.Title>
		<Card.Description>
			Every session recording is sealed on the daemon with a key only you control. Nokku stores
			ciphertext and can never read the content, no one can recover recordings without the key.
		</Card.Description>
	</Card.Header>
	<Card.Content class="space-y-4">
		{#if !settings?.recordingPublicKey}
			<div class="flex items-center justify-between rounded-lg border p-4">
				<div class="space-y-1">
					<div class="text-sm font-medium">No recording key set</div>
					<div class="text-sm text-muted-foreground">
						Daemons keep recordings on the host and upload nothing until a key is set.
					</div>
				</div>
				<Button onclick={openKeyDialog}>
					<KeyRound size={16} />
					Create key
				</Button>
			</div>
		{:else}
			<div class="flex items-center justify-between rounded-lg border p-4">
				<div class="space-y-1">
					<div class="flex items-center gap-2 text-sm font-medium">
						Recording encryption is on
						<Badge variant="default">Active</Badge>
					</div>
					<div class="text-xs text-muted-foreground">
						Key fingerprint: <code class="font-mono">{settings.recordingKeyFingerprint}</code>
						{#if settings.recordingKeyCreatedAt}
							· created {toDate(settings.recordingKeyCreatedAt)}
						{/if}
					</div>
					{#if keyState !== 'match'}
						<Alert.Root variant="destructive" class="mt-2">
							<Alert.Description>
								{#if keyState === 'none'}
									No private key found in this browser. When you open a recording, paste your key to
									decrypt it locally.
								{:else}
									The private key in this browser does not match the workspace key ({settings.recordingKeyFingerprint}).
									When you open a recording, paste the correct key to decrypt it.
								{/if}
							</Alert.Description>
						</Alert.Root>
					{/if}
				</div>
				<div class="flex gap-2">
					<Button variant="outline" onclick={openKeyDialog}>
						<RefreshCw size={16} />
						Regenerate
					</Button>
					<Button variant="destructive" onclick={() => (disableKeyOpen = true)}>Disable</Button>
				</div>
			</div>
		{/if}

		{#if settings?.recordingPublicKey}
			<Alert.Root>
				<Alert.Description>
					Regenerating the key or disabling encryption permanently deletes all stored recordings:
					without the old private key they are unrecoverable.
				</Alert.Description>
			</Alert.Root>
		{/if}
	</Card.Content>
</Card.Root>

<!-- Key creation dialog -->
<Dialog.Root bind:open={keyDialogOpen}>
	<Dialog.Content class="sm:min-w-100">
		<Dialog.Header>
			<Dialog.Title>
				{settings?.recordingPublicKey ? 'Regenerate recording key' : 'Create recording key'}
			</Dialog.Title>
			<Dialog.Description>
				This key seals every future session recording. Only the private key can decrypt them so keep
				it safe!
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4">
			{#if settings?.recordingPublicKey}
				<Alert.Root variant="destructive">
					<Alert.Description>
						All existing recordings will be permanently deleted when you save the new key.
					</Alert.Description>
				</Alert.Root>
			{/if}

			<div class="space-y-2">
				<Label>Private key (shown once)</Label>
				<div class="flex items-center gap-2">
					<code
						class="flex-1 rounded-md border bg-muted p-2 font-mono text-xs break-all select-all"
					>
						{privateKeyB64}
					</code>
					<CopyButton text={privateKeyB64} />
				</div>
				<Button variant="outline" onclick={downloadKey} title="Download key" class="w-full">
					<Download size={16} />
					Download
				</Button>
				<p class="text-xs text-muted-foreground">
					Copy or download this key and store it in your password manager. If you lose it,
					recordings encrypted with it are
					<span class="text-destructive"> permanently unrecoverable. </span>
				</p>
			</div>
			{#if saveError}
				<p class="text-xs text-destructive">{saveError}</p>
			{/if}
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (keyDialogOpen = false)}>Cancel</Button>
			<Button onclick={enableEncryption}>Use Key</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>

<DeleteConfirmationModal
	bind:open={disableKeyOpen}
	title="Disable recording encryption"
	description="This permanently deletes the workspace encryption key and all stored recordings. Without the old private key the recordings are unrecoverable, and daemons will keep future recordings local until a new key is set. This action cannot be undone."
	itemName="disable"
	requireConfirmation={true}
	submitText="Disable encryption"
	onConfirm={disableEncryption}
/>
