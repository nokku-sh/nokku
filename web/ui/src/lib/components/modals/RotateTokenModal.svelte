<script lang="ts">
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { RefreshCw } from '@lucide/svelte';
	import TokenExpiryField, { TokenExpiry } from './TokenExpiryField.svelte';

	let {
		open = $bindable(false),
		id,
		name
	}: { open?: boolean; id: string; name: string } = $props();

	const rotate = saApi.rotate();
	const expiry = new TokenExpiry();

	let token = $state('');

	async function onSubmit() {
		const res = await rotate.mutateAsync({ id, tokenExpiresAt: expiry.timestamp });
		token = res.token;
		// Stays open to show the token.
		return false;
	}

	function close() {
		open = false;
		token = '';
	}
</script>

<FormModal
	bind:open
	title={token ? 'Copy the new token now' : `Rotate the token of ${name}`}
	description={token
		? 'Replace it in your CI secrets.'
		: 'The current token stops working right away. Grants stay as they are.'}
	icon={RefreshCw}
	submitLabel="Rotate and show token"
	{onSubmit}
	onOpenChange={(v) => !v && (token = '')}
	footer={token ? saved : undefined}
>
	{#if token}
		<SecretReveal
			values={[{ value: token }, { label: 'As an env var', value: `export NK_TOKEN=${token}` }]}
			note="Copy it now, it is only shown once. The old token no longer works."
		/>
	{:else}
		<TokenExpiryField {expiry} />
	{/if}
</FormModal>

{#snippet saved()}
	<Button onclick={close}>I saved it</Button>
{/snippet}
