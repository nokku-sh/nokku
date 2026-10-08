<script lang="ts">
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { KeyRound } from '@lucide/svelte';
	import TokenExpiryField, { TokenExpiry } from './TokenExpiryField.svelte';

	let {
		open = $bindable(false),
		serviceAccountId,
		name
	}: { open?: boolean; serviceAccountId: string; name: string } = $props();

	const create = saApi.tokens.create();
	const expiry = new TokenExpiry();

	let label = $state('');
	let secret = $state('');

	async function onSubmit() {
		const res = await create.mutateAsync({
			serviceAccountId,
			label: label.trim(),
			expiresAt: expiry.timestamp
		});
		secret = res.secret;
		label = '';
		// Stays open to show the secret.
		return false;
	}

	function close() {
		open = false;
		secret = '';
	}
</script>

<FormModal
	bind:open
	title={secret ? 'Copy the token now' : `New token for ${name}`}
	description={secret
		? 'Store it in your CI secrets. Other tokens of the account keep working.'
		: 'Roll it out first, then revoke the one it replaces.'}
	icon={KeyRound}
	submitLabel="Create and show token"
	{onSubmit}
	onOpenChange={(v) => !v && (secret = '')}
	footer={secret ? saved : undefined}
>
	{#if secret}
		<SecretReveal
			values={[{ value: secret }, { label: 'As an env var', value: `export NK_TOKEN=${secret}` }]}
		/>
	{:else}
		<Field.Field>
			<Field.Label for="new-token-label">Label</Field.Label>
			<Input id="new-token-label" bind:value={label} placeholder="github-actions" maxlength={100} />
			<Field.Description>Where the token lives, so you know which one to revoke.</Field.Description>
		</Field.Field>
		<TokenExpiryField {expiry} />
	{/if}
</FormModal>

{#snippet saved()}
	<Button onclick={close}>I saved it</Button>
{/snippet}
