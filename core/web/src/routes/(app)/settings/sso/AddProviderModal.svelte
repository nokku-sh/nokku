<script lang="ts">
	import { sso, testHref } from '#lib/api/sso.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { KeyRound } from '@lucide/svelte';
	import RedirectURI from './RedirectURI.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const idPattern = /^[a-z0-9-]{1,64}$/;
	// The button label most people would pick anyway, from the issuer's host.
	const knownHosts: [RegExp, string][] = [
		[/(^|\.)okta(preview)?\.com$/, 'Okta'],
		[/^login\.microsoftonline\.com$/, 'Entra ID'],
		[/^accounts\.google\.com$/, 'Google'],
		[/(^|\.)auth0\.com$/, 'Auth0'],
		[/(^|\.)onelogin\.com$/, 'OneLogin'],
		[/(^|\.)jumpcloud\.com$/, 'JumpCloud']
	];

	const put = sso.put();

	let issuerUrl = $state('');
	let clientId = $state('');
	let clientSecret = $state('');
	let typedName = $state<string>();
	let typedId = $state<string>();
	let editId = $state(false);

	const issuer = $derived(issuerUrl.trim());
	const issuerValid = $derived(/^https?:\/\//.test(issuer) && URL.canParse(issuer));
	const issuerInvalid = $derived(!!issuer && !issuerValid);

	const guessedName = $derived.by(() => {
		if (!issuerValid) return '';
		const host = new URL(issuer).hostname;
		const known = knownHosts.find(([re]) => re.test(host))?.[1];
		if (known) return known;
		const label = host.split('.')[0];
		return label.charAt(0).toUpperCase() + label.slice(1);
	});
	const name = $derived(typedName ?? guessedName);
	const providerId = $derived(
		typedId ??
			name
				.toLowerCase()
				.replace(/[^a-z0-9]+/g, '-')
				.replace(/^-|-$/g, '')
				.slice(0, 64)
	);

	const valid = $derived(
		issuerValid &&
			!!clientId.trim() &&
			!!clientSecret.trim() &&
			!!name.trim() &&
			idPattern.test(providerId)
	);

	function reset() {
		issuerUrl = clientId = clientSecret = '';
		typedName = typedId = undefined;
		editId = false;
	}

	// Saved off, so nobody sees it on the sign-in page before the test passes. The test offers to turn it on.
	async function submit() {
		await put.mutateAsync({
			providerId,
			name: name.trim(),
			issuerUrl: issuer,
			clientId: clientId.trim(),
			clientSecret: clientSecret.trim(),
			scopes: ['openid', 'email', 'profile'],
			enabled: false,
			jitProvisioning: false
		});
		location.assign(testHref(providerId));
		return false;
	}
</script>

<FormModal
	bind:open
	title="Add provider"
	description="Create an OpenID Connect web app at your provider, then paste what it gives you."
	icon={KeyRound}
	onOpenChange={(v) => !v && reset()}
	onSubmit={submit}
	submitLabel="Add and test"
	submitDisabled={!valid}
	classModal="sm:max-w-lg"
>
	<RedirectURI id="new-provider-redirect" />

	<Field.Field data-invalid={issuerInvalid}>
		<Field.Label for="new-provider-issuer">Issuer URL</Field.Label>
		<Input
			id="new-provider-issuer"
			bind:value={issuerUrl}
			placeholder="https://acme.okta.com"
			class="font-mono"
			aria-invalid={issuerInvalid}
			aria-describedby={issuerInvalid ? 'new-provider-issuer-error' : undefined}
			required
		/>
		{#if issuerInvalid}
			<Field.Error id="new-provider-issuer-error">Starts with https://</Field.Error>
		{/if}
	</Field.Field>

	<div class="grid gap-4 sm:grid-cols-2">
		<Field.Field>
			<Field.Label for="new-provider-client-id">Client ID</Field.Label>
			<Input id="new-provider-client-id" bind:value={clientId} class="font-mono" required />
		</Field.Field>
		<Field.Field>
			<Field.Label for="new-provider-secret">Client secret</Field.Label>
			<InputGroupVariants
				variant="password"
				bind:value={clientSecret}
				placeholder=" "
				inputProps={{ id: 'new-provider-secret', autocomplete: 'off' }}
			/>
		</Field.Field>
	</div>

	<Field.Field>
		<Field.Label for="new-provider-name">Name on the sign-in button</Field.Label>
		<Input
			id="new-provider-name"
			value={name}
			oninput={(e) => (typedName = e.currentTarget.value)}
			placeholder="Okta"
			required
		/>
		{#if editId}
			<Input
				aria-label="Identifier"
				value={providerId}
				oninput={(e) => (typedId = e.currentTarget.value)}
				class="font-mono"
				aria-invalid={!idPattern.test(providerId)}
			/>
			<Field.Description>Lowercase letters, digits and dashes. Fixed once saved.</Field.Description>
		{:else if providerId}
			<Field.Description class="flex items-center gap-1">
				ID <span class="font-mono text-foreground">{providerId}</span>
				<Button variant="link" size="sm" class="h-auto p-0" onclick={() => (editId = true)}>
					Change
				</Button>
			</Field.Description>
		{/if}
	</Field.Field>
</FormModal>
