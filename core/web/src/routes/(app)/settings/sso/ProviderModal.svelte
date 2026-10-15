<script lang="ts">
	import { sso } from '#lib/api/sso.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import type { SSOProvider } from '#lib/gen/nokku/v1/sso_pb.js';
	import { Globe, KeyRound } from '@lucide/svelte';
	import RedirectURI from './RedirectURI.svelte';

	interface Props {
		open?: boolean;
		/** Unset adds a provider, set edits it. */
		provider?: SSOProvider;
		mode?: string;
	}

	let { open = $bindable(false), provider, mode }: Props = $props();

	const standardScopes = ['openid', 'email', 'profile'];
	const idPattern = /^[a-z0-9-]{1,64}$/;

	const put = sso.put();
	const isEdit = $derived(!!provider);

	let form = $state(blank());
	let clientSecret = $state('');

	function blank() {
		return {
			providerId: '',
			name: '',
			issuerUrl: '',
			clientId: '',
			scopes: [...standardScopes],
			enabled: true,
			// Off by default. A public issuer like Google knows every account on the internet.
			jitProvisioning: false
		};
	}

	// Reset for each open. An effect, since the parent opens this and bits-ui only reports its own changes.
	$effect(() => {
		if (!open) return;
		clientSecret = '';
		idTouched = false;
		form = provider
			? {
					providerId: provider.providerId,
					name: provider.name,
					issuerUrl: provider.issuerUrl,
					clientId: provider.clientId,
					scopes: [...provider.scopes],
					enabled: provider.enabled,
					jitProvisioning: provider.jitProvisioning
				}
			: blank();
	});

	// The id is derived from the name until the person edits it.
	function slugFromName(name: string) {
		return name
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-|-$/g, '')
			.slice(0, 64);
	}
	let idTouched = $state(false);
	function onNameInput() {
		if (!isEdit && !idTouched) form.providerId = slugFromName(form.name);
	}

	const issuerValid = $derived(
		/^https?:\/\//.test(form.issuerUrl.trim()) && URL.canParse(form.issuerUrl.trim())
	);
	const scopesValid = $derived(form.scopes.includes('openid') && form.scopes.includes('email'));
	const valid = $derived(
		idPattern.test(form.providerId) &&
			!!form.name.trim() &&
			issuerValid &&
			!!form.clientId.trim() &&
			scopesValid &&
			(isEdit || !!clientSecret.trim())
	);

	function submit() {
		return put.mutateAsync({
			...form,
			issuerUrl: form.issuerUrl.trim(),
			clientId: form.clientId.trim(),
			clientSecret: clientSecret.trim()
		});
	}
</script>

<FormModal
	bind:open
	title={isEdit ? 'Edit provider' : 'Add provider'}
	description={isEdit
		? 'Changes apply to the next sign-in through it.'
		: 'Connect an OpenID Connect provider in two steps.'}
	icon={KeyRound}
	onSubmit={submit}
	submitLabel={isEdit ? 'Save' : 'Add provider'}
	submitDisabled={!valid}
	classModal="sm:max-w-lg"
>
	{#snippet before()}
		{#if !isEdit}
			<ol class="flex flex-col gap-3 rounded-lg border bg-muted/40 p-3 text-sm">
				<li class="flex flex-col gap-2">
					<span class="flex gap-2">
						<span class="font-mono text-muted-foreground">1</span>
						<label for="modal-callback-url">
							At your provider, create an OpenID Connect web app with this redirect URI.
						</label>
					</span>
					<RedirectURI id="modal-callback-url" />
				</li>
				<li class="flex gap-2">
					<span class="font-mono text-muted-foreground">2</span>
					Paste what the provider gives you below.
				</li>
			</ol>
		{/if}
	{/snippet}

	<Field.Set>
		<Field.Legend variant="label">From your provider</Field.Legend>
		<Field.Field data-invalid={!!form.issuerUrl.trim() && !issuerValid}>
			<Field.Label for="sso-issuer">Issuer URL</Field.Label>
			<Input
				id="sso-issuer"
				bind:value={form.issuerUrl}
				placeholder="https://login.example.com"
				class="font-mono"
				aria-invalid={!!form.issuerUrl.trim() && !issuerValid}
				required
			/>
			<Field.Description>
				{#if form.issuerUrl.trim() && !issuerValid}
					Starts with https://, like https://acme.okta.com.
				{:else}
					Its discovery document lives at /.well-known/openid-configuration under it.
				{/if}
			</Field.Description>
		</Field.Field>

		<div class="grid gap-4 sm:grid-cols-2">
			<Field.Field>
				<Field.Label for="sso-client-id">Client ID</Field.Label>
				<Input id="sso-client-id" bind:value={form.clientId} class="font-mono" required />
			</Field.Field>
			<Field.Field>
				<Field.Label for="sso-client-secret">Client secret</Field.Label>
				<InputGroupVariants
					variant="password"
					bind:value={clientSecret}
					placeholder={isEdit ? 'Unchanged' : ' '}
					inputProps={{ id: 'sso-client-secret', autocomplete: 'off' }}
				/>
				{#if isEdit}
					<Field.Description>Leave empty to keep the stored one.</Field.Description>
				{/if}
			</Field.Field>
		</div>

		<Field.Field data-invalid={!scopesValid}>
			<Field.Label for="sso-scopes">Scopes</Field.Label>
			<TagsInput
				id="sso-scopes"
				bind:value={form.scopes}
				icon={Globe}
				suggestions={standardScopes}
				separator={/[\s,]+/}
				placeholder="openid, email, profile"
			/>
			<Field.Description>
				openid and email are required, profile brings the name and picture.
			</Field.Description>
		</Field.Field>
	</Field.Set>

	<Field.Separator />

	<Field.Set>
		<Field.Legend variant="label">In Nokku</Field.Legend>
		<div class="grid gap-4 sm:grid-cols-2">
			<Field.Field>
				<Field.Label for="sso-name">Name</Field.Label>
				<Input
					id="sso-name"
					bind:value={form.name}
					oninput={onNameInput}
					placeholder="Okta"
					required
				/>
				<Field.Description>The button label on the sign-in page.</Field.Description>
			</Field.Field>
			<Field.Field data-invalid={!!form.providerId && !idPattern.test(form.providerId)}>
				<Field.Label for="sso-id">Identifier</Field.Label>
				<Input
					id="sso-id"
					bind:value={form.providerId}
					oninput={() => (idTouched = true)}
					placeholder="okta"
					readonly={isEdit}
					class="font-mono"
					required
				/>
				<Field.Description
					>Lowercase letters, digits and dashes. Fixed once saved.</Field.Description
				>
			</Field.Field>
		</div>

		<Field.Field orientation="horizontal">
			<Field.Content>
				<Field.Label for="sso-enabled">Enabled</Field.Label>
				<Field.Description>Shown on the sign-in page.</Field.Description>
			</Field.Content>
			<Switch id="sso-enabled" bind:checked={form.enabled} />
		</Field.Field>
		<Field.Field orientation="horizontal">
			<Field.Content>
				<Field.Label for="sso-jit">Create accounts on first sign-in</Field.Label>
				<Field.Description>
					Anyone who can sign in to this provider gets a member account here{mode === 'saas'
						? ', and each one takes a seat'
						: ''}. Off means you invite people first.
				</Field.Description>
			</Field.Content>
			<Switch id="sso-jit" bind:checked={form.jitProvisioning} />
		</Field.Field>
	</Field.Set>
</FormModal>
