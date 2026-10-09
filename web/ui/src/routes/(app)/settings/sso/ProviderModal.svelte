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

	interface Props {
		open?: boolean;
		/** Unset adds a provider, set edits it. */
		provider?: SSOProvider;
	}

	let { open = $bindable(false), provider }: Props = $props();

	const standardScopes = ['openid', 'profile', 'email', 'groups', 'offline_access'];
	const defaultScopes = ['openid', 'profile', 'email'];

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
			scopes: defaultScopes,
			enabled: true,
			jitProvisioning: true
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

	const valid = $derived(
		/^[a-z0-9-]{1,64}$/.test(form.providerId) &&
			!!form.name.trim() &&
			!!form.clientId.trim() &&
			form.scopes.includes('openid') &&
			(isEdit || !!clientSecret.trim())
	);

	function submit() {
		return put.mutateAsync({ ...form, clientSecret: clientSecret.trim() });
	}
</script>

<FormModal
	bind:open
	title={isEdit ? 'Edit provider' : 'Add provider'}
	description="An OpenID Connect provider. The redirect URI is on the previous page."
	icon={KeyRound}
	onSubmit={submit}
	submitLabel={isEdit ? 'Save' : 'Add provider'}
	submitDisabled={!valid}
	classModal="sm:max-w-lg"
>
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
		<Field.Field data-invalid={!!form.providerId && !/^[a-z0-9-]{1,64}$/.test(form.providerId)}>
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
			<Field.Description>Lowercase letters, digits and dashes. Fixed once saved.</Field.Description>
		</Field.Field>
	</div>

	<Field.Field>
		<Field.Label for="sso-issuer">Issuer URL</Field.Label>
		<Input
			id="sso-issuer"
			bind:value={form.issuerUrl}
			placeholder="https://login.example.com"
			class="font-mono"
			required
		/>
		<Field.Description>
			The provider's discovery document lives at /.well-known/openid-configuration under it.
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
				placeholder={isEdit ? 'Unchanged' : ''}
				inputProps={{ id: 'sso-client-secret', autocomplete: 'off' }}
			/>
			{#if isEdit}
				<Field.Description>Leave empty to keep the stored one.</Field.Description>
			{/if}
		</Field.Field>
	</div>

	<Field.Field>
		<Field.Label for="sso-scopes">Scopes</Field.Label>
		<TagsInput
			id="sso-scopes"
			bind:value={form.scopes}
			icon={Globe}
			suggestions={standardScopes}
			separator={/[\s,]+/}
			placeholder="openid, profile, email"
		/>
		<Field.Description
			>openid and email are required, profile brings the name and picture.</Field.Description
		>
	</Field.Field>

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
				Someone the provider knows but Nokku does not gets a member account. Off means invite first.
			</Field.Description>
		</Field.Content>
		<Switch id="sso-jit" bind:checked={form.jitProvisioning} />
	</Field.Field>
</FormModal>
