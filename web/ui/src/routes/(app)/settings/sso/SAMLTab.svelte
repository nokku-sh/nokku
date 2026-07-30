<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';
	import { Save, Info } from '@lucide/svelte';
	import { Switch } from '$lib/components/ui/switch';
	import Separator from '$lib/components/ui/separator/separator.svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import { sso } from '$lib/api/sso.svelte';
	import type { SAMLProvider } from '$lib/gen/nokku/v1/sso_pb';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';

	let change = $state({
		isActive: false,
		enforceSso: false,
		allowJitProvisioning: false
	} as SAMLProvider);

	const provider = $derived(sso.getSAML());
	$effect(() => {
		if (provider.data) change = { ...provider.data };
	});

	const updateProvider = sso.updateSAML();
	function handleSubmit() {
		updateProvider.mutate({ ...change });
	}
	const callbackURL = window.location.origin + '/saml/acs';
	const metadataURL = $derived(window.location.origin + '/saml/metadata/' + provider.data?.id);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>SAML 2.0 Configuration</Card.Title>
		<Card.Description>
			Configure your SAML identity provider to enable single sign-on.
		</Card.Description>
	</Card.Header>

	<Card.Content class="space-y-8">
		<!-- Basic Configuration -->
		<Field.Set>
			<Field.Legend class="sr-only">Basic Configuration</Field.Legend>
			<Field.Group>
				<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label for="samlName">
							Display Name
							<span class="text-destructive">*</span>
						</Field.Label>
						<Field.Content>
							<Input
								id="samlName"
								bind:value={change.name}
								placeholder="e.g., Okta, Azure AD, Google SAML"
								required
							/>
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label for="idpssourl">
							Identity Provider Metadata URL
							<span class="text-destructive">*</span>
						</Field.Label>
						<Field.Content>
							<Input
								id="idpssourl"
								bind:value={change.metadataUrl}
								placeholder="https://idp.example.com/saml/metadata"
								required
							/>
						</Field.Content>
					</Field.Field>
				</div>
			</Field.Group>
		</Field.Set>

		<Separator />

		<!-- Attribute Mapping -->
		<Field.Set>
			<div class="space-y-1">
				<Field.Legend>User Attribute Mapping</Field.Legend>
				<Field.Description>
					Map SAML assertion attributes to user profile fields. Leave empty to use standard
					attribute names.
				</Field.Description>
			</div>

			<Field.Group class="grid grid-cols-1 gap-4 sm:grid-cols-2">
				<Field.Field>
					<Field.Label for="emailAttr">Email</Field.Label>
					<Field.Content>
						<Input id="emailAttr" bind:value={change.emailAttribute} placeholder="email" />
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="nameAttr">Full Name</Field.Label>
					<Field.Content>
						<Input id="nameAttr" bind:value={change.nameAttribute} placeholder="name" />
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="usernameAttr">Username</Field.Label>
					<Field.Content>
						<Input id="usernameAttr" bind:value={change.usernameAttribute} placeholder="username" />
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="picAttr">Profile Picture</Field.Label>
					<Field.Content>
						<Input id="picAttr" bind:value={change.pictureAttribute} placeholder="picture" />
					</Field.Content>
				</Field.Field>
			</Field.Group>
		</Field.Set>

		<Separator />

		<!-- Security & Access Options -->
		<Field.Set>
			<div class="space-y-1">
				<Field.Legend>Security & Access Options</Field.Legend>
				<Field.Description>Configure how users authenticate and are provisioned</Field.Description>
			</div>

			<Field.Group>
				<div
					class="flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-muted/50"
				>
					<div class="flex flex-col space-y-1">
						<Label class="text-base font-medium">Enable Provider</Label>
						<p class="text-sm text-muted-foreground">
							Activate this SAML provider for user authentication
						</p>
					</div>
					<Switch bind:checked={change.isActive} />
				</div>

				<div
					class="flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-muted/50"
				>
					<div class="flex flex-col space-y-1">
						<Label class="text-base font-medium">Enforce SSO</Label>
						<p class="text-sm text-muted-foreground">
							Require all users to authenticate through this identity provider. Disables local
							password authentication.
						</p>
					</div>
					<Switch bind:checked={change.enforceSso} />
				</div>

				<div
					class="flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-muted/50"
				>
					<div class="flex flex-col space-y-1">
						<Label class="text-base font-medium">Just-In-Time Provisioning</Label>
						<p class="text-sm text-muted-foreground">
							Automatically create new user accounts when someone logs in for the first time
						</p>
					</div>
					<Switch bind:checked={change.allowJitProvisioning} />
				</div>
			</Field.Group>
		</Field.Set>

		<Separator />

		<!-- Service Provider Information -->
		<Field.Set>
			<div class="space-y-1">
				<Field.Legend>Service Provider Information</Field.Legend>
				<Field.Description>
					Use these values when configuring this application in your identity provider
				</Field.Description>
			</div>

			<Field.Group class="grid grid-cols-1 gap-4 md:grid-cols-5">
				<Field.Field class="md:col-span-2">
					<Field.Label for="acsUrl">Assertion Consumer Service (ACS) URL</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={callbackURL} readonly />
						<Field.Description class="flex items-center gap-1">
							<Info size={12} />
							<span>The endpoint that receives SAML assertions from your IdP</span>
						</Field.Description>
					</Field.Content>
				</Field.Field>

				<Field.Field class="md:col-span-3">
					<Field.Label for="spMetadata">Service Provider Metadata URL</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={metadataURL} readonly />
						<Field.Description class="flex items-center gap-1">
							<Info size={12} />
							<span
								>Import this URL in your IdP to automatically configure the SAML integration</span
							>
						</Field.Description>
					</Field.Content>
				</Field.Field>
			</Field.Group>
		</Field.Set>
	</Card.Content>

	<Card.Footer class="flex justify-end">
		<Button
			variant="default"
			size="sm"
			onclick={handleSubmit}
			disabled={updateProvider.isPending}
			class="w-full sm:w-auto"
		>
			<Save class={updateProvider.isPending ? 'hidden' : ''} />
			<Spinner class={updateProvider.isPending ? '' : 'hidden'} />
			Save
		</Button>
	</Card.Footer>
</Card.Root>
