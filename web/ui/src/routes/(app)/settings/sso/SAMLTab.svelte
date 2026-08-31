<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';
	import { Save, Info, Download, TriangleAlert } from '@lucide/svelte';
	import { Switch } from '$lib/components/ui/switch';
	import Separator from '$lib/components/ui/separator/separator.svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import { sso } from '$lib/api/sso.svelte';
	import type { SAMLProvider } from '$lib/gen/nokku/v1/sso_pb';
	import * as Alert from '$lib/components/ui/alert';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';

	let change = $state({
		isActive: false,
		enforceSso: false,
		allowJitProvisioning: false
	} as SAMLProvider);

	const provider = $derived(sso.getSAML());
	// A provider is configured once its payload fields are set; the API
	// reports an unconfigured one as an empty provider instead of 404.
	const configured = $derived(!!provider.data?.metadataUrl);
	// Providers share a single slot per workspace: saving here replaces an
	// existing OIDC configuration.
	const oidcProvider = $derived(sso.getOIDC());
	const replacesOIDC = $derived(!!oidcProvider.data?.issuerUrl);
	$effect(() => {
		if (provider.data) change = { ...provider.data };
	});

	const updateProvider = sso.updateSAML();
	function handleSubmit() {
		updateProvider.mutate({ ...change });
	}
	const callbackURL = window.location.origin + '/saml/acs';
	const metadataURL = $derived(
		window.location.origin + '/saml/metadata/' + provider.data?.workspaceId
	);
	const certURL = $derived('/saml/certificate/' + provider.data?.workspaceId);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>SAML 2.0 Configuration</Card.Title>
		<Card.Description>
			Configure your SAML identity provider to enable single sign-on.
		</Card.Description>
	</Card.Header>

	<Card.Content class="space-y-8">
		{#if replacesOIDC}
			<Alert.Root>
				<TriangleAlert class="h-4 w-4" />
				<Alert.Title>Replaces the OIDC provider</Alert.Title>
				<Alert.Description>
					Only one SSO provider is allowed per workspace. Saving this SAML provider replaces the
					existing OIDC configuration.
				</Alert.Description>
			</Alert.Root>
		{/if}

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

			<Field.Group>
				<Field.Field>
					<Field.Label for="acsUrl">Assertion Consumer Service (ACS) URL</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={callbackURL} readonly />
						<Field.Description class="flex items-center gap-1">
							<Info size={12} />
							<span>
								The endpoint that receives SAML assertions from your IdP. Use this as the redirect
								URI.
							</span>
						</Field.Description>
					</Field.Content>
				</Field.Field>

				<Field.Field>
					<Field.Label for="spMetadata">Service Provider Metadata URL</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={metadataURL} readonly />
						<Field.Description class="flex items-center justify-between gap-2">
							<span class="flex items-center gap-1">
								<Info size={12} />
								<span>Use this value as the Client ID (entity ID) in your identity provider</span>
							</span>
							<Button variant="outline" size="sm" onclick={() => (window.location.href = certURL)}>
								<Download size={14} />
								Download Signing Certificate (PEM)
							</Button>
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
			{configured ? 'Save' : 'Add Provider'}
		</Button>
	</Card.Footer>
</Card.Root>
