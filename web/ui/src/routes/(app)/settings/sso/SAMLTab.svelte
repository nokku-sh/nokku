<script lang="ts">
	import { page } from '$app/state';
	import { sso } from '#lib/api/sso.svelte.js';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Label } from '#lib/components/ui/label/index.js';
	import { Separator } from '#lib/components/ui/separator/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { workspaceID } from '#lib/store.svelte.js';
	import { Download, Info, Save, TriangleAlert } from '@lucide/svelte';

	let change = $state({
		isActive: false,
		enforceSso: false,
		allowJitProvisioning: false,
		name: '',
		metadataUrl: ''
	});

	const provider = sso.getProvider();
	const configured = $derived(provider.data?.method === 'saml');
	const replacesOIDC = $derived(provider.data?.method === 'oidc');
	$effect(() => {
		const p = provider.data;
		if (!p) return;
		change = {
			isActive: p.isActive ?? false,
			enforceSso: p.enforceSso ?? false,
			allowJitProvisioning: p.allowJitProvisioning ?? false,
			name: p.name ?? '',
			metadataUrl: p.config?.metadataUrl ?? ''
		};
	});

	const updateProvider = sso.updateProvider();
	function handleSubmit() {
		updateProvider.mutate({
			workspaceId: workspaceID.current,
			method: 'saml',
			name: change.name,
			isActive: change.isActive,
			enforceSso: change.enforceSso,
			allowJitProvisioning: change.allowJitProvisioning,
			config: {
				metadataUrl: change.metadataUrl
			}
		});
	}

	const callbackURL = page.url.origin + '/saml/acs';
	const metadataURL = page.url.origin + '/saml/metadata';
	const certURL = '/saml/certificate';
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
				<TriangleAlert class="size-4" />
				<Alert.Title>Replaces the OIDC provider</Alert.Title>
				<Alert.Description>
					Only one SSO provider is allowed per workspace. Saving this SAML provider replaces the
					existing OIDC configuration.
				</Alert.Description>
			</Alert.Root>
		{/if}

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
					<Field.Label for="spMetadata" class="flex items-center justify-between">
						Service Provider Metadata URL
						<Button variant="outline" size="sm" onclick={() => (window.location.href = certURL)}>
							<Download size={14} />
							Download Signing Certificate (PEM)
						</Button>
					</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={metadataURL} readonly />
						<Field.Description class="flex items-center justify-between gap-2">
							<span class="flex items-center gap-1">
								<Info size={12} />
								<span>Use this value as the Client ID (entity ID) in your identity provider</span>
							</span>
						</Field.Description>
					</Field.Content>
				</Field.Field>
			</Field.Group>
		</Field.Set>
	</Card.Content>

	<Card.Footer class="flex justify-end">
		<Button onclick={handleSubmit} disabled={updateProvider.isPending} class="w-full sm:w-auto">
			{#if updateProvider.isPending}<Spinner data-icon="inline-start" />{:else}<Save
					data-icon="inline-start"
				/>{/if}
			{configured ? 'Save' : 'Add provider'}
		</Button>
	</Card.Footer>
</Card.Root>
