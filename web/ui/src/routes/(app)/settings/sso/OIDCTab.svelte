<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';
	import { Globe, Save, Info, TriangleAlert } from '@lucide/svelte';
	import { Switch } from '$lib/components/ui/switch';
	import Separator from '$lib/components/ui/separator/separator.svelte';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as Alert from '$lib/components/ui/alert';
	import { sso } from '$lib/api/sso.svelte';
	import { workspaceID } from '$lib/store.svelte';
	import { page } from '$app/state';

	let change = $state({
		isActive: false,
		enforceSso: false,
		allowJitProvisioning: false,
		name: '',
		issuerUrl: '',
		clientId: '',
		scopes: [] as string[]
	});
	let clientSecret = $state('');

	const provider = $derived(sso.getProvider());
	const configured = $derived(provider.data?.method === 'oidc');
	const replacesSAML = $derived(provider.data?.method === 'saml');
	$effect(() => {
		const p = provider.data;
		if (!p) return;
		change = {
			isActive: p.isActive ?? false,
			enforceSso: p.enforceSso ?? false,
			allowJitProvisioning: p.allowJitProvisioning ?? false,
			name: p.name ?? '',
			issuerUrl: p.config?.issuerUrl ?? '',
			clientId: p.config?.clientId ?? '',
			scopes: p.config?.scopes ? [...p.config.scopes] : []
		};
	});

	const updateProvider = sso.updateProvider();
	function handleSubmit() {
		clientSecret = clientSecret.trim();
		updateProvider.mutate({
			workspaceId: workspaceID.current,
			method: 'oidc',
			name: change.name,
			isActive: change.isActive,
			enforceSso: change.enforceSso,
			allowJitProvisioning: change.allowJitProvisioning,
			clientSecret: clientSecret,
			config: {
				issuerUrl: change.issuerUrl,
				clientId: change.clientId,
				scopes: change.scopes
			}
		});
	}

	const callbackURL = page.url.origin + '/oidc/callback';
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>OpenID Connect Configuration</Card.Title>
		<Card.Description>
			Configure your OpenID Connect (OIDC) identity provider to enable single sign-on for your
			users.
		</Card.Description>
	</Card.Header>

	<Card.Content class="space-y-8">
		{#if replacesSAML}
			<Alert.Root>
				<TriangleAlert class="h-4 w-4" />
				<Alert.Title>Replaces the SAML provider</Alert.Title>
				<Alert.Description>
					Only one SSO provider is allowed per workspace. Saving this OIDC provider replaces the
					existing SAML configuration.
				</Alert.Description>
			</Alert.Root>
		{/if}

		<Field.Set>
			<Field.Legend class="sr-only">Basic Configuration</Field.Legend>
			<Field.Group>
				<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label for="name">
							Display Name <span class="text-destructive">*</span>
						</Field.Label>
						<Field.Content>
							<Input
								id="name"
								bind:value={change.name}
								placeholder="e.g., Google Workspace, Okta, Auth0"
								required
							/>
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label for="issuerUrl">
							Issuer URL <span class="text-destructive">*</span>
						</Field.Label>
						<Field.Content>
							<Input
								id="issuerUrl"
								bind:value={change.issuerUrl}
								placeholder="https://accounts.google.com"
								required
							/>
						</Field.Content>
					</Field.Field>
				</div>

				<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label for="clientId">
							Client ID <span class="text-destructive">*</span>
						</Field.Label>
						<Field.Content>
							<Input
								id="clientId"
								bind:value={change.clientId}
								placeholder="your-application-client-id"
								required
							/>
						</Field.Content>
					</Field.Field>

					<Field.Field>
						<Field.Label for="clientSecret">
							Client Secret
							<span class="text-xs font-normal text-muted-foreground">
								(optional - leave empty to keep current value)
							</span>
						</Field.Label>
						<Field.Content>
							<InputGroupVariants
								variant="password"
								placeholder="••••••••••••"
								bind:value={clientSecret}
							/>
						</Field.Content>
					</Field.Field>
				</div>

				<Field.Field>
					<Field.Label for="scopes">
						OAuth Scopes <span class="ml-1 text-destructive">*</span>
					</Field.Label>
					<Field.Content>
						<InputGroupVariants
							variant="tags"
							tags={change.scopes}
							icon={{ tags: Globe }}
							placeholder="Press Enter to add scopes"
							onTagChange={(tags) => {
								if (!change.scopes) change.scopes = [];
								change.scopes = tags;
							}}
						/>
						<Field.Description class="flex items-center gap-1">
							<Info size={12} />
							<span>
								Required scopes:
								<span class="rounded-xl bg-muted px-1.5 font-mono">openid, email</span>. Add
								<span class="rounded-xl bg-muted px-1.5 font-mono">profile</span> to retrieve user name
								and picture.
							</span>
						</Field.Description>
					</Field.Content>
				</Field.Field>
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
							Activate this OIDC provider for user authentication
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
					<Field.Label for="callbackUrl">Redirect URI / Callback URL</Field.Label>
					<Field.Content>
						<InputGroupVariants variant="copy-input" value={callbackURL} readonly />
						<Field.Description class="flex items-center gap-1">
							<Info size={12} />
							<span>Add this URL to your identity provider's list of authorized redirect URIs</span>
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
