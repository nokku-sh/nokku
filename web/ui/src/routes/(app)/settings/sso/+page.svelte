<script lang="ts">
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { billing } from '#lib/api/billing.svelte.js';
	import { activeSSOTab } from '#lib/store.svelte.js';
	import { domain } from '#lib/api/sso.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { Crown, Globe, UsersRound } from '@lucide/svelte';
	import DomainTab from './DomainTab.svelte';
	import OIDCTab from './OIDCTab.svelte';
	import SCIMTab from './SCIMTab.svelte';
	import SAMLTab from './SAMLTab.svelte';
	import { OIDCIcon, SAMLIcon } from '#lib/assets/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { UpgradeURL } from '#lib/config.js';

	// Unknown until the workspace loads, so the buttons don't flicker.
	const ws = workspace.get();
	const readonly = $derived(ws.data !== undefined && ws.data.role !== 'owner');

	const billingData = billing.get();
	const samlAvailable = $derived(billingData.data?.features?.['saml'] === true);
	const scimAvailable = $derived(billingData.data?.features?.['scim'] === true);

	const domains = domain.list();
	const hasVerifiedDomain = $derived(
		(domains.data ?? []).some((d) => d.verifiedAt !== undefined && d.verifiedAt !== null)
	);

	$effect(() => {
		if (!samlAvailable && activeSSOTab.current === 'saml') {
			activeSSOTab.current = 'oidc';
		}
	});
	// Setup starts on the Domains tab.
	$effect(() => {
		if (domains.isSuccess && !hasVerifiedDomain && activeSSOTab.current !== 'domains') {
			activeSSOTab.current = 'domains';
		}
	});
</script>

{#snippet needsDomain()}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon">
				<Globe />
			</Empty.Media>
			<Empty.Title>No verified domain</Empty.Title>
			<Empty.Description>
				Add and verify a domain first. SSO only matches users whose email domain is verified for
				this workspace, and SCIM provisioning requires the same proof of ownership.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button onclick={() => (activeSSOTab.current = 'domains')}>Go to domains</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

{#snippet needsUpgrade()}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon">
				<UsersRound />
			</Empty.Media>
			<Empty.Title>Available on Enterprise</Empty.Title>
			<Empty.Description>
				SCIM provisioning syncs users and groups from your identity provider automatically. Upgrade
				to Enterprise to connect Okta, Azure AD, and other SCIM directories.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button href={UpgradeURL} target="_blank" rel="noopener">See plans</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

<PageHeader
	title="Single sign-on"
	description="Verify a domain, connect one OIDC or SAML provider, then provision people with SCIM"
/>

{#if readonly}
	<Alert.Root class="mb-4">
		<Crown class="size-4" />
		<Alert.Title>Only the owner can change this</Alert.Title>
		<Alert.Description>
			The provider vouches for every account under these domains, so the settings stay with the
			workspace owner.
		</Alert.Description>
	</Alert.Root>
{/if}

<Tabs.Root bind:value={activeSSOTab.current} class="gap-4">
	<Tabs.List>
		<Tabs.Trigger value="domains">
			<Globe />
			Domains
		</Tabs.Trigger>
		<Tabs.Trigger value="oidc" disabled={!hasVerifiedDomain}>
			<OIDCIcon />
			OIDC
		</Tabs.Trigger>
		<Tabs.Trigger value="saml" disabled={!samlAvailable || !hasVerifiedDomain}>
			<SAMLIcon />
			SAML
		</Tabs.Trigger>
		<Tabs.Trigger value="scim">
			<UsersRound />
			SCIM
		</Tabs.Trigger>
	</Tabs.List>

	<Tabs.Content value="domains">
		<DomainTab {readonly} />
	</Tabs.Content>
	<Tabs.Content value="oidc">
		{#if hasVerifiedDomain}
			<OIDCTab {readonly} />
		{:else}
			{@render needsDomain()}
		{/if}
	</Tabs.Content>
	{#if samlAvailable}
		<Tabs.Content value="saml">
			{#if hasVerifiedDomain}
				<SAMLTab {readonly} />
			{:else}
				{@render needsDomain()}
			{/if}
		</Tabs.Content>
	{/if}
	<Tabs.Content value="scim">
		{#if !scimAvailable}
			{@render needsUpgrade()}
		{:else if !hasVerifiedDomain}
			{@render needsDomain()}
		{:else}
			<SCIMTab {readonly} />
		{/if}
	</Tabs.Content>
</Tabs.Root>
