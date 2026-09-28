<script lang="ts">
	import * as Tabs from '$lib/components/ui/tabs';
	import { billing } from '$lib/api/billing.svelte';
	import { activeSSOTab } from '$lib/store.svelte';
	import { domain } from '$lib/api/sso.svelte';
	import { Globe, KeyRound, UsersRound } from '@lucide/svelte';
	import DomainTab from './DomainTab.svelte';
	import OIDCTab from './OIDCTab.svelte';
	import SCIMTab from './SCIMTab.svelte';
	import SAMLTab from './SAMLTab.svelte';
	import { OIDCIcon, SAMLIcon } from '$lib/assets';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import { Button } from '$lib/components/ui/button';
	import { UpgradeURL } from '$lib/config';

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
			<Button onclick={() => (activeSSOTab.current = 'domains')}>Go to Domains</Button>
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
			<Button onclick={() => window.open(UpgradeURL, '_blank', 'noopener')}>See Plans</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

<PageHeader
	icon={KeyRound}
	title="Single Sign-On & Provisioning"
	description="Verify a domain, then configure an OIDC or SAML provider and SCIM provisioning. One provider per workspace."
>
	<Tabs.Root bind:value={activeSSOTab.current}>
		<Tabs.List class="flex items-center gap-2">
			<Tabs.Trigger value="oidc" class="flex items-center gap-2" disabled={!hasVerifiedDomain}>
				<OIDCIcon class="dark:invert" />
				OIDC
			</Tabs.Trigger>
			<Tabs.Trigger
				value="saml"
				class="flex items-center gap-2"
				disabled={!samlAvailable || !hasVerifiedDomain}
			>
				<SAMLIcon class="dark:invert" />
				SAML
			</Tabs.Trigger>
			<Tabs.Trigger value="scim" class="flex items-center gap-2">
				<UsersRound size={16} />
				SCIM
			</Tabs.Trigger>
			<Tabs.Trigger value="domains">
				<Globe size={16} />
				Domains
			</Tabs.Trigger>
		</Tabs.List>
	</Tabs.Root>
</PageHeader>

<Tabs.Root bind:value={activeSSOTab.current}>
	<Tabs.Content value="oidc">
		{#if hasVerifiedDomain}
			<OIDCTab />
		{:else}
			{@render needsDomain()}
		{/if}
	</Tabs.Content>
	{#if samlAvailable}
		<Tabs.Content value="saml">
			{#if hasVerifiedDomain}
				<SAMLTab />
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
			<SCIMTab />
		{/if}
	</Tabs.Content>

	<Tabs.Content value="domains">
		<DomainTab />
	</Tabs.Content>
</Tabs.Root>
