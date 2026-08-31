<script lang="ts">
	import * as Tabs from '$lib/components/ui/tabs';
	import { billing } from '$lib/api/billing.svelte';
	import { parseBillingCapabilities } from '$lib/billing-capabilities';
	import { activeSSOTab } from '$lib/store.svelte';
	import { domain } from '$lib/api/sso.svelte';
	import { Globe, KeyRound } from '@lucide/svelte';
	import DomainTab from './DomainTab.svelte';
	import OIDCTab from './OIDCTab.svelte';
	import SAMLTab from './SAMLTab.svelte';
	import { OIDCIcon, SAMLIcon } from '$lib/assets';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import { Button } from '$lib/components/ui/button';

	const billingData = $derived(billing.get());
	const capabilities = $derived(parseBillingCapabilities(billingData.data?.metadata));
	const samlAvailable = $derived(capabilities.hasFeature('saml'));

	const domains = $derived(domain.list());
	// Providers can only be added once a domain is verified: home realm
	// discovery routes users by their email domain, so without one the
	// provider could never match a login.
	const hasVerifiedDomain = $derived(
		(domains.data ?? []).some((d) => d.verifiedAt !== undefined && d.verifiedAt !== null)
	);

	$effect(() => {
		if (!samlAvailable && activeSSOTab.current === 'saml') {
			activeSSOTab.current = 'oidc';
		}
	});
	// New workspaces land on the Domains tab: the setup flow starts there.
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
				this workspace.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button onclick={() => (activeSSOTab.current = 'domains')}>Go to Domains</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

<PageHeader
	icon={KeyRound}
	title="Single Sign-On"
	description="Verify a domain, then configure an OIDC or SAML provider. One provider per workspace."
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

	<Tabs.Content value="domains">
		<DomainTab />
	</Tabs.Content>
</Tabs.Root>
