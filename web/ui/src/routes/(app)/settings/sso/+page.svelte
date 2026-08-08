<script lang="ts">
	import * as Tabs from '$lib/components/ui/tabs';
	import { billing } from '$lib/api/billing.svelte';
	import { parseBillingCapabilities } from '$lib/billing-capabilities';
	import { activeSSOTab } from '$lib/store.svelte';
	import { Globe, KeyRound } from '@lucide/svelte';
	import DomainTab from './DomainTab.svelte';
	import OIDCTab from './OIDCTab.svelte';
	import SAMLTab from './SAMLTab.svelte';
	import { OIDCIcon, SAMLIcon } from '$lib/assets';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';

	const billingData = $derived(billing.get());
	const capabilities = $derived(parseBillingCapabilities(billingData.data?.metadata));
	const samlAvailable = $derived(capabilities.hasFeature('saml'));

	$effect(() => {
		if (!samlAvailable && activeSSOTab.current === 'saml') {
			activeSSOTab.current = 'oidc';
		}
	});
</script>

<PageHeader
	icon={KeyRound}
	title="Single Sign-On"
	description="Configure OIDC/SAML provider for SSO authentication"
>
	<Tabs.Root bind:value={activeSSOTab.current}>
		<Tabs.List class="flex items-center gap-2">
			<Tabs.Trigger value="oidc" class="flex items-center gap-2">
				<OIDCIcon class="dark:invert" />
				OIDC
			</Tabs.Trigger>
			<Tabs.Trigger value="saml" class="flex items-center gap-2" disabled={!samlAvailable}>
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
		<OIDCTab />
	</Tabs.Content>
	{#if samlAvailable}
		<Tabs.Content value="saml">
			<SAMLTab />
		</Tabs.Content>
	{/if}

	<Tabs.Content value="domains">
		<DomainTab />
	</Tabs.Content>
</Tabs.Root>
