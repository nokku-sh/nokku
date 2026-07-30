<script lang="ts">
	import * as Tabs from '$lib/components/ui/tabs';
	import { activeSSOTab } from '$lib/store.svelte';
	import { Globe, KeyRound } from '@lucide/svelte';
	import DomainTab from './DomainTab.svelte';
	import OIDCTab from './OIDCTab.svelte';
	import SAMLTab from './SAMLTab.svelte';
	import { OIDCIcon, SAMLIcon } from '$lib/assets';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
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
			<Tabs.Trigger value="saml" class="flex items-center gap-2">
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
	<Tabs.Content value="saml">
		<SAMLTab />
	</Tabs.Content>

	<Tabs.Content value="domains">
		<DomainTab />
	</Tabs.Content>
</Tabs.Root>
