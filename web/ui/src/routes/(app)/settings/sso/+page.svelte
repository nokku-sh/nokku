<script lang="ts">
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { billing } from '#lib/api/billing.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { Crown, UsersRound } from '@lucide/svelte';
	import ProvidersTab from './ProvidersTab.svelte';
	import SCIMTab from './SCIMTab.svelte';
	import { OIDCIcon } from '#lib/assets/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { UpgradeURL } from '#lib/config.js';

	// Unknown until the account loads, so the buttons don't flicker.
	const me = user.self();
	const readonly = $derived(me.data !== undefined && me.data.role !== 'owner');

	const billingData = billing.get();
	const scimAvailable = $derived(billingData.data?.features?.['scim'] === true);

	let tab = $state('providers');
</script>

{#snippet needsUpgrade()}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon">
				<UsersRound />
			</Empty.Media>
			<Empty.Title>Available on Enterprise</Empty.Title>
			<Empty.Description>
				SCIM provisioning syncs users and groups from your identity provider automatically. Upgrade
				to Enterprise to connect Okta, Entra ID, and other SCIM directories.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button href={UpgradeURL} target="_blank" rel="noopener">See plans</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

<PageHeader
	title="Single sign-on"
	description="Connect the identity providers people sign in with, then provision them with SCIM"
/>

{#if readonly}
	<Alert.Root class="mb-4">
		<Crown class="size-4" />
		<Alert.Title>Only the owner can change this</Alert.Title>
		<Alert.Description>
			A provider vouches for every account that signs in through it, so the settings stay with the
			workspace owner.
		</Alert.Description>
	</Alert.Root>
{/if}

<Tabs.Root bind:value={tab} class="gap-4">
	<Tabs.List>
		<Tabs.Trigger value="providers">
			<OIDCIcon />
			Providers
		</Tabs.Trigger>
		<Tabs.Trigger value="scim">
			<UsersRound />
			SCIM
		</Tabs.Trigger>
	</Tabs.List>

	<Tabs.Content value="providers">
		<ProvidersTab {readonly} />
	</Tabs.Content>
	<Tabs.Content value="scim">
		{#if !scimAvailable}
			{@render needsUpgrade()}
		{:else}
			<SCIMTab {readonly} />
		{/if}
	</Tabs.Content>
</Tabs.Root>
