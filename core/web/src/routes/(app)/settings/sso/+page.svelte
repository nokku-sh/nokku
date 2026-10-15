<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { billing } from '#lib/api/billing.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util } from '#lib/api/workspaces.svelte.js';
	import { Crown, UsersRound } from '@lucide/svelte';
	import ProvidersTab from './ProvidersTab.svelte';
	import SCIMTab from './SCIMTab.svelte';
	import { OIDCIcon } from '#lib/assets/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';

	const me = user.self();
	const can = user.can();
	const info = util.instanceInfo();
	const mode = $derived(info.data?.mode);

	// Only admins read the plan. Everyone below sees the settings read-only, so they get no lock either.
	// Undefined while the plan loads, so nothing gets offered or locked too early.
	const billingData = billing.get(() => can.admin);
	const has = (feature: string) => {
		if (!can.admin) return true;
		return billingData.data ? billingData.data.features?.[feature] === true : undefined;
	};

	// Not `tab`, the provider sheet owns that one.
	const view = $derived(page.url.searchParams.get('view') === 'scim' ? 'scim' : 'providers');
	function setView(value: string) {
		const url = new URL(page.url.href);
		if (value === 'scim') url.searchParams.set('view', value);
		else url.searchParams.delete('view');
		void goto(url, { replace: true, reset: false });
	}
</script>

<PageHeader
	title="Single sign-on"
	description="Connect the identity providers people sign in with, then provision them with SCIM"
/>

{#if me.data && !can.own}
	<Alert.Root class="mb-4">
		<Crown class="size-4" />
		<Alert.Title>Only the owner can change this</Alert.Title>
		<Alert.Description>
			A provider vouches for every account that signs in through it, so the settings stay with the
			workspace owner.
		</Alert.Description>
	</Alert.Root>
{/if}

<Tabs.Root value={view} onValueChange={setView} class="gap-4">
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
		<ProvidersTab readonly={!can.own} {mode} enforceAvailable={has('enforce_sso')} />
	</Tabs.Content>
	<Tabs.Content value="scim">
		<SCIMTab readonly={!can.own} {mode} available={has('scim')} />
	</Tabs.Content>
</Tabs.Root>
