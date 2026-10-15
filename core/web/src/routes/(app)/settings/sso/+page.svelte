<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
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
	const isOwner = $derived(me.data?.role === WorkspaceRole.OWNER);
	// Read-only until the account loads, so nothing looks clickable for a moment and then isn't.
	const readonly = $derived(!isOwner);

	// Only admins read the plan. Everyone below sees the settings read-only either way.
	const can = user.can();
	const billingData = billing.get(() => can.admin);
	const mode = $derived(util.instanceInfo().data?.mode);
	// Undefined while the plan loads, so nothing gets offered or locked too early.
	const has = (feature: string) =>
		billingData.data ? billingData.data.features?.[feature] === true : undefined;

	const tab = $derived(page.url.searchParams.get('tab') === 'scim' ? 'scim' : 'providers');
	function setTab(value: string) {
		const url = new URL(page.url.href);
		if (value === 'scim') url.searchParams.set('tab', value);
		else url.searchParams.delete('tab');
		void goto(url, { replace: true, reset: false });
	}
</script>

<PageHeader
	title="Single sign-on"
	description="Connect the identity providers people sign in with, then provision them with SCIM"
/>

{#if me.data && readonly}
	<Alert.Root class="mb-4">
		<Crown class="size-4" />
		<Alert.Title>Only the owner can change this</Alert.Title>
		<Alert.Description>
			A provider vouches for every account that signs in through it, so the settings stay with the
			workspace owner.
		</Alert.Description>
	</Alert.Root>
{/if}

<Tabs.Root value={tab} onValueChange={setTab} class="gap-4">
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
		<ProvidersTab {readonly} {mode} enforceAvailable={can.admin ? has('enforce_sso') : true} />
	</Tabs.Content>
	<Tabs.Content value="scim">
		<SCIMTab {readonly} {mode} available={can.admin ? has('scim') : true} />
	</Tabs.Content>
</Tabs.Root>
