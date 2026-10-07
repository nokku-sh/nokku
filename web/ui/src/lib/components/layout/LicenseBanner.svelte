<script lang="ts">
	import { license, licenseStatus } from '#lib/api/license.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { atLeast } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { TriangleAlert } from '@lucide/svelte';

	const data = license.get();
	const me = user.self();

	const status = $derived(licenseStatus(data.data));
	const expired = $derived(status.state === 'expired');
	// Only the people who can act on it.
	const show = $derived(
		(expired || status.state === 'expiring') && atLeast(me.data?.role, 'admin')
	);
</script>

{#if show}
	<a
		href="/settings/billing"
		class={[
			'flex shrink-0 items-center justify-center gap-2 border-b px-4 py-1.5 text-sm hover:underline',
			expired ? 'bg-destructive/10 text-destructive' : 'bg-warning/10 text-warning'
		]}
	>
		<TriangleAlert class="size-4 shrink-0" />
		{#if expired}
			The license expired on {formatTs(status.expiresAt)}. Activate the renewed key to turn licensed
			features back on
		{:else}
			The license expires in {status.daysLeft}
			{status.daysLeft === 1 ? 'day' : 'days'}. Activate the renewed key
		{/if}
	</a>
{/if}
