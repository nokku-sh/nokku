<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { license, licenseStatus } from '#lib/api/license.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util } from '#lib/api/workspaces.svelte.js';
	import { atLeast } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { TriangleAlert } from '@lucide/svelte';

	const data = license.get();
	const me = user.self();
	const info = util.instanceInfo();

	const status = $derived(licenseStatus(data.data));
	// A hosted workspace with an expired key has no plan, the plan banner says so.
	const expired = $derived(status.state === 'expired' && !info.data?.hosted);
	// Only the people who can act on it.
	const show = $derived(
		(expired || status.state === 'expiring') && atLeast(me.data?.role, WorkspaceRole.ADMIN)
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
