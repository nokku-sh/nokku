<script lang="ts">
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { formatTs } from '#lib/utils.js';
	import { TriangleAlert } from '@lucide/svelte';

	const plan = workspace.plan();
	const can = user.can();

	const deleteAt = $derived(formatTs(plan.data?.deleteAt));
	// The owner can act on it, so for them it links to billing.
	const next = $derived.by(() => {
		if (can.own) {
			return deleteAt
				? `Subscribe before ${deleteAt} or the workspace is deleted`
				: 'Subscribe to turn signing back on';
		}
		return deleteAt
			? `The workspace is deleted on ${deleteAt} unless the owner subscribes`
			: 'Ask the workspace owner to subscribe';
	});
</script>

{#if plan.data?.inactive}
	<svelte:element
		this={can.own ? 'a' : 'p'}
		href={can.own ? '/settings/billing' : undefined}
		class={[
			'flex shrink-0 items-center justify-center gap-2 border-b bg-destructive/10 px-4 py-1.5 text-sm text-destructive',
			can.own && 'hover:underline'
		]}
	>
		<TriangleAlert class="size-4 shrink-0" />
		<span>No active plan, so Nokku signs no certificates. {next}</span>
	</svelte:element>
{/if}
