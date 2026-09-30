<script lang="ts">
	import { util } from '$lib/api/workspaces.svelte';

	/** Everything before "you agree", e.g. "By signing up,". */
	let { lead }: { lead: string } = $props();

	const info = util.instanceInfo();
	const docs = $derived(
		[
			{ label: 'Terms', href: info.data?.termsUrl },
			{ label: 'Privacy Policy', href: info.data?.privacyUrl }
		].filter((d) => d.href)
	);
</script>

<!-- Only when the operator has terms to agree to. -->
{#if docs.length}
	<p class="text-center text-xs text-balance text-muted-foreground">
		{lead} you agree to the
		{#each docs as d, i (d.label)}
			{#if i > 0}and the{/if}
			<a
				href={d.href}
				target="_blank"
				rel="noopener"
				class="underline underline-offset-2 hover:text-foreground">{d.label}</a
			>{/each}.
	</p>
{/if}
