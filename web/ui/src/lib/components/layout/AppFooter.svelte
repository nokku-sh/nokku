<script lang="ts">
	import { util } from '$lib/api/workspaces.svelte';
	import ModeSwitch from '$lib/components/blocks/ModeSwitch.svelte';
	import LegalLinks from '$lib/components/blocks/LegalLinks.svelte';

	const version = util.getVersion();
</script>

<footer
	class="flex flex-col items-center justify-between gap-4 rounded-b-xl border-t bg-background/95 px-4 py-2 backdrop-blur supports-backdrop-filter:bg-background/80 sm:flex-row"
>
	<LegalLinks />

	<div class="flex items-center gap-2">
		<div
			class="flex h-8 items-center gap-1.5 px-2 text-xs text-muted-foreground hover:text-foreground sm:px-3"
		>
			<span class="italic opacity-70">
				{#if version.data && version.data !== 'dev'}
					v{version.data}
				{:else}
					dev build
				{/if}
			</span>
		</div>

		<ModeSwitch />
	</div>
</footer>
