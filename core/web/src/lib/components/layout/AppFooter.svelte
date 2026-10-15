<script lang="ts">
	import { util } from '#lib/api/workspaces.svelte.js';
	import ModeSwitch from '#lib/components/blocks/ModeSwitch.svelte';
	import LegalLinks from '#lib/components/blocks/LegalLinks.svelte';

	const version = util.getVersion();
</script>

<footer
	class="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-b-xl border-t bg-background px-4 py-1 sm:py-2"
>
	<LegalLinks />

	<div class="flex items-center gap-2">
		<div
			class="flex h-8 items-center gap-1.5 px-2 text-xs text-muted-foreground hover:text-foreground sm:px-3"
		>
			<span class="italic">
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
