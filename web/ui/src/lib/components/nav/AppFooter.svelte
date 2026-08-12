<script lang="ts">
	import { util } from '$lib/api/workspaces.svelte';
	import ModeSwitch from '$lib/components/utils/ModeSwitch.svelte';
	import { ImprintURL, PrivacyURL, ToSURL } from '$lib/config';

	const version = $derived(util.getVersion());
</script>

<footer
	class="flex flex-col items-center justify-between gap-4 rounded-b-xl border-t bg-background/95 px-4 py-2 shadow-[0_-1px_2px_rgba(0,0,0,0.05)] backdrop-blur supports-backdrop-filter:bg-background/80 sm:flex-row"
>
	<div class="flex flex-col items-center gap-2 sm:flex-row sm:gap-4">
		<p class="text-xs text-muted-foreground">
			&copy; {new Date().getFullYear()} Mizuchi Labs. All rights reserved.
		</p>

		<div class="hidden h-4 w-px bg-border sm:block"></div>

		<nav class="flex items-center gap-4 text-xs text-muted-foreground">
			<a href={ToSURL} class="transition-colors hover:text-foreground">Terms of Service</a>
			<a href={PrivacyURL} class="transition-colors hover:text-foreground">Privacy Policy</a>
			<a href={ImprintURL} class="transition-colors hover:text-foreground">Legal Notice</a>
		</nav>
	</div>

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
