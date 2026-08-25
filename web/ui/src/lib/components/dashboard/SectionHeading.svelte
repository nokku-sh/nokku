<script lang="ts">
	import { ArrowRight } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	interface Props {
		title: string;
		description?: string;
		href?: string;
		hrefLabel?: string;
		children?: Snippet;
	}

	let { title, description, href, hrefLabel = 'View all', children }: Props = $props();
</script>

<div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
	<div class="space-y-0.5">
		<h2 class="text-lg font-semibold tracking-tight">{title}</h2>
		{#if description}
			<p class="text-xs text-muted-foreground">{description}</p>
		{/if}
	</div>
	{#if children || href}
		<div class="flex items-center gap-3">
			{@render children?.()}
			{#if href}
				<a
					{href}
					class="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
				>
					{hrefLabel}
					<ArrowRight class="size-3" />
				</a>
			{/if}
		</div>
	{/if}
</div>
