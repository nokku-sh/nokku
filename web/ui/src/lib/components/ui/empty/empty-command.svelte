<script lang="ts">
	import { cn, type WithElementRef } from '$lib/utils.js';
	import type { HTMLAttributes } from 'svelte/elements';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLElement>> = $props();
</script>

<!-- A shell prompt hint, the CLI way to fill an empty state. -->
<code
	bind:this={ref}
	data-slot="empty-command"
	class={cn(
		'inline-flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-1.5 font-mono text-xs text-foreground select-all',
		className
	)}
	{...restProps}
>
	<span class="text-primary select-none" aria-hidden="true">$</span>
	<span>{@render children?.()}</span>
	<span
		class="-ml-1 inline-block h-3.5 w-1.5 bg-primary select-none motion-safe:animate-blink"
		aria-hidden="true"
	></span>
</code>
