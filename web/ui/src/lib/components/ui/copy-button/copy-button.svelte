<script lang="ts">
	import { UseClipboard } from '$lib/hooks/use-clipboard.svelte';
	import { cn } from '$lib/utils.js';
	import CheckIcon from '@lucide/svelte/icons/check';
	import CopyIcon from '@lucide/svelte/icons/copy';
	import XIcon from '@lucide/svelte/icons/x';
	import { scale } from 'svelte/transition';

	type Props = {
		text: string;
		icon?: boolean;
		animationDuration?: number;
		class?: string;
		children?: any;
	};
	let {
		text,
		icon = true,
		animationDuration = 500,
		class: className,
		children,
		...restProps
	}: Props = $props();

	const clipboard = new UseClipboard();
</script>

<button
	onclick={() => clipboard.copy(text)}
	class={cn('flex items-center gap-2 outline-none', className)}
	{...restProps}
>
	{@render children?.()}

	{#if clipboard.status === 'success'}
		<div in:scale={{ duration: animationDuration, start: 0.85 }}>
			<CheckIcon size={16} tabindex={-1} class="text-muted-foreground" />
			<span class="sr-only">Copied</span>
		</div>
	{:else if clipboard.status === 'failure'}
		<div in:scale={{ duration: animationDuration, start: 0.85 }}>
			<XIcon size={16} tabindex={-1} class="text-destructive" />
			<span class="sr-only">Failed to copy</span>
		</div>
	{:else}
		<div in:scale={{ duration: animationDuration, start: 0.85 }}>
			{#if icon}
				<CopyIcon size={16} tabindex={-1} class="text-muted-foreground" />
			{/if}
			<span class="sr-only">Copy</span>
		</div>
	{/if}
</button>
