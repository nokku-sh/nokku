<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import { cn } from '#lib/utils.js';
	import { Check } from '@lucide/svelte';

	interface Props {
		value: string;
		mono?: boolean;
		class?: string;
		children?: Snippet;
	}

	let { value, mono = false, class: className, children }: Props = $props();

	const clipboard = new UseClipboard({ delay: 1200 });
</script>

<Tooltip.Root>
	<Tooltip.Trigger>
		{#snippet child({ props })}
			<button
				{...props}
				type="button"
				class={cn(
					'-mx-1 inline-flex max-w-full min-w-0 cursor-copy items-center gap-1 rounded-sm px-1 text-left transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
					mono && 'font-mono text-xs',
					className
				)}
				onclick={(e) => {
					e.stopPropagation();
					void clipboard.copy(value);
				}}
			>
				<span class="truncate">
					{#if children}{@render children()}{:else}{value}{/if}
				</span>
				{#if clipboard.copied}
					<Check class="size-3 shrink-0 text-success" />
				{/if}
			</button>
		{/snippet}
	</Tooltip.Trigger>
	<Tooltip.Content>{clipboard.copied ? 'Copied' : 'Click to copy'}</Tooltip.Content>
</Tooltip.Root>
