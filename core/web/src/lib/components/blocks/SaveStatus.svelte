<script lang="ts">
	import { Check, CircleX } from '@lucide/svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import type { SaveState } from '#lib/hooks/index.js';
	import { cn } from '#lib/utils.js';

	interface Props {
		state: SaveState;
		/** Shown while idle, e.g. a hint that changes save on their own. */
		idleText?: string;
		/** Offers to run the failed change again. The reason is in the error toast. */
		onRetry?: () => void;
		class?: string;
	}

	let { state, idleText, onRetry, class: className }: Props = $props();
</script>

<p
	class={cn(
		'flex items-center gap-1.5 text-xs text-muted-foreground transition-colors',
		state === 'saved' && 'text-success',
		state === 'error' && 'text-destructive',
		className
	)}
	role="status"
>
	{#if state === 'saving'}
		<Spinner class="size-3" />
		Saving&hellip;
	{:else if state === 'saved'}
		<Check class="size-3" />
		Saved
	{:else if state === 'error'}
		<CircleX class="size-3" />
		Save failed
		{#if onRetry}
			<Button variant="ghost" size="xs" class="-my-1 text-destructive" onclick={onRetry}
				>Retry</Button
			>
		{/if}
	{:else if idleText}
		{idleText}
	{/if}
</p>
