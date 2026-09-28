<script lang="ts">
	import { Check, CircleX } from '@lucide/svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { SaveState } from '$lib/hooks';
	import { cn } from '$lib/utils';

	interface Props {
		state: SaveState;
		/** Shown while idle, e.g. a hint that changes save on their own. */
		idleText?: string;
		class?: string;
	}

	let { state, idleText, class: className }: Props = $props();
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
	{:else if idleText}
		{idleText}
	{/if}
</p>
