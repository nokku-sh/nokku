<script lang="ts">
	import { cn } from '#lib/utils.js';
	import { toneBg, type Tone } from '#lib/tone.js';

	interface Props {
		tone?: Tone;
		/** Adds a ping ring, for things happening right now. */
		live?: boolean;
		class?: string;
	}

	let { tone = 'muted', live = false, class: className }: Props = $props();
</script>

<span class={cn('relative flex size-2 shrink-0', className)} aria-hidden="true">
	{#if live}
		<span
			class={['absolute inline-flex size-full animate-ping rounded-full opacity-60', toneBg[tone]]}
		></span>
	{/if}
	<span class={['relative size-full rounded-full', toneBg[tone]]}></span>
</span>
