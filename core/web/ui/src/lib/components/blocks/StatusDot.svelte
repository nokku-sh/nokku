<script lang="ts">
	import { cn } from '#lib/utils.js';
	import { toneBg, type Tone } from '#lib/tone.js';

	interface Props {
		tone?: Tone;
		/** Adds a slow halo, for things happening right now. Steady states stay still. */
		live?: boolean;
		class?: string;
	}

	let { tone = 'muted', live = false, class: className }: Props = $props();
</script>

<span class={cn('relative flex size-2 shrink-0', className)} aria-hidden="true">
	{#if live}
		<span
			class={[
				'absolute -inset-0.5 rounded-full opacity-50 [--breathe-to:0.1] motion-safe:animate-breathe',
				toneBg[tone]
			]}
		></span>
	{/if}
	<span class={['relative size-full rounded-full', toneBg[tone]]}></span>
</span>
