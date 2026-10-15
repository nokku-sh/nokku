<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { statusTone, type Tone } from '#lib/tone.js';

	type Props = {
		label: string;
		/** Defaults to the tone the status word maps to in tone.ts. */
		tone?: Tone;
		icon?: LucideIcon;
	};
	let { label, tone, icon: Icon }: Props = $props();
</script>

<!-- One look for every state in every table: a tone, an icon when it helps, always a word. -->
<Badge variant={tone ?? statusTone(label)}>
	{#if Icon}<Icon data-icon="inline-start" />{/if}
	{label}
</Badge>
