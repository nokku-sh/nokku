<script lang="ts">
	import type { Node, NodeProps } from '@xyflow/svelte';
	import type { LabelData } from './graph.js';

	let { data }: NodeProps<Node<LabelData>> = $props();
</script>

<div class="flex size-full items-end justify-between px-1">
	<span class={data.heading ? 'text-sm font-semibold' : 'spec-label'}>{data.text}</span>
	{#if data.heading}
		<span class="spec-label">Targets</span>
	{/if}
</div>
