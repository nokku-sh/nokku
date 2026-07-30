<script lang="ts">
	import { SvelteFlowProvider } from '@xyflow/svelte';
	let { children } = $props();
</script>

<SvelteFlowProvider>
	{@render children?.()}
</SvelteFlowProvider>
