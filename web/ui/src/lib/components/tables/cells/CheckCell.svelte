<script lang="ts">
	import { CircleCheckBig, CircleSlash } from '@lucide/svelte';

	type Props = {
		checked?: boolean;
	};
	let { checked = false, ...restProps }: Props = $props();
</script>

{#if checked}
	<CircleCheckBig class="text-chart-3" size={16} {...restProps} />
{:else}
	<CircleSlash class="text-destructive" size={16} {...restProps} />
{/if}
