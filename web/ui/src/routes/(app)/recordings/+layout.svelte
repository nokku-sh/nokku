<script lang="ts">
	let { children } = $props();
</script>

<div class="container mx-auto max-w-6xl space-y-6 p-6">
	{@render children?.()}
</div>
