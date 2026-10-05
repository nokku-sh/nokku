<script lang="ts">
	import { principal } from '#lib/api/principals.svelte.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import TagsCell from './TagsCell.svelte';

	let { targetId }: { targetId: string } = $props();

	const pData = principal.list(() => ({ targetId }));
	const principals = $derived(pData.data?.principals || []);
	const tags = $derived(principals.map((p) => p.username));
</script>

{#if pData.isLoading}
	<Skeleton class="h-5 w-16" />
{:else if tags.length > 0}
	<TagsCell {tags} />
{:else}
	<span class="text-sm text-muted-foreground">-</span>
{/if}
