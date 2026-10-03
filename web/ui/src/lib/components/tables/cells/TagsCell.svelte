<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';

	type Props = {
		tags: string[];
		maxVisible?: number;
	};
	let { tags = [], maxVisible = 2, ...restProps }: Props = $props();

	let visibleTags = $derived(tags.slice(0, maxVisible));
	let hiddenTags = $derived(tags.slice(maxVisible));
	let hasHidden = $derived(hiddenTags.length > 0);
</script>

<div class="flex flex-wrap items-center gap-1" {...restProps}>
	{#each visibleTags as tag}
		<Badge variant="secondary" class="px-1.5 py-0.5 text-2xs leading-none font-normal">
			{tag}
		</Badge>
	{/each}

	{#if hasHidden}
		<HoverCard.Root>
			<HoverCard.Trigger>
				<Badge
					variant="outline"
					class="cursor-default px-1.5 py-0.5 text-2xs leading-none font-normal text-muted-foreground"
				>
					+{hiddenTags.length}
				</Badge>
			</HoverCard.Trigger>
			<HoverCard.Content class="w-auto p-2">
				<div class="flex max-w-50 flex-wrap gap-1">
					{#each hiddenTags as tag}
						<Badge variant="secondary" class="px-1.5 py-0.5 text-2xs leading-none font-normal">
							{tag}
						</Badge>
					{/each}
				</div>
			</HoverCard.Content>
		</HoverCard.Root>
	{/if}
</div>
