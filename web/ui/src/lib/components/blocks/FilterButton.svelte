<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Separator } from '$lib/components/ui/separator';
	import { CirclePlus } from '@lucide/svelte';

	// The rest are trigger props from a Popover or SearchPopover.
	interface Props extends Record<string, unknown> {
		title: string;
		/** Labels of the selected values. */
		selected: string[];
	}

	let { title, selected, ...restProps }: Props = $props();
</script>

<Button {...restProps} variant="outline" size="sm" class="h-8 rounded-full border-dashed">
	<CirclePlus data-icon="inline-start" />
	{title}
	{#if selected.length}
		<Separator orientation="vertical" class="mx-1 h-4" />
		<Badge variant="secondary" class="rounded-sm px-1 font-normal">
			{selected.length === 1 ? selected[0] : `${selected.length} selected`}
		</Badge>
	{/if}
</Button>
