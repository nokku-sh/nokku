<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { cn } from '#lib/utils.js';
	import { RotateCw, TriangleAlert } from '@lucide/svelte';

	interface Props {
		title: string;
		/** What still works, so a failed read does not look like lost data. */
		description?: string;
		onRetry: () => unknown;
		class?: string;
	}

	let { title, description, onRetry, class: className }: Props = $props();
</script>

<Empty.Root class={cn('border border-dashed', className)}>
	<Empty.Header>
		<Empty.Media variant="icon" class="bg-destructive/10 text-destructive">
			<TriangleAlert />
		</Empty.Media>
		<Empty.Title>{title}</Empty.Title>
		{#if description}
			<Empty.Description>{description}</Empty.Description>
		{/if}
	</Empty.Header>
	<Empty.Content>
		<Button variant="outline" size="sm" onclick={onRetry}>
			<RotateCw data-icon="inline-start" />
			Try again
		</Button>
	</Empty.Content>
</Empty.Root>
