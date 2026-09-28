<script lang="ts" module>
	export type DangerAction = {
		title: string;
		description: string;
		label: string;
		onClick: () => void;
		disabled?: boolean;
	};
</script>

<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Item from '$lib/components/ui/item';
	import { TriangleAlert } from '@lucide/svelte';
	import Section from './Section.svelte';

	let { actions }: { actions: DangerAction[] } = $props();
</script>

{#if actions.length}
	<Section title="Danger zone" icon={TriangleAlert} tone="destructive">
		<Item.Group class="divide-y rounded-lg border border-destructive/25">
			{#each actions as action (action.title)}
				<Item.Root size="sm" class="rounded-none">
					<Item.Content>
						<Item.Title>{action.title}</Item.Title>
						<Item.Description>{action.description}</Item.Description>
					</Item.Content>
					<Item.Actions>
						<Button
							variant="destructive"
							size="sm"
							disabled={action.disabled}
							onclick={action.onClick}
						>
							{action.label}
						</Button>
					</Item.Actions>
				</Item.Root>
			{/each}
		</Item.Group>
	</Section>
{/if}
