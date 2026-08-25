<script lang="ts">
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import * as Item from '$lib/components/ui/item';
	import { formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon } from '@lucide/svelte';

	interface Props {
		createdAt?: Timestamp;
		updatedAt?: Timestamp;
	}

	let { createdAt, updatedAt }: Props = $props();
</script>

{#if createdAt || updatedAt}
	<Item.Group class="grid grid-cols-2 gap-2">
		{#if createdAt}
			<Item.Root variant="muted">
				<Item.Media variant="icon">
					<CalendarIcon />
				</Item.Media>
				<Item.Content>
					<Item.Title>Created</Item.Title>
					<Item.Description class="font-mono text-xs">
						{formatTs(createdAt)}
					</Item.Description>
				</Item.Content>
			</Item.Root>
		{/if}
		{#if updatedAt}
			<Item.Root variant="muted">
				<Item.Media variant="icon">
					<ClockIcon />
				</Item.Media>
				<Item.Content>
					<Item.Title>Last Updated</Item.Title>
					<Item.Description class="font-mono text-xs">
						{formatTs(updatedAt, 'relative')}
					</Item.Description>
				</Item.Content>
			</Item.Root>
		{/if}
	</Item.Group>
{/if}
