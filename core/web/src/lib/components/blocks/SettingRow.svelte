<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { cn } from '#lib/utils.js';

	interface Props {
		title: string;
		description?: string;
		/** The id of the control, so the title labels it. */
		for?: string;
		/** What sshd_config calls the setting, for people who know it by that name. */
		directive?: string;
		/** A border of its own. Leave it off inside a bordered Item.Group. */
		outline?: boolean;
		/** The control is a select or wider, on a phone it takes a row of its own. */
		wide?: boolean;
		/** After the title, e.g. a plan badge. */
		badge?: Snippet;
		/** A line under the description, for what the value means right now. */
		note?: Snippet;
		/** The control. */
		children: Snippet;
		class?: string;
	}

	let {
		title,
		description,
		for: id,
		directive,
		outline = false,
		wide = false,
		badge,
		note,
		children,
		class: className
	}: Props = $props();
</script>

<Item.Root
	size="sm"
	variant={outline ? 'outline' : 'default'}
	class={cn(!outline && 'rounded-none', className)}
>
	<Item.Content>
		<Item.Title class="line-clamp-none flex-wrap">
			{#if id}<label for={id}>{title}</label>{:else}{title}{/if}
			{#if directive}
				<Badge
					variant="outline"
					class="rounded-sm font-mono font-normal text-muted-foreground"
					title="The name of this setting in sshd_config"
				>
					{directive}
				</Badge>
			{/if}
			{@render badge?.()}
		</Item.Title>
		{#if description}
			<Item.Description class="line-clamp-none">{description}</Item.Description>
		{/if}
		{@render note?.()}
	</Item.Content>
	<Item.Actions class={wide ? 'w-full sm:w-auto' : undefined}>
		{@render children()}
	</Item.Actions>
</Item.Root>
