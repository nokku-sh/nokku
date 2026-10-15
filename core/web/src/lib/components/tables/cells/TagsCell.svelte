<script lang="ts">
	import { Badge, badgeVariants } from '#lib/components/ui/badge/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import { cn } from '#lib/utils.js';

	type Props = {
		tags: string[];
		maxVisible?: number;
		/** For machine values like login accounts. */
		mono?: boolean;
		/** What the chips are, for the "+n" label. */
		noun?: string;
	};
	let { tags = [], maxVisible = 3, mono = false, noun = 'tags' }: Props = $props();

	// "+1" would take the room of the one chip it hides.
	const visible = $derived(tags.length <= maxVisible + 1 ? tags : tags.slice(0, maxVisible));
	const rest = $derived(tags.slice(visible.length));

	const chip = $derived(cn('h-5 rounded-full px-2 font-normal', mono && 'font-mono'));
</script>

{#snippet chips(list: string[])}
	{#each list as tag (tag)}
		<Badge variant="outline" class={chip}>{tag}</Badge>
	{/each}
{/snippet}

{#if !tags.length}
	<span class="text-sm text-muted-foreground">-</span>
{:else}
	<div class="flex items-center gap-1">
		{@render chips(visible)}
		{#if rest.length}
			<Popover.Root>
				<Popover.Trigger
					class={cn(
						badgeVariants({ variant: 'outline' }),
						'h-5 cursor-pointer rounded-full px-2 font-normal text-muted-foreground hover:bg-muted hover:text-foreground'
					)}
					aria-label={`${rest.length} more ${noun}`}
				>
					+{rest.length}
				</Popover.Trigger>
				<Popover.Content class="w-auto max-w-64 p-2" align="start">
					<div class="flex flex-wrap gap-1">
						{@render chips(rest)}
					</div>
				</Popover.Content>
			</Popover.Root>
		{/if}
	</div>
{/if}
