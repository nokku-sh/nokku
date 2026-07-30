<script lang="ts">
	import CirclePlusIcon from '@lucide/svelte/icons/circle-plus';
	import { SvelteSet } from 'svelte/reactivity';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Separator } from '$lib/components/ui/separator';
	import { CircleCheckBig } from '@lucide/svelte';
	import type { FacetedFilter } from '$lib/components/tables/types';

	type Props = {
		values: SvelteSet<string>;
		title: string;
		options: FacetedFilter[];
	};
	let { values = $bindable(), title, options }: Props = $props();
</script>

<Popover.Root>
	<Popover.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline" size="sm" class="h-8 border-dashed">
				<CirclePlusIcon />
				{title}
				{#if values.size > 0}
					<Separator orientation="vertical" class="mx-2 h-4" />
					<Badge variant="secondary" class="rounded-sm px-1 font-normal lg:hidden">
						{values.size}
					</Badge>
					<div class="hidden space-x-1 lg:flex">
						{#if values.size > 2}
							<Badge variant="secondary" class="rounded-sm px-1 font-normal">
								{values.size} selected
							</Badge>
						{:else}
							{#each options.filter((opt) => values.has(opt.value)) as option (option)}
								<Badge variant="secondary" class="rounded-sm px-1 font-normal">
									{option.label}
								</Badge>
							{/each}
						{/if}
					</div>
				{/if}
			</Button>
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-[200px] p-0" align="start">
		<Command.Root>
			<Command.Input placeholder={title} />
			<Command.List>
				<Command.Empty>No results found.</Command.Empty>
				<Command.Group>
					{#each options as option (option)}
						{@const isSelected = values.has(option.value)}
						<Command.Item
							onSelect={() => {
								if (isSelected) {
									values.delete(option.value);
								} else {
									values.add(option.value);
								}
							}}
							class="flex items-center justify-between"
						>
							<div class="flex items-center gap-2">
								<option.icon class="text-muted-foreground" />
								<span>{option.label}</span>
							</div>
							{#if isSelected}
								<CircleCheckBig size="4" class="text-primary" />
							{/if}
						</Command.Item>
					{/each}
				</Command.Group>
				{#if values.size > 0}
					<Command.Separator />
					<Command.Group>
						<Command.Item onSelect={() => values.clear()} class="justify-center text-center">
							Clear filters
						</Command.Item>
					</Command.Group>
				{/if}
			</Command.List>
		</Command.Root>
	</Popover.Content>
</Popover.Root>
