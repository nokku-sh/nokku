<script lang="ts">
	import { SvelteSet } from 'svelte/reactivity';
	import CirclePlusIcon from '@lucide/svelte/icons/circle-plus';
	import XIcon from '@lucide/svelte/icons/x';
	import { CircleCheckBig } from '@lucide/svelte';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Separator } from '$lib/components/ui/separator';
	import type { Component } from 'svelte';

	type FilterOption = {
		label: string;
		value: string;
		icon?: Component<{ size?: number; class?: string }>;
	};

	type Props = {
		values: SvelteSet<string>;
		title: string;
		options: FilterOption[];
		mode?: 'single' | 'multi';
		clearable?: boolean;
	};

	let { values = $bindable(), title, options, mode = 'multi', clearable = true }: Props = $props();

	function toggle(option: FilterOption) {
		if (mode === 'single') {
			if (values.has(option.value)) {
				values.delete(option.value);
			} else {
				values.clear();
				values.add(option.value);
			}
		} else {
			if (values.has(option.value)) {
				values.delete(option.value);
			} else {
				values.add(option.value);
			}
		}
	}

	function clear() {
		values.clear();
	}

	function remove(value: string) {
		values.delete(value);
	}

	const selectedOptions = $derived(options.filter((opt) => values.has(opt.value)));
	const count = $derived(values.size);
</script>

<Popover.Root>
	<Popover.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline" size="sm" class="h-8 rounded-full border-dashed">
				<CirclePlusIcon />
				{title}
				{#if count > 0}
					<Separator orientation="vertical" class="mx-2 h-4" />
					<Badge variant="secondary" class="rounded-sm px-1 font-normal lg:hidden">
						{count}
					</Badge>
					<div class="hidden space-x-1 lg:flex">
						{#if count > 1}
							<Badge variant="secondary" class="rounded-sm px-1 font-normal">
								{count} selected
							</Badge>
						{:else}
							{#each selectedOptions as option (option.value)}
								<Badge variant="secondary" class="space-x-1 rounded-sm px-1 font-normal">
									<span>{option.label}</span>
									{#if clearable}
										<button
											type="button"
											class="inline-flex items-center justify-center hover:text-foreground"
											onclick={(e) => {
												e.stopPropagation();
												remove(option.value);
											}}
										>
											<XIcon class="size-3" />
										</button>
									{/if}
								</Badge>
							{/each}
						{/if}
					</div>
				{/if}
			</Button>
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-50 p-0" align="start">
		<Command.Root>
			<Command.Input placeholder={title} />
			<Command.List>
				<Command.Empty>No results found.</Command.Empty>
				<Command.Group>
					{#each options as option (option.value)}
						{@const isSelected = values.has(option.value)}
						<Command.Item onSelect={() => toggle(option)} class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								{#if option.icon}
									<option.icon class="text-muted-foreground" />
								{/if}
								<span>{option.label}</span>
							</div>
							{#if isSelected}
								<CircleCheckBig size="4" class="text-primary" />
							{/if}
						</Command.Item>
					{/each}
				</Command.Group>
				{#if count > 0}
					<Command.Separator />
					<Command.Group>
						<Command.Item onSelect={clear} class="justify-center text-center">
							Clear filters
						</Command.Item>
					</Command.Group>
				{/if}
			</Command.List>
		</Command.Root>
	</Popover.Content>
</Popover.Root>
