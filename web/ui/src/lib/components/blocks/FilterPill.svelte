<script lang="ts">
	import type { Component } from 'svelte';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Check } from '@lucide/svelte';
	import FilterButton from './FilterButton.svelte';

	export type FilterOption = {
		label: string;
		value: string;
		icon?: Component<{ class?: string }>;
	};

	interface Props {
		title: string;
		options: FilterOption[];
		selected: string[];
		onChange: (next: string[]) => void;
		mode?: 'single' | 'multi';
	}

	let { title, options, selected, onChange, mode = 'multi' }: Props = $props();

	const labels = $derived(selected.map((v) => options.find((o) => o.value === v)?.label ?? v));

	function toggle(value: string) {
		if (mode === 'single') onChange(selected.includes(value) ? [] : [value]);
		else
			onChange(
				selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value]
			);
	}
</script>

<Popover.Root>
	<Popover.Trigger>
		{#snippet child({ props })}
			<FilterButton {...props} {title} selected={labels} />
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-52 p-0" align="start">
		<Command.Root>
			<Command.Input placeholder={title} />
			<Command.List>
				<Command.Empty>No results found.</Command.Empty>
				<Command.Group>
					{#each options as option (option.value)}
						<Command.Item onSelect={() => toggle(option.value)}>
							{#if option.icon}
								<option.icon class="text-muted-foreground" />
							{/if}
							<span class="flex-1">{option.label}</span>
							<Check class={selected.includes(option.value) ? 'text-primary' : 'invisible'} />
						</Command.Item>
					{/each}
				</Command.Group>
				{#if selected.length}
					<Command.Separator />
					<Command.Group>
						<Command.Item onSelect={() => onChange([])} class="justify-center">
							Clear filters
						</Command.Item>
					</Command.Group>
				{/if}
			</Command.List>
		</Command.Root>
	</Popover.Content>
</Popover.Root>
