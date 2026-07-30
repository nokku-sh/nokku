<script lang="ts" generics="T">
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Select from '$lib/components/ui/select/index.js';
	import { Separator } from '$lib/components/ui/separator';
	import { XIcon } from '@lucide/svelte';
	import { slide } from 'svelte/transition';
	import type { BulkAction } from './types';

	type Props<TData> = {
		items: TData[];
		actions: BulkAction<TData>[];
		count: {
			selected: number;
			total: number;
		};
		onClear?: () => void;
	};
	let { items, actions, count, onClear }: Props<T> = $props();
</script>

{#if count.selected > 0}
	<div class="fixed bottom-16 left-1/2 z-50 -translate-x-16" transition:slide={{ duration: 200 }}>
		<div
			class="flex items-center gap-3 rounded-full border bg-background/95 px-4 py-2 shadow-lg backdrop-blur supports-backdrop-filter:bg-background/80"
		>
			<div class="flex items-center gap-2 pr-3">
				<Badge variant="secondary" class="size-7 rounded-full p-0 text-sm font-semibold">
					{count.selected}
				</Badge>
				<span class="text-sm text-muted-foreground">
					of {count.total} selected
				</span>
			</div>

			<Separator orientation="vertical" class="h-6" />

			<div class="flex flex-1 items-center gap-2 overflow-x-auto">
				{#each actions as action (action.label)}
					{#if action.type === 'button'}
						<Button
							variant={action.variant ?? 'ghost'}
							size="sm"
							class="h-8 {action.class ?? ''}"
							onclick={() => action.onClick?.(items)}
							disabled={action.disabled}
						>
							{#if action.icon}
								<action.icon data-icon="inline-start" />
							{/if}
							{action.label}
						</Button>
					{:else if action.type === 'select' && action.options}
						<Select.Root
							type="single"
							onValueChange={(value) => {
								const option = action.options?.find((o) => o.value === value);
								option?.onClick(items, value);
							}}
						>
							<Select.Trigger class="h-8">
								{action.label}
							</Select.Trigger>
							<Select.Content>
								{#each action.options as option (option.value)}
									<Select.Item value={option.value}>{option.label}</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					{/if}
				{/each}
			</div>

			<Separator orientation="vertical" class="h-6" />

			<Button
				variant="ghost"
				size="icon"
				class="size-7 rounded-full"
				onclick={onClear}
				title="Clear selection"
			>
				<XIcon />
			</Button>
		</div>
	</div>
{/if}
