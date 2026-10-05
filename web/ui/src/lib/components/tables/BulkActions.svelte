<script lang="ts" generics="T">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Separator } from '#lib/components/ui/separator/index.js';
	import { XIcon } from '@lucide/svelte';
	import { slide } from 'svelte/transition';
	import { confirm } from '#lib/hooks/index.js';
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

	// A cancelled confirm keeps the selection, so the user can try again.
	async function run(action: BulkAction<T>) {
		if (action.confirm) {
			const ok = await confirm({
				confirmText: action.label,
				...action.confirm(items),
				onConfirm: () => action.onClick?.(items)
			});
			if (ok) onClear?.();
			return;
		}
		await action.onClick?.(items);
		onClear?.();
	}
</script>

{#if count.selected > 0}
	<div
		class="fixed inset-x-0 bottom-16 z-50 flex justify-center px-4"
		transition:slide={{ duration: 200 }}
	>
		<div
			class="flex items-center gap-3 rounded-full border bg-background/95 px-4 py-2 backdrop-blur supports-backdrop-filter:bg-background/80"
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
					<Button
						variant={action.variant ?? 'ghost'}
						size="sm"
						class="h-8 {action.class ?? ''}"
						onclick={() => run(action)}
						disabled={action.disabled}
					>
						{#if action.icon}
							<action.icon data-icon="inline-start" />
						{/if}
						{action.label}
					</Button>
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
