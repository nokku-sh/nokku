<script lang="ts" generics="T">
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
	<!-- Sticks to the bottom of the content column while the list scrolls under it. -->
	<div class="sticky bottom-4 z-20 flex justify-center" transition:slide={{ duration: 200 }}>
		<div
			class="flex max-w-full items-center gap-2 rounded-full border bg-popover py-1.5 pr-1.5 pl-4 text-popover-foreground"
			role="region"
			aria-label="Selection"
		>
			<span class="shrink-0 text-sm whitespace-nowrap tabular-nums">
				<span class="font-semibold">{count.selected}</span>
				<span class="text-muted-foreground">of {count.total} selected</span>
			</span>

			<Separator orientation="vertical" class="mx-1 h-5" />

			<div class="no-scrollbar flex min-w-0 items-center gap-1 overflow-x-auto">
				{#each actions as action (action.label)}
					<Button
						variant={action.variant ?? 'ghost'}
						size="sm"
						class={action.class}
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

			<Button
				variant="ghost"
				size="icon-sm"
				class="shrink-0 rounded-full"
				aria-label="Clear selection"
				onclick={onClear}
			>
				<XIcon />
			</Button>
		</div>
	</div>
{/if}
