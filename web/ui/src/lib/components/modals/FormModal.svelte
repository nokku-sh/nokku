<script lang="ts">
	import { Check, CircleX, LoaderCircle } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import type { LucideIcon } from '@lucide/svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog/';
	import type { SaveState } from '$lib/hooks';
	import { cn } from '$lib/utils';
	import { slide } from 'svelte/transition'; // 1. Import the slide transition

	interface Props {
		open?: boolean;
		title: string;
		description?: string;
		icon?: LucideIcon;
		/** When set, renders a submit footer (create flows). Omit for autosave forms. */
		onSubmit?: () => void | Promise<void>;
		submitLabel?: string;
		isLoading?: boolean;
		/** Inline autosave status shown when there is no submit button */
		saveState?: SaveState;
		classModal?: string;
		children: Snippet;
	}

	let {
		open = $bindable(false),
		title,
		description,
		icon: Icon,
		onSubmit,
		submitLabel = 'Create',
		isLoading = false,
		saveState = 'idle',
		classModal,
		children
	}: Props = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class={cn('no-scrollbar max-h-[95vh] overflow-y-auto', classModal)}>
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				{#if Icon}
					<span class="rounded-md bg-primary/10 p-1.5 text-primary">
						<Icon class="size-4" />
					</span>
				{/if}
				{title}
			</Dialog.Title>
			{#if description}
				<Dialog.Description>{description}</Dialog.Description>
			{/if}
		</Dialog.Header>

		<form
			onsubmit={(e) => {
				e.preventDefault();
				onSubmit?.();
			}}
		>
			<div class="space-y-4">{@render children()}</div>

			<!-- 2. Conditionally render with the slide transition -->
			{#if onSubmit || saveState !== 'idle'}
				<div transition:slide={{ duration: 100 }}>
					<Dialog.Footer class="mt-4">
						{#if onSubmit}
							<Button type="submit" disabled={isLoading}>
								{#if isLoading}
									<LoaderCircle class="animate-spin" />
								{/if}
								{submitLabel}
							</Button>
						{:else}
							<p
								class="flex items-center gap-1.5 text-xs transition-colors
									{saveState === 'saved'
									? 'text-emerald-500'
									: saveState === 'error'
										? 'text-destructive'
										: 'text-muted-foreground'}"
								role="status"
							>
								{#if saveState === 'saving'}
									<LoaderCircle class="size-3 animate-spin" />
									Saving&hellip;
								{:else if saveState === 'saved'}
									<Check class="size-3" />
									Saved
								{:else if saveState === 'error'}
									<CircleX class="size-3" />
									Save failed
								{/if}
							</p>
						{/if}
					</Dialog.Footer>
				</div>
			{/if}
		</form>
	</Dialog.Content>
</Dialog.Root>
