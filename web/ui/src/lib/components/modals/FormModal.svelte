<script lang="ts">
	import { Check, CircleX } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import type { LucideIcon } from '@lucide/svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog/';
	import * as Field from '$lib/components/ui/field';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { SaveState } from '$lib/hooks';
	import { cn } from '$lib/utils';
	import { slide } from 'svelte/transition';

	interface Props {
		open?: boolean;
		title: string;
		description?: string;
		icon?: LucideIcon;
		/**
		 * Renders a submit footer (create flows). Return the mutateAsync promise,
		 * the modal closes when it resolves and stays open with the input if it
		 * throws. Omit for autosave forms.
		 */
		onSubmit?: () => unknown;
		submitLabel?: string;
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
		saveState = 'idle',
		classModal,
		children
	}: Props = $props();

	let submitting = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!onSubmit || submitting) return;
		submitting = true;
		try {
			await onSubmit();
			open = false;
		} catch {
			// The global mutation handler already toasted it.
		} finally {
			submitting = false;
		}
	}
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

		<form onsubmit={submit}>
			<Field.Group>{@render children()}</Field.Group>

			{#if onSubmit || saveState !== 'idle'}
				<div transition:slide={{ duration: 100 }}>
					<Dialog.Footer class="mt-4">
						{#if onSubmit}
							<Button type="submit" disabled={submitting}>
								{#if submitting}
									<Spinner data-icon="inline-start" />
								{/if}
								{submitLabel}
							</Button>
						{:else}
							<p
								class={cn(
									'flex items-center gap-1.5 text-xs text-muted-foreground transition-colors',
									saveState === 'saved' && 'text-success',
									saveState === 'error' && 'text-destructive'
								)}
								role="status"
							>
								{#if saveState === 'saving'}
									<Spinner class="size-3" />
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
