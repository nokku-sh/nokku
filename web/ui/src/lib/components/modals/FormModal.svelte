<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog/';
	import * as Field from '$lib/components/ui/field';
	import { cn } from '$lib/utils';
	import type { Snippet } from 'svelte';

	interface Props {
		open?: boolean;
		title: string;
		description?: string;
		onSubmit?: () => void | Promise<void>;
		submitLabel?: string;
		isLoading?: boolean;
		classModal?: string;
		children: Snippet;
	}

	let {
		open = $bindable(false),
		title,
		description,
		onSubmit,
		submitLabel = 'Submit',
		isLoading = false,
		classModal,
		children
	}: Props = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class={cn('no-scrollbar max-h-[95vh] overflow-y-auto', classModal)}>
		<Dialog.Title class="sr-only">{title}</Dialog.Title>
		<form
			onsubmit={(e) => {
				e.preventDefault();
				onSubmit?.();
			}}
		>
			<Field.Set>
				<Field.Legend>{title}</Field.Legend>
				{#if description}
					<Field.Description>{description}</Field.Description>
				{/if}

				<Field.Group>
					{@render children()}
				</Field.Group>

				{#if onSubmit}
					<Field.Field>
						<Button type="submit" class="w-full" disabled={isLoading}>
							{submitLabel}
						</Button>
					</Field.Field>
				{/if}
			</Field.Set>
		</form>
	</Dialog.Content>
</Dialog.Root>
