<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Field from '$lib/components/ui/field';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { TriangleAlert } from '@lucide/svelte';

	type Props = {
		open?: boolean;
		title?: string;
		description?: string;
		itemName?: string;
		submitText?: string;
		confirmationText?: string;
		requireConfirmation?: boolean;
		requireTyping?: boolean;
		onConfirm?: () => void;
	};

	let {
		open = $bindable(false),
		title = 'Confirm Deletion',
		description = 'This action cannot be undone. This will permanently delete the item.',
		itemName,
		submitText = 'Delete',
		confirmationText = $bindable(''),
		requireConfirmation = false,
		requireTyping = false,
		onConfirm
	}: Props = $props();

	let isDeleting = $state(false);

	const canConfirm = $derived(!requireConfirmation || confirmationText === itemName);

	function handleConfirm() {
		if (!canConfirm) return;

		isDeleting = true;
		try {
			onConfirm?.();
			open = false;
			confirmationText = '';
		} finally {
			isDeleting = false;
		}
	}

	$effect(() => {
		if (open) confirmationText = '';
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="z-100 no-scrollbar max-h-[95vh] overflow-y-auto">
		<Field.Set>
			<Field.Legend class="flex items-center gap-2">
				<TriangleAlert size={20} />
				{title}
			</Field.Legend>
			<Field.Description>{description}</Field.Description>

			{#if requireConfirmation && itemName}
				<Field.Group>
					<Field.Field>
						<Field.Label for="confirmation">
							Type <button
								class="font-mono font-semibold select-all"
								tabindex="-1"
								onmouseup={(e) => e.stopPropagation()}
								onclick={(e) => e.preventDefault()}>{itemName}</button
							> to confirm
						</Field.Label>
						<Field.Content>
							<Input
								id="confirmation"
								bind:value={confirmationText}
								placeholder={itemName}
								disabled={isDeleting}
							/>
						</Field.Content>
					</Field.Field>
				</Field.Group>
			{/if}
			{#if requireTyping}
				<Field.Group>
					<Field.Field>
						<Field.Label for="confirmation">
							{itemName}
						</Field.Label>
						<Field.Content>
							<Input
								id="confirmation"
								bind:value={confirmationText}
								placeholder={itemName}
								disabled={isDeleting}
							/>
						</Field.Content>
					</Field.Field>
				</Field.Group>
			{/if}

			<Field.Field>
				<Button variant="destructive" class="w-full" disabled={isDeleting} onclick={handleConfirm}>
					{submitText}
				</Button>
			</Field.Field>
		</Field.Set>
	</Dialog.Content>
</Dialog.Root>
