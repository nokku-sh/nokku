<script lang="ts" module>
	export type ActionItem = {
		label?: string;
		icon?: LucideIcon;
		onClick: () => void;
		disabled?: boolean;
		isDestructive?: boolean;
	};

	export type InlineAction = ActionItem & {
		variant?: 'default' | 'secondary' | 'outline' | 'ghost' | 'destructive';
	};
</script>

<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Ellipsis, Trash2, type LucideIcon } from '@lucide/svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import * as ButtonGroup from '$lib/components/ui/button-group/index.js';

	type Props = {
		// Buttons that sit right in the table cell for quick access (e.g., Approve/Reject)
		inlineActions?: InlineAction[];

		// Actions tucked away inside the "..." dropdown (e.g., View, Edit, Duplicate)
		menuActions?: ActionItem[];

		// Special config just for deletion to automatically wire up your modal
		deleteConfig?: {
			onDelete: () => void;
			itemName?: string;
			title?: string;
			description?: string;
			requireTyping?: boolean;
		};
	};

	let { inlineActions = [], menuActions = [], deleteConfig }: Props = $props();

	let showDeleteDialog = $state(false);
	let hasDropdownActions = $derived(menuActions.length > 0 || !!deleteConfig);
</script>

<div class="flex items-center justify-end gap-2">
	<!-- Render Quick Inline Actions -->
	{#if inlineActions.length > 0}
		<ButtonGroup.Root>
			{#each inlineActions as action}
				<Button
					variant={action.variant || 'secondary'}
					size={action.label ? 'sm' : 'icon-sm'}
					disabled={action.disabled}
					onclick={action.onClick}
				>
					{#if action.icon}
						<action.icon class="size-3.5" />
					{/if}
					{#if action.label}
						{action.label}
					{/if}
				</Button>
			{/each}
		</ButtonGroup.Root>
	{/if}

	<!-- Render Dropdown Menu for Secondary Actions -->
	{#if hasDropdownActions}
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				<!-- Sneaky Shadcn trick: child snippet avoids button nesting issues -->
				{#snippet child({ props })}
					<Button {...props} variant="ghost" size="icon-sm">
						<span class="sr-only">Open menu</span>
						<Ellipsis class="size-4" />
					</Button>
				{/snippet}
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="end" class="w-48">
				<!-- Custom Menu Items -->
				{#each menuActions as action}
					<DropdownMenu.Item
						onclick={action.onClick}
						disabled={action.disabled}
						class={action.isDestructive
							? 'text-destructive focus:bg-destructive/10 focus:text-destructive'
							: ''}
					>
						{#if action.icon}
							<action.icon class="size-3.5" />
						{/if}
						{#if action.label}
							{action.label}
						{/if}
					</DropdownMenu.Item>
				{/each}

				<!-- Integrated Delete Action -->
				{#if deleteConfig}
					{#if menuActions.length > 0}
						<DropdownMenu.Separator />
					{/if}
					<DropdownMenu.Item
						onclick={() => (showDeleteDialog = true)}
						class="text-destructive focus:bg-destructive/10 focus:text-destructive"
					>
						<Trash2 class="size-3.5" />
						Delete
					</DropdownMenu.Item>
				{/if}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	{/if}
</div>

<!-- Render Modal outside the flex container so layout isn't affected -->
{#if deleteConfig}
	<DeleteConfirmationModal
		bind:open={showDeleteDialog}
		title={deleteConfig.title}
		description={deleteConfig.description}
		itemName={deleteConfig.itemName}
		requireConfirmation={deleteConfig.requireTyping}
		onConfirm={() => {
			deleteConfig.onDelete();
			showDeleteDialog = false;
		}}
	/>
{/if}
