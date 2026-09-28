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
	import * as ButtonGroup from '$lib/components/ui/button-group/index.js';
	import { confirm } from '$lib/hooks';

	type Props = {
		inlineActions?: InlineAction[];

		menuActions?: ActionItem[];

		deleteConfig?: {
			/** Return the mutateAsync promise so the dialog waits for it. */
			onDelete: () => unknown;
			itemName?: string;
			title?: string;
			description?: string;
			requireTyping?: boolean;
		};
	};

	let { inlineActions = [], menuActions = [], deleteConfig }: Props = $props();

	const hasDropdownActions = $derived(menuActions.length > 0 || !!deleteConfig);

	function askDelete() {
		if (!deleteConfig) return;
		void confirm({
			title: deleteConfig.title ?? `Delete ${deleteConfig.itemName ?? 'item'}?`,
			description: deleteConfig.description ?? 'This action cannot be undone.',
			typeToConfirm: deleteConfig.requireTyping ? deleteConfig.itemName : undefined,
			onConfirm: deleteConfig.onDelete
		});
	}
</script>

<div class="flex items-center justify-end gap-2">
	{#if inlineActions.length > 0}
		<ButtonGroup.Root>
			{#each inlineActions as action, i (i)}
				<Button
					variant={action.variant || 'secondary'}
					size={action.label ? 'sm' : 'icon-sm'}
					disabled={action.disabled}
					onclick={action.onClick}
				>
					{#if action.icon}
						<action.icon data-icon={action.label ? 'inline-start' : undefined} />
					{/if}
					{#if action.label}
						{action.label}
					{/if}
				</Button>
			{/each}
		</ButtonGroup.Root>
	{/if}

	{#if hasDropdownActions}
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				<!-- The child snippet avoids nesting buttons. -->
				{#snippet child({ props })}
					<Button {...props} variant="ghost" size="icon-sm">
						<span class="sr-only">Open menu</span>
						<Ellipsis />
					</Button>
				{/snippet}
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="end" class="w-48">
				{#if menuActions.length > 0}
					<DropdownMenu.Group>
						{#each menuActions as action, i (i)}
							<DropdownMenu.Item
								onclick={action.onClick}
								disabled={action.disabled}
								variant={action.isDestructive ? 'destructive' : 'default'}
							>
								{#if action.icon}
									<action.icon />
								{/if}
								{#if action.label}
									{action.label}
								{/if}
							</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Group>
				{/if}

				{#if deleteConfig}
					{#if menuActions.length > 0}
						<DropdownMenu.Separator />
					{/if}
					<DropdownMenu.Group>
						<DropdownMenu.Item onclick={askDelete} variant="destructive">
							<Trash2 />
							Delete
						</DropdownMenu.Item>
					</DropdownMenu.Group>
				{/if}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	{/if}
</div>
