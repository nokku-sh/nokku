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
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Ellipsis, Hash, Link, Trash2, type LucideIcon } from '@lucide/svelte';
	import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
	import { confirm, sheetLink } from '#lib/hooks/index.js';
	import { toast } from 'svelte-sonner';

	type Props = {
		/** Names the row, so the menu button says whose actions it holds. */
		label?: string;
		/** Adds Copy ID to the menu, in the same spot on every table. */
		id?: string;
		/** Also adds Copy link, for rows that open a sheet from `?id=`. */
		link?: boolean;
		inlineActions?: InlineAction[];

		menuActions?: ActionItem[];

		deleteConfig?: {
			/** Return the mutateAsync promise so the dialog waits for it. */
			onDelete: () => unknown;
			itemName?: string;
			title?: string;
			description?: string;
			confirmText?: string;
			/** Asks the user to type this first, for deletes that are hard to undo. */
			typeToConfirm?: string;
		};
	};

	let {
		label,
		id,
		link = false,
		inlineActions = [],
		menuActions = [],
		deleteConfig
	}: Props = $props();

	const hasDropdownActions = $derived(menuActions.length > 0 || !!deleteConfig || !!id);

	async function copy(text: string, what: string) {
		await navigator.clipboard.writeText(text);
		toast.success(`${what} copied`);
	}

	function askDelete() {
		if (!deleteConfig) return;
		void confirm({
			title: deleteConfig.title ?? `Delete ${deleteConfig.itemName ?? 'item'}?`,
			description: deleteConfig.description ?? 'This action cannot be undone.',
			confirmText: deleteConfig.confirmText,
			typeToConfirm: deleteConfig.typeToConfirm,
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
						<span class="sr-only">{label ? `Actions for ${label}` : 'More actions'}</span>
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

				{#if id}
					{#if menuActions.length > 0}
						<DropdownMenu.Separator />
					{/if}
					<DropdownMenu.Group>
						<DropdownMenu.Item onclick={() => copy(id, 'ID')}>
							<Hash />
							Copy ID
						</DropdownMenu.Item>
						{#if link}
							<DropdownMenu.Item onclick={() => copy(sheetLink(id), 'Link')}>
								<Link />
								Copy link
							</DropdownMenu.Item>
						{/if}
					</DropdownMenu.Group>
				{/if}

				{#if deleteConfig}
					{#if menuActions.length > 0 || id}
						<DropdownMenu.Separator />
					{/if}
					<DropdownMenu.Group>
						<DropdownMenu.Item onclick={askDelete} variant="destructive">
							<Trash2 />
							{deleteConfig.confirmText ?? 'Delete'}
						</DropdownMenu.Item>
					</DropdownMenu.Group>
				{/if}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	{/if}
</div>
