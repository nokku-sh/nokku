<script lang="ts" generics="TData extends RowData">
	import Settings2Icon from '@lucide/svelte/icons/settings-2';
	import type { RowData, Table } from '@tanstack/svelte-table';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import type { DataTableFeatures } from './data-table-features.js';

	let { table }: { table: Table<DataTableFeatures, TData> } = $props();
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger
		class={buttonVariants({
			variant: 'outline',
			size: 'sm',
			class: 'h-8 rounded-full border-dashed'
		})}
		aria-label="Choose columns"
	>
		<Settings2Icon />
		<span class="hidden sm:inline">View</span>
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end" class="w-48">
		<DropdownMenu.Group>
			<DropdownMenu.Label>Columns</DropdownMenu.Label>
			{#each table
				.getAllColumns()
				.filter((col) => typeof col.accessorFn !== 'undefined' && col.getCanHide() && !['id', 'userId'].includes(col.id)) as column (column)}
				{@const header = column.columnDef.header}
				<DropdownMenu.CheckboxItem
					bind:checked={() => column.getIsVisible(), (v) => column.toggleVisibility(!!v)}
					closeOnSelect={false}
				>
					{typeof header === 'string' ? header : column.id}
				</DropdownMenu.CheckboxItem>
			{/each}
		</DropdownMenu.Group>
	</DropdownMenu.Content>
</DropdownMenu.Root>
