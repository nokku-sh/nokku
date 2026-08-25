<script lang="ts" generics="TData extends RowData">
	import { untrack } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import Checkbox from '$lib/components/ui/checkbox/checkbox.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import * as Select from '$lib/components/ui/select/index.js';
	import * as TableUI from '$lib/components/ui/table/index.js';
	import { pageIndex, pageSize } from '$lib/store.svelte';
	import {
		ArrowDown,
		ArrowUp,
		ChevronLeft,
		ChevronRight,
		ChevronsLeft,
		ChevronsRight,
		ChevronsUpDown,
		SearchXIcon,
		type LucideIcon
	} from '@lucide/svelte';
	import {
		FlexRender,
		renderComponent,
		type ColumnDef,
		type ColumnVisibilityState,
		type PaginationState,
		type RowData,
		type Table
	} from '@tanstack/svelte-table';
	import type { Snippet } from 'svelte';
	import { PersistedState } from 'runed';
	import BulkActions from './BulkActions.svelte';
	import type { BulkAction } from './types';
	import type { DataTableFeatures } from './data-table-features.js';
	import { createAppTable } from './data-table.js';

	type DataTableProps<TData extends RowData> = {
		data?: TData[];
		columns: ColumnDef<DataTableFeatures, TData>[];
		bulkActions?: BulkAction<TData>[] | undefined;
		enableRowSelection?: boolean;
		rowCount?: number;
		emptyState?: {
			icon: LucideIcon;
			title: string;
			description: string;
		};
		toolbar?: Snippet<[Table<DataTableFeatures, TData>]>;
	};

	let {
		data = [],
		columns,
		bulkActions,
		enableRowSelection,
		rowCount,
		emptyState = {
			icon: SearchXIcon,
			title: 'No Data',
			description: 'No data found'
		},
		toolbar
	}: DataTableProps<TData> = $props();

	const hasSelection = $derived(enableRowSelection ?? (bulkActions && bulkActions.length > 0));

	// Pagination
	const pageSizeOptions = [2, 10, 15, 20, 30, 50];
	let pagination = $state<PaginationState>({
		pageIndex: 0,
		pageSize: pageSize.current
	});
	const defaultVisibility: ColumnVisibilityState = {
		id: false,
		userId: false,
		updatedAt: false,
		createdAt: false
	};
	const visibilityKey = untrack(
		() =>
			`nokku:columns:${columns
				.map((c) => ('accessorKey' in c ? c.accessorKey : c.id))
				.filter(Boolean)
				.join(':')}`
	);
	const persistedVisibility = new PersistedState<ColumnVisibilityState>(
		visibilityKey,
		defaultVisibility
	);
	let columnVisibility = $state<ColumnVisibilityState>(persistedVisibility.current);

	// Table
	const table = createAppTable<TData>({
		get data() {
			return data;
		},
		get columns() {
			return [
				...(hasSelection
					? [
							{
								id: 'select',
								header: ({ table }) =>
									renderComponent(Checkbox, {
										checked: table.getIsAllPageRowsSelected(),
										onCheckedChange: (value: boolean) => table.toggleAllPageRowsSelected(!!value),
										indeterminate:
											table.getIsSomePageRowsSelected() && !table.getIsAllPageRowsSelected(),
										'aria-label': 'Select all'
									}),
								cell: ({ row }) =>
									renderComponent(Checkbox, {
										checked: row.getIsSelected(),
										onCheckedChange: (value: boolean) => row.toggleSelected(!!value),
										'aria-label': 'Select row'
									}),
								enableSorting: false,
								enableHiding: false
							} as ColumnDef<DataTableFeatures, TData>
						]
					: []),
				...columns
			];
		},
		get rowCount() {
			if (rowCount) return rowCount;
		},
		get manualPagination() {
			return !!rowCount;
		},
		get enableRowSelection() {
			return hasSelection;
		},
		onPaginationChange: (updater) => {
			if (typeof updater === 'function') {
				pagination = updater(pagination);
			} else {
				pagination = updater;
			}
			pageSize.current = pagination.pageSize;
			pageIndex.current = pagination.pageIndex;
		},
		onColumnVisibilityChange: (updater) => {
			const next = typeof updater === 'function' ? updater(columnVisibility) : updater;
			columnVisibility = next;
			persistedVisibility.current = next;
		},
		state: {
			get pagination() {
				return pagination;
			},
			get columnVisibility() {
				return columnVisibility;
			}
		}
	});

	const paginationState = $derived(table.atoms.pagination.get());
</script>

{#if toolbar}
	{@render toolbar(table)}
{/if}

{#if !data.length}
	<Empty.Root class="h-[25vh] rounded-xl border bg-card text-card-foreground shadow-sm">
		<Empty.Header>
			<Empty.Media variant="icon">
				<emptyState.icon />
			</Empty.Media>
			<Empty.Title>{emptyState.title}</Empty.Title>
			<Empty.Description>
				{emptyState.description}
			</Empty.Description>
		</Empty.Header>
	</Empty.Root>
{:else}
	<!-- Table -->
	<div class="overflow-hidden rounded-md border">
		<TableUI.Root>
			<TableUI.Header>
				{#each table.getHeaderGroups() as headerGroup (headerGroup.id)}
					<TableUI.Row>
						{#each headerGroup.headers as header (header.id)}
							<TableUI.Head colspan={header.colSpan}>
								{#if !header.isPlaceholder}
									<Button
										variant="ghost"
										size="sm"
										class="-ml-3 h-8 data-[state=open]:bg-accent"
										data-sortable={header.column.getCanSort()}
										onclick={() => header.column.toggleSorting()}
									>
										<FlexRender {header} />
										{#if header.column.getCanSort()}
											{#if header.column.getIsSorted() === 'asc'}
												<ArrowUp />
											{:else if header.column.getIsSorted() === 'desc'}
												<ArrowDown />
											{:else}
												<ChevronsUpDown />
											{/if}
										{/if}
									</Button>
								{/if}
							</TableUI.Head>
						{/each}
					</TableUI.Row>
				{/each}
			</TableUI.Header>
			<TableUI.Body>
				{#each table.getRowModel().rows as row (row.id)}
					<TableUI.Row data-state={row.getIsSelected() && 'selected'}>
						{#each row.getVisibleCells() as cell (cell.id)}
							<TableUI.Cell>
								<FlexRender {cell} />
							</TableUI.Cell>
						{/each}
					</TableUI.Row>
				{:else}
					<TableUI.Row>
						<TableUI.Cell colspan={columns.length} class="h-24 text-center"
							>No results.</TableUI.Cell
						>
					</TableUI.Row>
				{/each}
			</TableUI.Body>
			{#if table.getRowCount() > 0}
				<TableUI.Footer>
					<TableUI.Row>
						<TableUI.Cell colspan={columns.length}>Total</TableUI.Cell>
						<TableUI.Cell class="text-right">{table.getRowCount()}</TableUI.Cell>
					</TableUI.Row>
				</TableUI.Footer>
			{/if}
		</TableUI.Root>

		{#if table.getSelectedRowModel().rows.length > 0 && bulkActions && bulkActions.length > 0}
			<BulkActions
				items={table.getSelectedRowModel().rows.map((row) => row.original)}
				actions={bulkActions}
				count={{
					selected: table.getFilteredSelectedRowModel().rows.length,
					total: table.getFilteredRowModel().rows.length
				}}
				onClear={() => table.resetRowSelection()}
			/>
		{/if}
	</div>

	<!-- Pagination -->
	<div class="flex items-center justify-between px-2">
		<div class="flex-1 text-sm text-muted-foreground">
			{#if table.getFilteredSelectedRowModel().rows.length > 0}
				{table.getFilteredSelectedRowModel().rows.length} of
				{table.getFilteredRowModel().rows.length} row(s) selected.
			{/if}
		</div>
		<div class="flex items-center gap-2">
			<div class="flex items-center gap-2">
				<p class="text-sm font-medium">Rows per page</p>
				<Select.Root
					allowDeselect={false}
					type="single"
					value={`${paginationState.pageSize}`}
					onValueChange={(value) => {
						table.setPageSize(Number(value));
						pageSize.current = Number(value);
					}}
				>
					<Select.Trigger class="h-8 w-17.5">
						{String(paginationState.pageSize)}
					</Select.Trigger>
					<Select.Content side="top">
						{#each pageSizeOptions as size (size)}
							<Select.Item value={size.toString()}>{size}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			<div class="flex w-25 items-center justify-center text-sm font-medium">
				Page {paginationState.pageIndex + 1}
				{table.getPageCount() > 1 ? `of ${table.getPageCount()}` : ''}
			</div>
			<div class="flex items-center gap-2">
				<Button
					variant="outline"
					class="hidden size-8 p-0 lg:flex"
					onclick={() => table.setPageIndex(0)}
					disabled={!table.getCanPreviousPage()}
				>
					<span class="sr-only">Go to first page</span>
					<ChevronsLeft />
				</Button>
				<Button
					variant="outline"
					class="size-8 p-0"
					onclick={() => table.previousPage()}
					disabled={!table.getCanPreviousPage()}
				>
					<span class="sr-only">Go to previous page</span>
					<ChevronLeft />
				</Button>
				<Button
					variant="outline"
					class="size-8 p-0"
					onclick={() => table.nextPage()}
					disabled={!table.getCanNextPage()}
				>
					<span class="sr-only">Go to next page</span>
					<ChevronRight />
				</Button>
				<Button
					variant="outline"
					class="hidden size-8 p-0 lg:flex"
					onclick={() => table.setPageIndex(table.getPageCount() - 1)}
					disabled={!table.getCanNextPage() || table.getPageCount() === 1}
				>
					<span class="sr-only">Go to last page</span>
					<ChevronsRight />
				</Button>
			</div>
		</div>
	</div>
{/if}
