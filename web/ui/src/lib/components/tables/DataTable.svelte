<script lang="ts" generics="TData, TValue">
	import { untrack } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import Checkbox from '$lib/components/ui/checkbox/checkbox.svelte';
	import {
		createSvelteTable,
		FlexRender,
		renderComponent
	} from '$lib/components/ui/data-table/index.js';
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
		type IconProps
	} from '@lucide/svelte';
	import {
		getCoreRowModel,
		getFilteredRowModel,
		getPaginationRowModel,
		getSortedRowModel,
		type ColumnDef,
		type ColumnFiltersState,
		type PaginationState,
		type RowSelectionState,
		type SortingState,
		type Table,
		type VisibilityState
	} from '@tanstack/table-core';
	import type { Component } from 'svelte';
	import { PersistedState } from 'runed';
	import BulkActions from './BulkActions.svelte';
	import type { BulkAction } from './types';

	type IconComponent = Component<IconProps, Record<string, never>, ''>;

	type DataTableProps<TData, TValue> = {
		data?: TData[];
		columns: ColumnDef<TData, TValue>[];
		bulkActions?: BulkAction<TData>[] | undefined;
		rowCount?: number;
		emptyState?: {
			icon: IconComponent;
			title: string;
			description: string;
		};
		onTableReady?: (table: Table<TData>) => void;
	};

	let {
		data = [],
		columns,
		bulkActions,
		rowCount,
		emptyState = {
			icon: SearchXIcon,
			title: 'No Data',
			description: 'No data found'
		},
		onTableReady
	}: DataTableProps<TData, TValue> = $props();

	// Pagination
	const pageSizeOptions = [2, 10, 15, 20, 30, 50];
	let pagination = $state<PaginationState>({
		pageIndex: 0,
		pageSize: pageSize.current
	});
	let sorting = $state<SortingState>([]);
	let columnFilters = $derived<ColumnFiltersState>([]);
	const defaultVisibility: VisibilityState = {
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
	const persistedVisibility = new PersistedState<VisibilityState>(visibilityKey, defaultVisibility);
	let columnVisibility = $state<VisibilityState>(persistedVisibility.current);
	let rowSelection = $state<RowSelectionState>({});
	let globalFilter = $state<string>('');

	// Table
	const table = createSvelteTable({
		get data() {
			return data;
		},
		get columns() {
			return [
				{
					id: 'select',
					header: ({ table }: { table: any }) =>
						renderComponent(Checkbox, {
							checked: table.getIsAllPageRowsSelected(),
							onCheckedChange: (value) => table.toggleAllPageRowsSelected(value),
							indeterminate: table.getIsSomePageRowsSelected() && !table.getIsAllPageRowsSelected(),
							'aria-label': 'Select all'
						}),
					cell: ({ row }: { row: any }) =>
						renderComponent(Checkbox, {
							checked: row.getIsSelected(),
							onCheckedChange: (value) => row.toggleSelected(value),
							'aria-label': 'Select row'
						}),
					enableSorting: false,
					enableHiding: false,
					enableGlobalFilter: false
				},
				...columns
			];
		},
		get rowCount() {
			if (rowCount) return rowCount;
		},
		get manualPagination() {
			return !!rowCount;
		},
		globalFilterFn: 'includesString',
		getCoreRowModel: getCoreRowModel(),
		getPaginationRowModel: getPaginationRowModel(),
		getSortedRowModel: getSortedRowModel(),
		getFilteredRowModel: getFilteredRowModel(),
		onPaginationChange: (updater) => {
			if (typeof updater === 'function') {
				pagination = updater(pagination);
			} else {
				pagination = updater;
			}
			pageSize.current = pagination.pageSize;
			pageIndex.current = pagination.pageIndex;
		},
		onSortingChange: (updater) => {
			if (typeof updater === 'function') {
				sorting = updater(sorting);
			} else {
				sorting = updater;
			}
		},
		onColumnFiltersChange: (updater) => {
			if (typeof updater === 'function') {
				columnFilters = updater(columnFilters);
			} else {
				columnFilters = updater;
			}
		},
		onColumnVisibilityChange: (updater) => {
			const next = typeof updater === 'function' ? updater(columnVisibility) : updater;
			columnVisibility = next;
			if (persistedVisibility) persistedVisibility.current = next;
		},
		onRowSelectionChange: (updater) => {
			if (typeof updater === 'function') {
				rowSelection = updater(rowSelection);
			} else {
				rowSelection = updater;
			}
		},
		onGlobalFilterChange: (updater) => {
			if (typeof updater === 'function') {
				globalFilter = updater(globalFilter);
			} else {
				globalFilter = updater;
			}
		},
		state: {
			get pagination() {
				return pagination;
			},
			get sorting() {
				return sorting;
			},
			get columnFilters() {
				return columnFilters;
			},
			get columnVisibility() {
				return columnVisibility;
			},
			get rowSelection() {
				return rowSelection;
			},
			get globalFilter() {
				return globalFilter;
			}
		}
	});

	$effect(() => {
		onTableReady?.(table);
	});
</script>

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
										<FlexRender
											content={header.column.columnDef.header}
											context={header.getContext()}
										/>
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
								<FlexRender content={cell.column.columnDef.cell} context={cell.getContext()} />
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
					value={`${table.getState().pagination.pageSize}`}
					onValueChange={(value) => {
						table.setPageSize(Number(value));
						pageSize.current = Number(value);
					}}
				>
					<Select.Trigger class="h-8 w-17.5">
						{String(table.getState().pagination.pageSize)}
					</Select.Trigger>
					<Select.Content side="top">
						{#each pageSizeOptions as size (size)}
							<Select.Item value={size.toString()}>{size}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			<div class="flex w-25 items-center justify-center text-sm font-medium">
				Page {table.getState().pagination.pageIndex + 1}
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
