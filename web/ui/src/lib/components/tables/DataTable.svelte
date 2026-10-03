<script lang="ts" generics="TData extends RowData">
	import { untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Empty from '#lib/components/ext/empty/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import * as TableUI from '#lib/components/ui/table/index.js';
	import { PAGE_PARAM, SHEET_PARAMS, usePagination } from '#lib/hooks/index.js';
	import {
		ArrowDown,
		ArrowUp,
		ChevronLeft,
		ChevronRight,
		ChevronsLeft,
		ChevronsRight,
		ChevronsUpDown,
		FilterX,
		SearchXIcon,
		type LucideIcon
	} from '@lucide/svelte';
	import {
		FlexRender,
		renderComponent,
		type ColumnDef,
		type ColumnVisibilityState,
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
		/** Set for server-side pagination, the query then reads `usePagination().args`. */
		rowCount?: number;
		isLoading?: boolean;
		emptyState?: {
			icon: LucideIcon;
			title: string;
			description: string;
			/** CLI hint, shown as a shell prompt. */
			command?: string;
		};
		toolbar?: Snippet<[Table<DataTableFeatures, TData>]>;
		/** Makes rows clickable, usually to open the entity sheet. */
		onRowClick?: (row: TData) => void;
	};

	let {
		data = [],
		columns,
		bulkActions,
		enableRowSelection,
		rowCount,
		isLoading = false,
		emptyState = {
			icon: SearchXIcon,
			title: 'Nothing here yet',
			description: 'No rows to show.'
		},
		toolbar,
		onRowClick
	}: DataTableProps<TData> = $props();

	// Clicks on controls inside a row keep their own behavior.
	const interactive =
		'button, a, input, label, [role="checkbox"], [role="combobox"], [role="menuitem"]';

	function rowClick(e: MouseEvent, row: TData) {
		if (!onRowClick || (e.target as HTMLElement).closest(interactive)) return;
		onRowClick(row);
	}

	function rowKey(e: KeyboardEvent, row: TData) {
		if (!onRowClick || e.target !== e.currentTarget || e.key !== 'Enter') return;
		onRowClick(row);
	}

	const hasSelection = $derived(enableRowSelection ?? (bulkActions && bulkActions.length > 0));

	const pageSizeOptions = [10, 15, 20, 30, 50, 100];
	const pager = usePagination();

	// Any query param besides paging and sheets is a search or filter from TableToolbar.
	const ownParams = [PAGE_PARAM, ...SHEET_PARAMS];
	const isFiltered = $derived(
		[...page.url.searchParams.keys()].some((k) => !ownParams.includes(k))
	);

	function clearFilters() {
		const url = new URL(page.url.href);
		const kept = new URLSearchParams();
		for (const key of SHEET_PARAMS) {
			const value = url.searchParams.get(key);
			if (value) kept.set(key, value);
		}
		url.search = kept.toString();
		void goto(url, { replace: true, reset: false });
	}

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
		// Index ids would move a selection onto another row after a delete.
		getRowId: (row, index) => (row as { id?: string }).id || String(index),
		get rowCount() {
			return rowCount;
		},
		get manualPagination() {
			return rowCount !== undefined;
		},
		get enableRowSelection() {
			return hasSelection;
		},
		onPaginationChange: (updater) => {
			const current = { pageIndex: pager.pageIndex, pageSize: pager.pageSize };
			const next = typeof updater === 'function' ? updater(current) : updater;
			pager.set(next.pageIndex, next.pageSize);
		},
		onColumnVisibilityChange: (updater) => {
			const next = typeof updater === 'function' ? updater(columnVisibility) : updater;
			columnVisibility = next;
			persistedVisibility.current = next;
		},
		state: {
			get pagination() {
				return { pageIndex: pager.pageIndex, pageSize: pager.pageSize };
			},
			get columnVisibility() {
				return columnVisibility;
			}
		}
	});

	const colSpan = $derived(table.getVisibleLeafColumns().length);
	const pageCount = $derived(table.getPageCount());
	const selectedCount = $derived(table.getFilteredSelectedRowModel().rows.length);
	const total = $derived(table.getRowCount());

	// Deleting the last row on the last page would strand the user on an empty page.
	$effect(() => {
		if (!isLoading && pageCount > 0 && pager.pageIndex >= pageCount) {
			untrack(() => pager.set(pageCount - 1));
		}
	});
</script>

<div class="flex min-w-0 flex-col gap-4">
	{#if toolbar}
		{@render toolbar(table)}
	{/if}

	{#if !isLoading && !data.length}
		<Empty.Root class="h-[25vh] rounded-xl border bg-card text-card-foreground">
			<Empty.Header>
				<Empty.Media variant="icon">
					{#if isFiltered}
						<FilterX />
					{:else}
						<emptyState.icon />
					{/if}
				</Empty.Media>
				<Empty.Title>{isFiltered ? 'No matches' : emptyState.title}</Empty.Title>
				<Empty.Description>
					{isFiltered ? 'Nothing matches the current search and filters.' : emptyState.description}
				</Empty.Description>
			</Empty.Header>
			{#if isFiltered}
				<Empty.Content>
					<Button variant="outline" size="sm" onclick={clearFilters}>Clear filters</Button>
				</Empty.Content>
			{:else if emptyState.command}
				<Empty.Content>
					<Empty.Command>{emptyState.command}</Empty.Command>
				</Empty.Content>
			{/if}
		</Empty.Root>
	{:else}
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
					{#if isLoading}
						{#each { length: 5 }, i (i)}
							<TableUI.Row>
								<TableUI.Cell colspan={colSpan}>
									<Skeleton class="h-6 w-full" />
								</TableUI.Cell>
							</TableUI.Row>
						{/each}
					{:else}
						{#each table.getRowModel().rows as row (row.id)}
							<TableUI.Row
								data-state={row.getIsSelected() && 'selected'}
								class={onRowClick ? 'cursor-pointer' : undefined}
								tabindex={onRowClick ? 0 : undefined}
								onclick={(e) => rowClick(e, row.original)}
								onkeydown={(e) => rowKey(e, row.original)}
							>
								{#each row.getVisibleCells() as cell (cell.id)}
									<TableUI.Cell>
										<FlexRender {cell} />
									</TableUI.Cell>
								{/each}
							</TableUI.Row>
						{:else}
							<TableUI.Row>
								<TableUI.Cell colspan={colSpan} class="h-24 text-center">No results.</TableUI.Cell>
							</TableUI.Row>
						{/each}
					{/if}
				</TableUI.Body>
			</TableUI.Root>

			{#if selectedCount > 0 && bulkActions && bulkActions.length > 0}
				<BulkActions
					items={table.getSelectedRowModel().rows.map((row) => row.original)}
					actions={bulkActions}
					count={{ selected: selectedCount, total: table.getFilteredRowModel().rows.length }}
					onClear={() => table.resetRowSelection()}
				/>
			{/if}
		</div>

		<div class="flex items-center justify-between px-2">
			<div class="flex-1 text-sm text-muted-foreground">
				{#if selectedCount > 0}
					{selectedCount} of {table.getFilteredRowModel().rows.length} row(s) selected.
				{:else if total > 0}
					{total} total
				{/if}
			</div>
			<div class="flex items-center gap-2">
				<div class="flex items-center gap-2">
					<p class="hidden text-sm font-medium sm:block">Rows per page</p>
					<Select.Root
						allowDeselect={false}
						type="single"
						value={`${pager.pageSize}`}
						onValueChange={(value) => table.setPageSize(Number(value))}
					>
						<Select.Trigger class="w-17.5" aria-label="Rows per page">
							{pager.pageSize}
						</Select.Trigger>
						<Select.Content side="top">
							<Select.Group>
								{#each pageSizeOptions as size (size)}
									<Select.Item value={size.toString()}>{size}</Select.Item>
								{/each}
							</Select.Group>
						</Select.Content>
					</Select.Root>
				</div>
				<div class="flex w-25 items-center justify-center text-sm font-medium">
					Page {pager.pageIndex + 1}
					{pageCount > 1 ? `of ${pageCount}` : ''}
				</div>
				<div class="flex items-center gap-2">
					<Button
						variant="outline"
						size="icon"
						class="hidden lg:flex"
						onclick={() => table.setPageIndex(0)}
						disabled={!table.getCanPreviousPage()}
					>
						<span class="sr-only">Go to first page</span>
						<ChevronsLeft />
					</Button>
					<Button
						variant="outline"
						size="icon"
						onclick={() => table.previousPage()}
						disabled={!table.getCanPreviousPage()}
					>
						<span class="sr-only">Go to previous page</span>
						<ChevronLeft />
					</Button>
					<Button
						variant="outline"
						size="icon"
						onclick={() => table.nextPage()}
						disabled={!table.getCanNextPage()}
					>
						<span class="sr-only">Go to next page</span>
						<ChevronRight />
					</Button>
					<Button
						variant="outline"
						size="icon"
						class="hidden lg:flex"
						onclick={() => table.setPageIndex(pageCount - 1)}
						disabled={!table.getCanNextPage()}
					>
						<span class="sr-only">Go to last page</span>
						<ChevronsRight />
					</Button>
				</div>
			</div>
		</div>
	{/if}
</div>
