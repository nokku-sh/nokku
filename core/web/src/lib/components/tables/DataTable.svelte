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
		CircleAlert,
		FilterX,
		RotateCw,
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
	import type { Attachment } from 'svelte/attachments';
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
		/** Set for server-side pagination, the query then reads `usePagination().args`. */
		rowCount?: number;
		isLoading?: boolean;
		/** A failed load. Without it a broken query would read as an empty list. */
		error?: Error | null;
		onRetry?: () => unknown;
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
		/** Names a row for screen readers, in its open action and its checkbox. */
		rowLabel?: (row: TData) => string;
	};

	let {
		data = [],
		columns,
		bulkActions,
		rowCount,
		isLoading = false,
		error,
		onRetry,
		emptyState = {
			icon: SearchXIcon,
			title: 'Nothing here yet',
			description: 'No rows to show.'
		},
		toolbar,
		onRowClick,
		rowLabel
	}: DataTableProps<TData> = $props();

	// Clicks on controls inside a row keep their own behavior.
	const interactive =
		'button, a, input, label, [role="checkbox"], [role="combobox"], [role="menuitem"]';

	function rowClick(e: MouseEvent, row: TData) {
		if (!onRowClick || (e.target as HTMLElement).closest(interactive)) return;
		onRowClick(row);
	}

	function rowKey(e: KeyboardEvent, row: TData) {
		if (!onRowClick || e.target !== e.currentTarget) return;
		const tr = e.currentTarget as HTMLElement;
		if (e.key === 'Enter') onRowClick(row);
		else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
			e.preventDefault();
			const next = e.key === 'ArrowDown' ? tr.nextElementSibling : tr.previousElementSibling;
			(next as HTMLElement | null)?.focus();
		}
	}

	const hidden = { md: 'hidden md:table-cell', lg: 'hidden lg:table-cell' };

	// A table wider than its column fades at the edge that still hides columns.
	const edgeFade: Attachment<HTMLElement> = (frame) => {
		const scroller = frame.querySelector<HTMLElement>('[data-slot="table-container"]');
		if (!scroller) return;
		const update = () => {
			const more = scroller.scrollWidth - scroller.clientWidth - scroller.scrollLeft > 1;
			frame.toggleAttribute('data-fade-end', more);
		};
		const ro = new ResizeObserver(update);
		ro.observe(scroller);
		scroller.addEventListener('scroll', update, { passive: true });
		update();
		return () => {
			ro.disconnect();
			scroller.removeEventListener('scroll', update);
		};
	};

	const hasSelection = $derived(!!bulkActions?.length);

	const pageSizeOptions = [10, 15, 20, 30, 50, 100];
	const pager = usePagination();

	// Any query param besides paging and sheets is a search or filter from TableToolbar.
	const ownParams = [PAGE_PARAM, ...SHEET_PARAMS];
	const isFiltered = $derived(
		[...page.url.searchParams.keys()].some((k) => !ownParams.includes(k))
	);

	// One empty state for three reasons: the load failed, the filters match nothing, or there is nothing yet.
	const blank = $derived(
		error
			? { icon: CircleAlert, title: "Couldn't load this list", description: error.message }
			: isFiltered
				? {
						icon: FilterX,
						title: 'No matches',
						description: 'Nothing matches the current search and filters.'
					}
				: emptyState
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
										'aria-label': rowLabel ? `Select ${rowLabel(row.original)}` : 'Select row'
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
		// The list RPCs take no order, so a sort would only shuffle the loaded page.
		get enableSorting() {
			return rowCount === undefined;
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

	{#if !data.length && (error || !isLoading)}
		<Empty.Root class="h-[25vh] rounded-xl border bg-card text-card-foreground">
			<Empty.Header>
				<Empty.Media variant="icon" class={error && 'bg-destructive/10 text-destructive'}>
					<blank.icon />
				</Empty.Media>
				<Empty.Title>{blank.title}</Empty.Title>
				<Empty.Description>{blank.description}</Empty.Description>
			</Empty.Header>
			{#if error && onRetry}
				<Empty.Content>
					<Button variant="outline" size="sm" onclick={onRetry}>
						<RotateCw data-icon="inline-start" />
						Try again
					</Button>
				</Empty.Content>
			{:else if !error && isFiltered}
				<Empty.Content>
					<Button variant="outline" size="sm" onclick={clearFilters}>Clear filters</Button>
				</Empty.Content>
			{:else if !error && emptyState.command}
				<Empty.Content>
					<Empty.Command>{emptyState.command}</Empty.Command>
				</Empty.Content>
			{/if}
		</Empty.Root>
	{:else}
		{#if error}
			<p class="flex items-center gap-2 text-sm text-destructive" role="alert">
				<CircleAlert class="size-4 shrink-0" />
				<span class="min-w-0">Couldn't refresh, showing the last loaded rows. {error.message}</span>
				{#if onRetry}
					<Button variant="ghost" size="sm" class="ml-auto" onclick={onRetry}>Try again</Button>
				{/if}
			</p>
		{/if}

		<div class="overflow-hidden rounded-xl border bg-card" {@attach edgeFade}>
			<TableUI.Root>
				<TableUI.Header>
					{#each table.getHeaderGroups() as headerGroup (headerGroup.id)}
						<TableUI.Row class="hover:bg-transparent">
							{#each headerGroup.headers as header (header.id)}
								{@const sorted = header.column.getIsSorted()}
								{@const below = header.column.columnDef.meta?.hideBelow}
								<TableUI.Head
									colspan={header.colSpan}
									class={below && hidden[below]}
									aria-sort={sorted ? (sorted === 'asc' ? 'ascending' : 'descending') : undefined}
								>
									{#if header.column.getCanSort()}
										<Button
											variant="ghost"
											size="sm"
											class="-ml-3 h-8"
											onclick={() => header.column.toggleSorting()}
										>
											<FlexRender {header} />
											{#if sorted === 'asc'}
												<ArrowUp />
											{:else if sorted === 'desc'}
												<ArrowDown />
											{:else}
												<ChevronsUpDown />
											{/if}
										</Button>
									{:else if !header.isPlaceholder}
										<FlexRender {header} />
									{/if}
								</TableUI.Head>
							{/each}
							{#if onRowClick}
								<TableUI.Head class="w-8"></TableUI.Head>
							{/if}
						</TableUI.Row>
					{/each}
				</TableUI.Header>
				<TableUI.Body>
					{#if isLoading}
						{#each { length: 5 }, i (i)}
							<TableUI.Row class="hover:bg-transparent">
								{#each table.getVisibleLeafColumns() as column (column.id)}
									{@const below = column.columnDef.meta?.hideBelow}
									<TableUI.Cell class={below && hidden[below]}>
										<Skeleton class={['h-4', column.id === 'select' ? 'w-4' : 'w-3/4 max-w-40']} />
									</TableUI.Cell>
								{/each}
								{#if onRowClick}<TableUI.Cell></TableUI.Cell>{/if}
							</TableUI.Row>
						{/each}
					{:else}
						{#each table.getRowModel().rows as row (row.id)}
							<TableUI.Row
								data-state={row.getIsSelected() && 'selected'}
								class={onRowClick &&
									'group/row cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring'}
								tabindex={onRowClick ? 0 : undefined}
								aria-label={onRowClick && rowLabel ? `Open ${rowLabel(row.original)}` : undefined}
								onclick={(e) => rowClick(e, row.original)}
								onkeydown={(e) => rowKey(e, row.original)}
							>
								{#each row.getVisibleCells() as cell (cell.id)}
									{@const below = cell.column.columnDef.meta?.hideBelow}
									<TableUI.Cell class={below && hidden[below]}>
										<FlexRender {cell} />
									</TableUI.Cell>
								{/each}
								{#if onRowClick}
									<!-- Says "this opens" without a word, and only where the pointer or focus is. -->
									<TableUI.Cell class="w-8 pr-3 text-muted-foreground">
										<ChevronRight
											class="size-4 opacity-0 transition-opacity group-hover/row:opacity-100 group-focus-visible/row:opacity-100"
											aria-hidden="true"
										/>
									</TableUI.Cell>
								{/if}
							</TableUI.Row>
						{/each}
					{/if}
				</TableUI.Body>
			</TableUI.Root>
		</div>

		<div class="flex items-center justify-between px-2">
			<div class="flex-1 text-sm text-muted-foreground">
				<!-- The bulk bar says how many are selected, the footer keeps the total. -->
				{#if total > 0}
					{total} total
				{/if}
			</div>
			<!-- Nothing to page through below the smallest page size. -->
			{#if total > pageSizeOptions[0]}
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
					<div class="flex w-25 items-center justify-center text-sm font-medium tabular-nums">
						Page {pager.pageIndex + 1} of {Math.max(1, pageCount)}
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
			{/if}
		</div>

		{#if selectedCount > 0 && bulkActions && bulkActions.length > 0}
			<BulkActions
				items={table.getSelectedRowModel().rows.map((row) => row.original)}
				actions={bulkActions}
				count={{ selected: selectedCount, total: table.getFilteredRowModel().rows.length }}
				onClear={() => table.resetRowSelection()}
			/>
		{/if}
	{/if}
</div>
