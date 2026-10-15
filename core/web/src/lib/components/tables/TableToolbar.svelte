<script lang="ts" generics="TData extends RowData">
	import type { Snippet } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import XIcon from '@lucide/svelte/icons/x';
	import { SearchIcon, DeleteIcon } from '@lucide/svelte';
	import type { RowData, Table } from '@tanstack/svelte-table';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import * as Kbd from '#lib/components/ui/kbd/index.js';
	import { focusOnSlash } from '#lib/hooks/index.js';
	import { PAGE_PARAM } from '#lib/hooks/index.js';
	import FilterPill from '#lib/components/blocks/FilterPill.svelte';
	import TableViewOptions from './TableViewOptions.svelte';
	import type { FilterConfig } from './types';
	import type { DataTableFeatures } from './data-table-features.js';

	type Props<TData extends RowData> = {
		search?: boolean | string;
		searchPlaceholder?: string;
		searchResultCount?: number;
		filters?: FilterConfig[];
		table?: Table<DataTableFeatures, TData>;
		/** Extra filter controls, placed after the built-in ones. */
		children?: Snippet;
		/** More URL params the reset button clears. */
		extraParams?: string[];
	};

	let {
		search: searchProp = false,
		searchPlaceholder = 'Search...',
		searchResultCount,
		filters,
		table,
		children,
		extraParams = []
	}: Props<TData> = $props();

	const searchParamKey = $derived(typeof searchProp === 'string' ? searchProp : 'q');
	const hasSearch = $derived(searchProp !== false);

	let searchValue = $derived(page.url.searchParams.get(searchParamKey) ?? '');

	// A new search or filter changes the result set, so it starts at page 1.
	function updateUrlParam(key: string, value: string | undefined) {
		const url = new URL(page.url.href);
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
		url.searchParams.delete(PAGE_PARAM);
		goto(url, { replace: true, reset: false });
	}

	function handleSearchInput(e: Event) {
		const value = (e.target as HTMLInputElement).value;
		searchValue = value;
		updateUrlParam(searchParamKey, value || undefined);
	}

	function handleSearchClear() {
		searchValue = '';
		updateUrlParam(searchParamKey, undefined);
	}

	function handleReset() {
		const url = new URL(page.url.href);
		if (hasSearch) {
			url.searchParams.delete(searchParamKey);
			searchValue = '';
		}
		filters?.forEach((f) => url.searchParams.delete(f.param));
		extraParams.forEach((p) => url.searchParams.delete(p));
		url.searchParams.delete(PAGE_PARAM);
		goto(url, { replace: true, reset: false });
	}

	const isFiltered = $derived(
		(hasSearch && !!searchValue) ||
			(filters?.some((f) => page.url.searchParams.has(f.param)) ?? false) ||
			extraParams.some((p) => page.url.searchParams.has(p))
	);

	function filterValue(f: FilterConfig): string[] {
		const raw = page.url.searchParams.get(f.param);
		if (!raw) return [];
		return f.mode === 'single' ? [raw] : raw.split(',');
	}
</script>

<!-- Phones get the search on its own line and the filters in one row that scrolls. -->
<div class="flex flex-col gap-2 md:flex-row md:items-center">
	{#if hasSearch}
		<InputGroup.Root class="w-full md:w-80">
			<InputGroup.Input
				value={searchValue}
				placeholder={searchPlaceholder}
				aria-label="Search"
				oninput={handleSearchInput}
				{@attach focusOnSlash}
			/>
			<InputGroup.Addon align="inline-end">
				{#if searchValue}
					{#if searchResultCount !== undefined}
						<span class="text-xs text-muted-foreground tabular-nums">
							{searchResultCount}
							{searchResultCount === 1 ? 'result' : 'results'}
						</span>
					{/if}
					<InputGroup.Button
						variant="ghost"
						size="icon-xs"
						aria-label="Clear search"
						onclick={handleSearchClear}
					>
						<DeleteIcon />
					</InputGroup.Button>
				{:else}
					<Kbd.Root class="hidden pointer-fine:inline-flex">/</Kbd.Root>
				{/if}
			</InputGroup.Addon>
			<InputGroup.Addon>
				<SearchIcon />
			</InputGroup.Addon>
		</InputGroup.Root>
	{/if}

	<div class="flex min-w-0 flex-1 items-center gap-2">
		<div class="-m-1 no-scrollbar flex min-w-0 items-center gap-2 overflow-x-auto p-1">
			{#each filters ?? [] as filter (filter.param)}
				<FilterPill
					title={filter.title}
					options={filter.options}
					mode={filter.mode}
					selected={filterValue(filter)}
					onChange={(next) => updateUrlParam(filter.param, next.join(',') || undefined)}
				/>
			{/each}

			{@render children?.()}

			{#if isFiltered}
				<Button variant="ghost" size="sm" class="shrink-0" onclick={handleReset}>
					<XIcon data-icon="inline-start" />
					Reset
				</Button>
			{/if}
		</div>

		{#if table}
			<div class="ml-auto shrink-0">
				<TableViewOptions {table} />
			</div>
		{/if}
	</div>
</div>
