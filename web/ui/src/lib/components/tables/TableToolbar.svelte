<script lang="ts" generics="TData extends RowData">
	import type { Snippet } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import XIcon from '@lucide/svelte/icons/x';
	import { SearchIcon, DeleteIcon } from '@lucide/svelte';
	import type { RowData, Table } from '@tanstack/svelte-table';
	import { Button } from '$lib/components/ui/button';
	import * as InputGroup from '$lib/components/ui/input-group';
	import { PAGE_PARAM } from '$lib/hooks';
	import FilterPill from '$lib/components/blocks/FilterPill.svelte';
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
		const url = new URL(page.url);
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
		url.searchParams.delete(PAGE_PARAM);
		goto(url, { replaceState: true, keepFocus: true });
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
		const url = new URL(page.url);
		if (hasSearch) {
			url.searchParams.delete(searchParamKey);
			searchValue = '';
		}
		filters?.forEach((f) => url.searchParams.delete(f.param));
		extraParams.forEach((p) => url.searchParams.delete(p));
		url.searchParams.delete(PAGE_PARAM);
		goto(url, { replaceState: true, keepFocus: true });
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

<div class="flex flex-col items-center justify-between gap-2 sm:flex-row">
	<div class="flex flex-col items-center gap-2 sm:flex-row">
		{#if hasSearch}
			<InputGroup.Root class="max-w-xs sm:min-w-sm">
				<InputGroup.Input
					value={searchValue}
					placeholder={searchPlaceholder}
					oninput={handleSearchInput}
				/>
				<InputGroup.Addon align="inline-end">
					{#if searchValue}
						{#if searchResultCount !== undefined}
							<span class="text-xs text-muted-foreground">
								{searchResultCount}
								{searchResultCount === 1 ? 'result' : 'results'}
							</span>
						{/if}
						<InputGroup.Button variant="ghost" size="icon-xs" onclick={handleSearchClear}>
							<DeleteIcon />
						</InputGroup.Button>
					{/if}
				</InputGroup.Addon>
				<InputGroup.Addon>
					<SearchIcon />
				</InputGroup.Addon>
			</InputGroup.Root>
		{/if}

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
			<Button variant="ghost" onclick={handleReset} title="Reset filters">
				<XIcon />
			</Button>
		{/if}
	</div>

	<div class="flex items-center justify-end gap-2">
		{#if table}
			<TableViewOptions {table} />
		{/if}
	</div>
</div>
