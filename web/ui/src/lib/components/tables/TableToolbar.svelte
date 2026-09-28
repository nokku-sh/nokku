<script lang="ts" generics="TData extends RowData">
	import type { Snippet } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import XIcon from '@lucide/svelte/icons/x';
	import { SearchIcon, DeleteIcon, CirclePlusIcon, CircleCheckBig } from '@lucide/svelte';
	import type { RowData, Table } from '@tanstack/svelte-table';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as InputGroup from '$lib/components/ui/input-group';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Separator } from '$lib/components/ui/separator';
	import { PAGE_PARAM } from '$lib/hooks';
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

	function toggleFilter(f: FilterConfig, value: string) {
		const current = filterValue(f);
		const next =
			f.mode === 'single'
				? current[0] === value
					? []
					: [value]
				: current.includes(value)
					? current.filter((v) => v !== value)
					: [...current, value];
		updateUrlParam(f.param, next.length > 0 ? next.join(',') : undefined);
	}

	function clearFilter(f: FilterConfig) {
		updateUrlParam(f.param, undefined);
	}

	const filterLabel = (f: FilterConfig, value: string) =>
		f.options.find((o: { value: string }) => o.value === value)?.label ?? value;
</script>

<div class="mb-4 flex flex-col items-center justify-between gap-2 sm:flex-row">
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

		{#if filters}
			{#each filters as filter (filter.param)}
				{@const values = filterValue(filter)}
				<Popover.Root>
					<Popover.Trigger>
						{#snippet child({ props })}
							<Button {...props} variant="outline" size="sm" class="h-8 rounded-full border-dashed">
								<CirclePlusIcon />
								{filter.title}
								{#if values.length > 0}
									<Separator orientation="vertical" class="mx-2 h-4" />
									<Badge variant="secondary" class="rounded-sm px-1 font-normal lg:hidden">
										{values.length}
									</Badge>
									<div class="hidden gap-1 lg:flex">
										{#if values.length > 1}
											<Badge variant="secondary" class="rounded-sm px-1 font-normal">
												{values.length} selected
											</Badge>
										{:else}
											{#each values as v (v)}
												<Badge variant="secondary" class="rounded-sm px-1 font-normal">
													{filterLabel(filter, v)}
												</Badge>
											{/each}
										{/if}
									</div>
								{/if}
							</Button>
						{/snippet}
					</Popover.Trigger>
					<Popover.Content class="w-50 p-0" align="start">
						<Command.Root>
							<Command.Input placeholder={filter.title} />
							<Command.List>
								<Command.Empty>No results found.</Command.Empty>
								<Command.Group>
									{#each filter.options as option (option.value)}
										{@const isSelected = values.includes(option.value)}
										<Command.Item
											onSelect={() => toggleFilter(filter, option.value)}
											class="flex items-center justify-between"
										>
											<div class="flex items-center gap-2">
												{#if option.icon}
													<option.icon class="text-muted-foreground" />
												{/if}
												<span>{option.label}</span>
											</div>
											{#if isSelected}
												<CircleCheckBig class="text-primary" />
											{/if}
										</Command.Item>
									{/each}
								</Command.Group>
								{#if values.length > 0}
									<Command.Separator />
									<Command.Group>
										<Command.Item
											onSelect={() => clearFilter(filter)}
											class="justify-center text-center"
										>
											Clear filters
										</Command.Item>
									</Command.Group>
								{/if}
							</Command.List>
						</Command.Root>
					</Popover.Content>
				</Popover.Root>
			{/each}
		{/if}

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
