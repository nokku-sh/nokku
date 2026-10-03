import { goto } from '$app/navigation';
import { page } from '$app/state';
import { pageSize } from '#lib/store.svelte.js';

export const PAGE_PARAM = 'page';

// usePagination keeps the page number in the URL (1-based) so every table
// has its own position and reloads or shared links land on the same page.
// The page size is a persisted user preference shared by all tables.
export function usePagination() {
	const pageIndex = $derived(
		Math.max(0, Math.floor(Number(page.url.searchParams.get(PAGE_PARAM)) || 1) - 1)
	);

	return {
		get pageIndex() {
			return pageIndex;
		},
		get pageSize() {
			return pageSize.current;
		},
		get args() {
			return { limit: pageSize.current, offset: pageIndex * pageSize.current };
		},
		set(index: number, size = pageSize.current) {
			if (size !== pageSize.current) {
				pageSize.current = size;
				index = 0;
			}
			const url = new URL(page.url.href);
			if (index > 0) url.searchParams.set(PAGE_PARAM, String(index + 1));
			else url.searchParams.delete(PAGE_PARAM);
			void goto(url, { replace: true, reset: false });
		}
	};
}
