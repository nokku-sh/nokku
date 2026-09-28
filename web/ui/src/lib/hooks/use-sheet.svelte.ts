import { goto } from '$app/navigation';
import { page } from '$app/state';

/** Query params owned by sheets, tables don't treat them as filters. */
export const SHEET_PARAMS = ['id', 'tab'];

// Set when this session pushed the history entry, so closing can go back
// instead of leaving a dead entry that reopens the sheet on Back.
let pushed = false;

function urlWith(params: Record<string, string | undefined>) {
	const url = new URL(page.url);
	for (const [key, value] of Object.entries(params)) {
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
	}
	return url;
}

// useSheet keeps the open entity in `?id=` (and its tab in `?tab=`), so links
// are shareable and the browser or phone back gesture closes the sheet.
export function useSheet() {
	const id = $derived(page.url.searchParams.get('id') ?? '');
	const tab = $derived(page.url.searchParams.get('tab') ?? '');

	return {
		get id() {
			return id;
		},
		get open() {
			return !!id;
		},
		set open(value: boolean) {
			if (!value) this.close();
		},
		get tab() {
			return tab;
		},
		set tab(value: string) {
			void goto(urlWith({ tab: value }), { replaceState: true, keepFocus: true, noScroll: true });
		},
		show(entityId: string, entityTab?: string) {
			pushed = true;
			void goto(urlWith({ id: entityId, tab: entityTab }), { keepFocus: true, noScroll: true });
		},
		close() {
			if (!id) return;
			if (pushed) {
				pushed = false;
				history.back();
				return;
			}
			void goto(urlWith({ id: undefined, tab: undefined }), {
				replaceState: true,
				keepFocus: true,
				noScroll: true
			});
		}
	};
}
