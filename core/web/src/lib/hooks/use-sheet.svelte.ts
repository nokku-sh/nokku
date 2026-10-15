import { goto } from '$app/navigation';
import { page } from '$app/state';

/** Query params owned by sheets and create forms, tables don't treat them as filters. */
export const SHEET_PARAMS = ['id', 'tab', 'new'];

// Set when this session pushed the history entry, so closing goes back instead of leaving a dead entry.
let pushed = false;

function urlWith(params: Record<string, string | undefined>) {
	const url = new URL(page.url.href);
	for (const [key, value] of Object.entries(params)) {
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
	}
	return url;
}

/** A link that opens this entity's sheet, on the current page unless a path is given. */
export function sheetLink(id: string, path = page.url.pathname): string {
	const url = new URL(path, page.url.origin);
	url.searchParams.set('id', id);
	return url.href;
}

// useSheet keeps the open entity in `?id=` and its tab in `?tab=`, so links are shareable and Back closes the sheet.
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
			void goto(urlWith({ tab: value }), { replace: true, reset: false });
		},
		// From a create form the sheet takes the form's place in one navigation. The form awaits it, so its own
		// close finds `new` gone and does not navigate back to a URL without the id.
		show(entityId: string, entityTab?: string) {
			const fromCreate = page.url.searchParams.has('new');
			pushed = !fromCreate;
			return goto(urlWith({ id: entityId, tab: entityTab, new: undefined }), {
				replace: fromCreate,
				reset: false
			});
		},
		close() {
			if (!id) return;
			if (pushed) {
				pushed = false;
				history.back();
				return;
			}
			void goto(urlWith({ id: undefined, tab: undefined }), { replace: true, reset: false });
		}
	};
}

// useCreate keeps "the create form is open" in `?new`, so the command palette can open it from any page.
export function useCreate() {
	const open = $derived(page.url.searchParams.has('new'));

	return {
		get open() {
			return open;
		},
		set open(value: boolean) {
			if (value === open) return;
			void goto(urlWith({ new: value ? '1' : undefined }), { replace: true, reset: false });
		}
	};
}
