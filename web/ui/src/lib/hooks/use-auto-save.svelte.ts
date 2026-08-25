import { useDebounce } from 'runed';

export type SaveState = 'idle' | 'saving' | 'saved' | 'error';

/**
 * Debounced autosave for edit forms. Trigger save() after every field change;
 * the mutation fires once the user stops typing. Errors still surface through
 * the global mutation toast, this only tracks state for inline indicators.
 */
export function useAutoSave(save: () => Promise<unknown>, wait = 600) {
	let inFlight = $state(false);
	let failed = $state(false);
	let savedRecently = $state(false);
	let resetTimer: ReturnType<typeof setTimeout> | undefined;

	const run = useDebounce(async () => {
		try {
			await save();
			failed = false;
			savedRecently = true;
			clearTimeout(resetTimer);
			resetTimer = setTimeout(() => (savedRecently = false), 2000);
		} catch {
			failed = true;
		} finally {
			inFlight = false;
		}
	}, wait);

	return {
		save: () => {
			inFlight = true;
			void run();
		},
		cancel: () => {
			run.cancel();
			inFlight = false;
		},
		get saveState(): SaveState {
			if (inFlight) return 'saving';
			if (failed) return 'error';
			if (savedRecently) return 'saved';
			return 'idle';
		}
	};
}
