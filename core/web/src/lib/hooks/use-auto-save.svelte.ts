import { useDebounce } from 'runed';

export type SaveState = 'idle' | 'saving' | 'saved' | 'error';

// useAutoSave is the one save signal of a sheet. Debounced field edits go through save(), one-off changes like a
// role or a membership through track(). Errors still raise the global mutation toast with the reason.
export function useAutoSave(save: () => Promise<unknown>, wait = 600) {
	let queued = $state(false);
	let inFlight = $state(0);
	let failed = $state(false);
	let savedRecently = $state(false);
	let resetTimer: ReturnType<typeof setTimeout> | undefined;
	let last: (() => Promise<unknown>) | undefined;

	async function track<T>(run: () => Promise<T>): Promise<T> {
		last = run;
		inFlight++;
		try {
			const result = await run();
			failed = false;
			savedRecently = true;
			clearTimeout(resetTimer);
			resetTimer = setTimeout(() => (savedRecently = false), 2000);
			return result;
		} catch (err) {
			failed = true;
			throw err;
		} finally {
			inFlight--;
		}
	}

	const debounced = useDebounce(async () => {
		queued = false;
		await track(save).catch(() => {});
	}, wait);

	return {
		save: () => {
			queued = true;
			void debounced();
		},
		track,
		/** Runs the last change again, for the Retry in the footer. */
		retry: () => {
			if (last) void track(last).catch(() => {});
		},
		get saveState(): SaveState {
			if (queued || inFlight > 0) return 'saving';
			if (failed) return 'error';
			if (savedRecently) return 'saved';
			return 'idle';
		}
	};
}
