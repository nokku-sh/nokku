export type ConfirmOptions = {
	title: string;
	description?: string;
	/** Defaults to "Delete" for destructive dialogs, "Confirm" otherwise. */
	confirmText?: string;
	/** Defaults to true, most confirmations guard a delete or revoke. */
	destructive?: boolean;
	/** The user must type this exact text before confirming. */
	typeToConfirm?: string;
	/** Asks for a value (e.g. the current password), passed to onConfirm. */
	input?: { label: string; type?: 'text' | 'password' };
	/** Runs with a spinner. The dialog stays open if it throws. */
	onConfirm?: (value: string) => unknown;
};

class ConfirmState {
	options = $state<ConfirmOptions | null>(null);
	value = $state('');
	pending = $state(false);
	#resolve: ((ok: boolean) => void) | undefined;

	open(options: ConfirmOptions) {
		this.#resolve?.(false);
		this.options = options;
		this.value = '';
		this.pending = false;
		return new Promise<boolean>((resolve) => (this.#resolve = resolve));
	}

	async accept() {
		const options = this.options;
		if (!options) return;
		if (options.onConfirm) {
			this.pending = true;
			try {
				await options.onConfirm(this.value);
			} catch {
				// The global mutation handler already toasted it.
				return;
			} finally {
				this.pending = false;
			}
		}
		this.#settle(true);
	}

	cancel() {
		if (!this.pending) this.#settle(false);
	}

	#settle(ok: boolean) {
		this.#resolve?.(ok);
		this.#resolve = undefined;
		this.options = null;
	}
}

export const confirmState = new ConfirmState();

// confirm opens the app-wide ConfirmDialog and resolves once the user decides.
export const confirm = (options: ConfirmOptions) => confirmState.open(options);
