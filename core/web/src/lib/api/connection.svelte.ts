import { Code, ConnectError } from '@connectrpc/connect';

// When the server stopped answering. Unset while it does.
let lostAt = $state<number>();

export const connection = {
	get lostAt() {
		return lostAt;
	},
	get down() {
		return lostAt !== undefined;
	},
	/** Reports whether this ends an outage. */
	answered(): boolean {
		const wasDown = lostAt !== undefined;
		lostAt = undefined;
		return wasDown;
	},
	/** Reports whether nothing answered, as opposed to the server saying no. */
	failed(error: ConnectError): boolean {
		// A fetch that never got a response surfaces as a TypeError cause.
		const unreachable = error.code === Code.Unavailable || error.cause instanceof TypeError;
		if (unreachable) lostAt ??= Date.now();
		else lostAt = undefined;
		return unreachable;
	}
};
