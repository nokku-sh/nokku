import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { IsDocumentVisible } from 'runed';
import { WorkspaceService } from '#lib/gen/nokku/v1/workspace_pb.js';
import { authTransport, queryClient } from './client';

const client = createClient(WorkspaceService, authTransport);

// The server says something every 20 seconds, changed or not.
const SILENCE = 45_000;

// Spread wide, after a restart every open tab comes back at once.
const backoff = (failures: number) =>
	Math.min(60_000, 5_000 * 2 ** (failures - 1)) * (0.2 + 1.8 * Math.random());

/**
 * Keeps what the page shows current without polling. The server says which
 * services answer differently now and their queries are read again. A hidden
 * tab holds no stream, it reads again when it gets the focus back.
 */
export function useLiveChanges(enabled: () => boolean) {
	const visible = new IsDocumentVisible();
	// The stream lives outside Svelte and follows two reactive values.
	$effect(() => {
		if (!enabled() || !visible.current) return;
		const leaving = new AbortController();
		void follow(leaving.signal);
		return () => leaving.abort();
	});
}

async function follow(leaving: AbortSignal) {
	// Nobody listens between two streams, the next one starts by reading everything.
	let missed = false;
	let failures = 0;
	while (!leaving.aborted) {
		const silent = new AbortController();
		let timer: ReturnType<typeof setTimeout> | undefined;
		const heard = () => {
			clearTimeout(timer);
			timer = setTimeout(() => silent.abort(), SILENCE);
		};
		try {
			heard();
			const signal = AbortSignal.any([leaving, silent.signal]);
			let opened = false;
			for await (const change of client.subscribeChanges({}, { signal })) {
				heard();
				opened = true;
				failures = 0;
				if (change.everything || missed) {
					missed = false;
					void queryClient.invalidateQueries();
					continue;
				}
				for (const serviceName of change.services) {
					void queryClient.invalidateQueries({ queryKey: ['connect-query', { serviceName }] });
				}
			}
			// The server ends a stream on purpose now and then. One that said nothing is broken.
			if (!opened) failures++;
		} catch (error) {
			if (leaving.aborted) return;
			// The account layer sends an ended session to /login.
			if (ConnectError.from(error).code === Code.Unauthenticated) return;
			failures++;
		} finally {
			clearTimeout(timer);
			missed = true;
		}
		if (failures) await new Promise((resolve) => setTimeout(resolve, backoff(failures)));
	}
}
