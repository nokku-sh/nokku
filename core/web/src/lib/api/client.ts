import { createConnectTransport } from '@connectrpc/connect-web';
import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { browser } from '$app/env';
import { Code, ConnectError } from '@connectrpc/connect';
import { toast } from 'svelte-sonner';
import { returnTo } from '#lib/store.svelte.js';
import { connection } from './connection.svelte';
import { formatConnectError } from './error-formatter';

// LIVE is how often a view that shows live state, like who is online or waiting, asks again on the tab in front.
export const LIVE = 15_000;

// The id keeps a failing poll from stacking the same toast.
function toastError(error: ConnectError) {
	const { title, description } = formatConnectError(error);
	toast.error(title, { description, id: `${title}:${description ?? ''}` });
}

export const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			enabled: browser,
			retry: false,
			refetchOnMount: true,
			refetchOnReconnect: true,
			refetchOnWindowFocus: true,
			refetchIntervalInBackground: false,
			// Only the views that show live state poll, see LIVE. During an outage every query retries, so the page
			// comes back by itself.
			refetchInterval: () => (connection.down ? LIVE : false)
		},
		mutations: {
			retry: false
		}
	},
	queryCache: new QueryCache({
		onSuccess: () => {
			// Everything on screen is as old as the outage.
			if (connection.answered()) void queryClient.invalidateQueries();
		},
		onError: (error) => {
			if (!(error instanceof ConnectError)) return;

			// ConnectionBanner says it once, a poll would say it every 15 seconds.
			if (connection.failed(error)) return;

			if (error.code === Code.Unauthenticated) {
				handleSessionExpired();
				return;
			}

			// Views render missing entities themselves (deleted subjects, stale links).
			if (error.code === Code.NotFound) return;

			toastError(error);
		}
	}),
	mutationCache: new MutationCache({
		onSuccess: async (_data, _variables, _context, mutation) => {
			connection.answered();
			const mutationKey = mutation.options.mutationKey;
			if (mutationKey && mutationKey.length >= 2 && mutationKey[0] === 'connect-query') {
				const serviceName = mutationKey[1];

				await queryClient.invalidateQueries({ queryKey: ['connect-query', serviceName] });
			} else {
				await queryClient.invalidateQueries({ queryKey: ['connect-query'] });
			}
		},
		onError: (error) => {
			if (!(error instanceof ConnectError)) return;
			// A step-up call ends an old session, sign in again lands back on this page.
			if (error.code === Code.Unauthenticated) {
				handleSessionExpired();
				return;
			}
			if (connection.failed(error)) {
				toast.error("Can't reach Nokku", {
					description: 'The change may not have gone through. Check once it is back.',
					id: 'unreachable'
				});
				return;
			}
			toastError(error);
		}
	})
});

const publicPaths = ['/login', '/invite', '/signup', '/device', '/email-change', '/sso-error'];

let leaving = false;
export const isLeaving = () => leaving;

// A full load, so this tab's web shells and cached data end with the session.
export function leave(path = '/login') {
	leaving = true;
	window.location.assign(path);
}

// back is where signing in again lands, this page by default.
export function handleSessionExpired(back?: string) {
	if (!browser || publicPaths.some((p) => window.location.pathname.startsWith(p))) return;

	const path = back ?? window.location.pathname + window.location.search;
	returnTo.current = path === '/' ? null : { path, at: Date.now() };
	leave();
}

export const authTransport = createConnectTransport({
	baseUrl: '/',
	useHttpGet: true,
	fetch: (input, init) => fetch(input, { ...init, credentials: 'include' }),
	jsonOptions: { ignoreUnknownFields: true }
});
