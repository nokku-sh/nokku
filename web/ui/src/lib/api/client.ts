import { createConnectTransport } from '@connectrpc/connect-web';
import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { browser } from '$app/env';
import { Code, ConnectError } from '@connectrpc/connect';
import { toast } from 'svelte-sonner';
import { formatConnectError, parseHTTPError } from './error-formatter';

export const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			enabled: browser,
			retry: false,
			refetchOnMount: true,
			refetchOnReconnect: true,
			refetchOnWindowFocus: true,
			refetchIntervalInBackground: false,
			refetchInterval: 300000 // 5min
		},
		mutations: {
			retry: false
		}
	},
	queryCache: new QueryCache({
		onError: (error) => {
			if (!(error instanceof ConnectError)) return;

			// The account layer bounces to /login itself.
			if (error.code === Code.Unauthenticated) return;

			// Views render missing entities themselves (deleted subjects, stale links).
			if (error.code === Code.NotFound) return;

			toast.error(formatConnectError(error).title, {
				description: formatConnectError(error).description
			});
		}
	}),
	mutationCache: new MutationCache({
		onSuccess: async (_data, _variables, _context, mutation) => {
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
			if (error.code === Code.Unauthenticated) return;
			toast.error(formatConnectError(error).title, {
				description: formatConnectError(error).description
			});
		}
	})
});

const publicPaths = ['/login', '/invite', '/signup', '/device', '/email-change', '/sso-error'];

export function handleSessionExpired() {
	if (!browser || publicPaths.some((p) => window.location.pathname.startsWith(p))) return;

	// A full load, so this tab's web shells and cached data end with the session.
	window.location.assign('/login');
}

export const authTransport = createConnectTransport({
	baseUrl: '/',
	useHttpGet: true,
	fetch: (input, init) => fetch(input, { ...init, credentials: 'include' }),
	jsonOptions: { ignoreUnknownFields: true }
});

export async function httpFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
	const response = await fetch(input, { credentials: 'include', ...init });
	if (!response.ok) {
		const err = await parseHTTPError(response);
		if (err.code !== Code.Unauthenticated) {
			const formatted = formatConnectError(err);
			toast.error(formatted.title, { description: formatted.description });
		}
		throw err;
	}
	return response;
}
