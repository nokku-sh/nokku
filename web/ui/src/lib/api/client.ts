import { createConnectTransport } from '@connectrpc/connect-web';
import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { browser } from '$app/environment';
import { Code, ConnectError, type Interceptor, type UnaryRequest } from '@connectrpc/connect';
import { toast } from 'svelte-sonner';
import { formatConnectError, parseHTTPError } from './error-formatter';
import { goto } from '$app/navigation';
import { UserService } from '$lib/gen/nokku/v1/user_pb';
import { WorkspaceService } from '$lib/gen/nokku/v1/workspace_pb';
import { workspaceID } from '$lib/store.svelte';

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
		onError: (error, query) => {
			if (!(error instanceof ConnectError)) return;

			const key = query.queryKey[1] as { methodName?: string } | undefined;

			// whoami is the canonical auth check: any failure means the session
			// is gone (revoked, expired, or the server rotated its secrets and
			// invalidated the cookie). Bounce back to /login instead of leaving
			// a broken page behind.
			if (
				key?.methodName === UserService.method.whoami.name &&
				(error.code === Code.Unauthenticated || error.code === Code.NotFound)
			) {
				handleSessionExpired();
				return;
			}

			if (error.code === Code.Unauthenticated) return;

			// A persisted workspace id can outlive the workspace itself (deleted
			// or membership revoked). Drop it silently and let the workspace list
			// select a valid one instead of erroring on every load.
			if (
				key?.methodName === WorkspaceService.method.getWorkspace.name &&
				(error.code === Code.NotFound || error.code === Code.PermissionDenied)
			) {
				workspaceID.current = '';
				void queryClient.invalidateQueries({
					queryKey: [
						'connect-query',
						{
							serviceName: WorkspaceService.typeName,
							methodName: WorkspaceService.method.listWorkspaces.name
						}
					]
				});
				return;
			}

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

				// Invalidate only queries that belong to this specific service
				await queryClient.invalidateQueries({ queryKey: ['connect-query', serviceName] });
			} else {
				// Safe fallback
				await queryClient.invalidateQueries({ queryKey: ['connect-query'] });
			}
		},
		onError: (error) => {
			if (error instanceof ConnectError && error.code !== Code.Unauthenticated) {
				toast.error(formatConnectError(error).title, {
					description: formatConnectError(error).description
				});
			}
		}
	})
});

let sessionExpiredAt = 0;

// Public routes don't require a session; a failing whoami there is expected
// and must not bounce the visitor to /login.
const publicPaths = [
	'/login',
	'/register',
	'/verify',
	'/recovery',
	'/reset',
	'/device',
	'/auth-error'
];

// The session cookie is HttpOnly, so only the backend can clear it. On an
// expired or revoked session the backend rejects with Unauthenticated; here we
// reset local state, drop cached data and land on /login.
function handleSessionExpired() {
	if (!browser || publicPaths.some((p) => window.location.pathname.startsWith(p))) return;

	const now = Date.now();
	if (now - sessionExpiredAt < 5000) return; // dedupe concurrent failures
	sessionExpiredAt = now;

	workspaceID.current = '';
	void queryClient.cancelQueries();
	queryClient.clear();
	void goto('/login');
	toast.info('Session expired', { description: 'Please log in again.' });
}

// Workspace-scoped protobuf requests all use the conventional workspace_id field.
export const workspaceInterceptor: Interceptor = (next) => async (req) => {
	if (req.stream || !browser || !workspaceID.current) {
		return await next(req);
	}

	const unaryRequest = req as UnaryRequest;
	const hasWorkspaceField = unaryRequest.method.input.fields.some(
		(field) => field.localName === 'workspaceId'
	);
	if (!hasWorkspaceField) {
		return await next(req);
	}

	const message = unaryRequest.message as Record<string, unknown>;
	if (message.workspaceId) {
		return await next(req);
	}

	const updatedRequest: UnaryRequest = {
		...unaryRequest,
		message: { ...message, workspaceId: workspaceID.current } as unknown as UnaryRequest['message']
	};
	return await next(updatedRequest);
};

export const authTransport = createConnectTransport({
	baseUrl: '/',
	useHttpGet: true,
	fetch: (input, init) => fetch(input, { ...init, credentials: 'include' }),
	jsonOptions: { ignoreUnknownFields: true },
	interceptors: [workspaceInterceptor]
});

export interface CallUnaryOptions {
	signal?: AbortSignal;
}

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
