import {
	create,
	type DescMessage,
	type DescMethodUnary,
	type MessageInitShape,
	type MessageShape
} from '@bufbuild/protobuf';
import { createConnectTransport } from '@connectrpc/connect-web';
import { MutationCache, QueryCache, QueryClient } from '@tanstack/svelte-query';
import { browser } from '$app/environment';
import { Code, ConnectError, type Interceptor, type UnaryRequest } from '@connectrpc/connect';
import { AuthService } from '$lib/gen/nokku/v1/auth_pb';
import { toast } from 'svelte-sonner';
import { formatConnectError, parseHTTPError } from './error-formatter';
import { goto } from '$app/navigation';
import { SSOService } from '$lib/gen/nokku/v1/sso_pb';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
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
		onError: (error) => {
			if (error instanceof ConnectError && error.code !== Code.Unauthenticated) {
				toast.error(formatConnectError(error).title, {
					description: formatConnectError(error).description
				});
			}
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

let refreshPromise: Promise<void> | null = null;

const publicServices = new Set([AuthService.typeName]);
const publicMethods = new Set([
	UtilService.method.getVersion.name,
	SSOService.method.checkSSO.name
]);

export const authInterceptor: Interceptor = (next) => async (req) => {
	if (publicServices.has(req.service.typeName) || publicMethods.has(req.method.name)) {
		return await next(req);
	}

	try {
		return await next(req);
	} catch (err) {
		if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
			// try to refresh token
			if (!refreshPromise) {
				refreshPromise = (async () => {
					try {
						await callUnary(AuthService.method.refreshToken, undefined);
					} catch (refreshErr) {
						if (browser && !window.location.pathname.startsWith('/login')) {
							void goto('/login');
						}
						throw refreshErr;
					} finally {
						refreshPromise = null;
					}
				})();
			}

			await refreshPromise;
			return await next(req);
		}
		throw err;
	}
};

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
	interceptors: [workspaceInterceptor, authInterceptor]
});

const transport = createConnectTransport({
	baseUrl: '/',
	useHttpGet: true,
	fetch: (input, init) => fetch(input, { ...init, credentials: 'include' }),
	jsonOptions: { ignoreUnknownFields: true },
	interceptors: [workspaceInterceptor]
});

export interface CallUnaryOptions {
	signal?: AbortSignal;
}

export async function callUnary<I extends DescMessage, O extends DescMessage>(
	schema: DescMethodUnary<I, O>,
	input?: MessageInitShape<I>,
	options?: CallUnaryOptions
): Promise<MessageShape<O> | undefined> {
	try {
		const result = await transport.unary(
			schema,
			options?.signal,
			undefined,
			undefined,
			input ?? create(schema.input),
			undefined
		);
		if (result.message) return result.message;
	} catch (error) {
		return Promise.reject(error);
	}
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
