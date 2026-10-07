import { createMutation } from '@tanstack/svelte-query';
import { createClient } from '@connectrpc/connect';
import { AuthService } from '#lib/gen/nokku/v1/auth_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { queryClient, authTransport, leave } from './client';

const client = createClient(AuthService, authTransport);

export const auth = {
	// What this workspace lets people sign in with. Public.
	options: () => useQuery(AuthService.method.getLoginOptions, {}, { staleTime: Infinity }),

	// Always succeeds from the outside, so the form reveals no accounts.
	requestMagicLink: () => useMutation(AuthService.method.requestMagicLink),
	consumeMagicLink: () => useMutation(AuthService.method.consumeMagicLink),
	logout: () =>
		createMutation(() => ({
			mutationFn: () => client.logout({}),
			onSuccess: () => leave()
		})),
	confirmEmailChange: () =>
		useMutation(AuthService.method.confirmEmailChange, {
			onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['account'] })
		}),
	cancelEmailChange: () =>
		useMutation(AuthService.method.cancelEmailChange, {
			onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['account'] })
		})
};
