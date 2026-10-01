import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { createMutation } from '@tanstack/svelte-query';
import { createClient } from '@connectrpc/connect';
import { AuthService } from '$lib/gen/nokku/v1/auth_pb';
import { workspaceID } from '$lib/store.svelte';
import { queryClient, authTransport } from './client';

const client = createClient(AuthService, authTransport);

function authMutation<B extends object | undefined, D = void>(
	mutationFn: (body: B) => Promise<D>,
	onSuccess?: (variables: B) => void
) {
	return createMutation<D, Error, B>(() => ({
		mutationFn: async (body: B) => mutationFn(body),
		onSuccess: (_data, variables) => {
			onSuccess?.(variables);
		}
	}));
}

export const auth = {
	login: () =>
		authMutation(
			(body: { email: string; password: string }) =>
				client.login({ email: body.email, password: body.password }),
			() => {
				void goto('/');
			}
		),
	loginWithBackupCode: () =>
		authMutation(
			(body: { email: string; code: string }) =>
				client.loginWithBackupCode({ email: body.email, code: body.code }),
			() => {
				void goto('/');
				toast.success('Welcome back 👋', { description: 'Make sure to change your password!' });
			}
		),
	logout: () =>
		authMutation(
			() => client.logout({}),
			() => {
				workspaceID.current = '';
				void queryClient.cancelQueries();
				queryClient.clear();
				void goto('/login');
			}
		),
	register: () =>
		authMutation(
			(body: { name: string; email: string; password: string }) =>
				client.register({ name: body.name, email: body.email, password: body.password }),
			(body) => {
				// The account stays locked until the emailed link is confirmed.
				void goto(`/verify?sent=true&email=${encodeURIComponent(body.email)}`);
			}
		),
	forgotPassword: () =>
		authMutation(
			(body: { email: string }) => client.forgotPassword({ email: body.email }),
			() => toast.success('Password reset email sent')
		),
	resetPassword: () =>
		authMutation((body: { token: string; newPassword: string }) =>
			client.resetPassword({ token: body.token, newPassword: body.newPassword })
		),
	verifyEmail: () =>
		authMutation(
			(body: { token: string }) => client.verifyEmail({ token: body.token }),
			() => toast.success('Email verified')
		),
	confirmEmailChange: () =>
		authMutation(
			(body: { token: string }) => client.confirmEmailChange({ token: body.token }),
			() => void queryClient.invalidateQueries({ queryKey: ['account'] })
		),
	cancelEmailChange: () =>
		authMutation(
			(body: { token: string }) => client.cancelEmailChange({ token: body.token }),
			() => void queryClient.invalidateQueries({ queryKey: ['account'] })
		),
	resendVerification: () =>
		authMutation(
			(body: { email: string }) => client.resendVerification({ email: body.email }),
			() => toast.success('Verification email sent')
		)
};
