import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { createMutation } from '@tanstack/svelte-query';
import { workspaceID } from '$lib/store.svelte';
import { queryClient, httpFetch } from './client';

// Auth flows moved from connectrpc RPCs to plain HTTP endpoints backed by
// kagi. These mutations mirror the previous useMutation(AuthService.method.*)
// surface so the pages and components keep working unchanged.

function post(url: string, body: unknown) {
	return httpFetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
}

function authMutation<B extends object | undefined>(url: string, onSuccess?: () => void) {
	return createMutation<void, Error, B>(() => ({
		mutationFn: async (body: B) => {
			await post(url, body ?? {});
		},
		onSuccess: () => {
			onSuccess?.();
		}
	}));
}

export const auth = {
	login: () =>
		authMutation<{ email: string; password: string }>('/auth/login', () => {
			void goto('/');
		}),
	loginWithBackupCode: () =>
		authMutation<{ email: string; code: string }>('/auth/login/backup-code', () => {
			void goto('/');
			toast.success('Welcome back 👋', { description: 'Make sure to change your password!' });
		}),
	logout: () =>
		authMutation('/auth/logout', () => {
			workspaceID.current = '';
			void queryClient.cancelQueries();
			queryClient.clear();
			void goto('/login');
		}),
	register: () =>
		authMutation<{ name: string; email: string; password: string }>('/auth/register', () =>
			toast.success('Registration successful')
		),
	forgotPassword: () =>
		authMutation<{ email: string }>('/auth/forgot-password', () =>
			toast.success('Password reset email sent')
		),
	verifyEmail: () =>
		authMutation<{ token: string }>('/auth/verify-email', () => toast.success('Email verified')),
	resendVerification: () =>
		authMutation<{ email: string }>('/auth/resend-verification', () =>
			toast.success('Verification email sent')
		),
	resetPassword: () =>
		authMutation<{ token: string; newPassword: string }>('/auth/reset-password', () =>
			toast.success('Password reset')
		)
};
