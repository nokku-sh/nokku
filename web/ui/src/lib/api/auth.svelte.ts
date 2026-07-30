import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { useMutation } from '$lib/query';
import { cliToken, workspaceID } from '$lib/store.svelte';
import { SquareTerminalIcon } from '@lucide/svelte';
import { queryClient } from './client';
import { AuthService } from '$lib/gen/nokku/v1/auth_pb';

export const auth = {
	login: () =>
		useMutation(AuthService.method.login, {
			onSuccess: () => {
				void goto('/');
				toast.success('Welcome back 👋');
			}
		}),
	loginWithBackupCode: () =>
		useMutation(AuthService.method.loginWithBackupCode, {
			onSuccess: () => {
				void goto('/');
				toast.success('Welcome back 👋', { description: 'Make sure to change your password!' });
			}
		}),
	logout: () =>
		useMutation(AuthService.method.logout, {
			onSuccess: () => {
				workspaceID.current = '';
				void queryClient.cancelQueries();
				queryClient.clear();
				void goto('/login');
				toast.success('Logged out 👋');
			}
		}),
	register: () =>
		useMutation(AuthService.method.register, {
			onSuccess: () => toast.success('Registration successful')
		}),
	forgotPassword: () =>
		useMutation(AuthService.method.forgotPassword, {
			onSuccess: () => toast.success('Password reset email sent')
		}),
	verifyEmail: () =>
		useMutation(AuthService.method.verifyEmail, {
			onSuccess: () => toast.success('Email verified')
		}),
	resendVerification: () =>
		useMutation(AuthService.method.resendVerification, {
			onSuccess: () => toast.success('Verification email sent')
		}),
	resetPassword: () =>
		useMutation(AuthService.method.resetPassword, {
			onSuccess: () => toast.success('Password reset')
		}),
	verifyCLI: () =>
		useMutation(AuthService.method.verifyCLILogin, {
			onSuccess: () => toast.success('Login verified', { icon: SquareTerminalIcon }),
			onSettled: () => (cliToken.current = ''),
			transform: () => ({ loginCode: cliToken.current })
		})
};
