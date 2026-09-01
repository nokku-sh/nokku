import { createMutation, createQuery } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account, type AccountSession } from './account';

// Active sessions of the account, as listed and revoked on the security
// page. Revoking the current session is rejected by the backend: logout is
// the way out.

const invalidateSessions = () => queryClient.invalidateQueries({ queryKey: ['account'] });

export const session = {
	list: () =>
		createQuery<AccountSession[]>(() => ({
			queryKey: ['account', 'sessions'],
			queryFn: () => account.sessions()
		})),

	revoke: () =>
		createMutation<void, Error, { id: string }>(() => ({
			mutationFn: ({ id }) => account.removeSession(id),
			onSuccess: () => {
				void invalidateSessions();
				toast.success('Session revoked', {
					description: 'That device has been signed out.'
				});
			}
		}))
};

// Human labels for the stored session kind and login method values.
export function sessionKindLabel(kind: string): string {
	switch (kind) {
		case 'user':
			return 'Browser';
		case 'cli':
			return 'CLI';
		case 'web_device':
			return 'Remembered device';
		default:
			return kind;
	}
}

export function sessionMethodLabel(method: string): string {
	switch (method) {
		case 'password':
			return 'Password';
		case 'passkey':
			return 'Passkey';
		case 'backup_code':
			return 'Backup code';
		case 'oidc':
			return 'OIDC';
		case 'oauth2':
			return 'OAuth';
		case 'saml':
			return 'SAML';
		case 'device':
			return 'Device';
		default:
			return method;
	}
}
