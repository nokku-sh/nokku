import { createMutation, createQuery } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { SessionKind, SignInMethod } from '#lib/gen/nokku/v1/account_pb.js';
import { account, type AccountSession } from './account';

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
		})),
	revokeOthers: () =>
		createMutation<number, Error, { ids: string[] }>(() => ({
			mutationFn: async ({ ids }) => {
				await Promise.all(ids.map((id) => account.removeSession(id)));
				return ids.length;
			},
			onSuccess: (n) => {
				void invalidateSessions();
				toast.success(`Signed out ${n} ${n === 1 ? 'device' : 'devices'}`);
			}
		}))
};

export function sessionKindLabel(kind: SessionKind): string {
	switch (kind) {
		case SessionKind.BROWSER:
			return 'Browser';
		case SessionKind.CLI:
			return 'CLI';
		case SessionKind.DEVICE:
			return 'Remembered device';
		default:
			return 'Session';
	}
}

export function sessionMethodLabel(method: SignInMethod): string {
	switch (method) {
		case SignInMethod.PASSKEY:
			return 'Passkey';
		case SignInMethod.MAGIC_LINK:
			return 'Email link';
		case SignInMethod.OIDC:
			return 'Single sign-on';
		case SignInMethod.DEVICE:
			return 'Device';
		default:
			return 'Unknown';
	}
}
