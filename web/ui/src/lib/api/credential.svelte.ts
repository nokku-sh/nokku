import { createMutation, createQuery } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account, type AccountCredential } from './account';

const invalidateCredentials = () => queryClient.invalidateQueries({ queryKey: ['account'] });

// Passkeys and identity provider links, the two ways an account signs in
// without a mailed link.
export const credentials = {
	all: () =>
		createQuery<AccountCredential[]>(() => ({
			queryKey: ['account', 'credentials'],
			queryFn: () => account.credentials()
		})),

	remove: () =>
		createMutation<void, Error, { id: string }>(() => ({
			mutationFn: ({ id }) => account.removeCredential(id),
			onSuccess: invalidateCredentials
		})),
	rename: () =>
		createMutation<void, Error, { id: string; label: string }>(() => ({
			mutationFn: ({ id, label }) => account.renameCredential(id, label),
			onSuccess: () => {
				void invalidateCredentials();
				toast.success('Passkey renamed');
			}
		}))
};
