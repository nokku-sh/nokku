import { timestampFromDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import { createMutation, createQuery } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account } from './account';

// Password, passkeys, and backup codes are kagi's /auth/account surface.
// The mutations keep the shapes the security page already consumes.

const invalidateCredentials = () => queryClient.invalidateQueries({ queryKey: ['account'] });

export const password = {
	update: () =>
		createMutation<void, Error, { currentPassword: string; newPassword: string }>(() => ({
			mutationFn: ({ currentPassword, newPassword }) =>
				account.changePassword(currentPassword, newPassword),
			onSuccess: invalidateCredentials
		})),
	delete: () =>
		createMutation<void, Error, { currentPassword: string }>(() => ({
			mutationFn: ({ currentPassword }) => account.removePassword(currentPassword),
			onSuccess: () => {
				void invalidateCredentials();
				toast.success('Password deleted', {
					description: 'You can now only sign in with passkeys.'
				});
			}
		}))
};

// Passkeys -------------------------------------------------------------------

export interface Passkey {
	id: string;
	name: string;
	createdAt: Timestamp;
}

export const passkey = {
	// Queries
	list: () =>
		createQuery<Passkey[]>(() => ({
			queryKey: ['account', 'credentials'],
			queryFn: async () => {
				const { credentials } = await account.credentials();
				return credentials
					.filter((c) => c.type === 'passkey')
					.map((c) => ({
						id: c.id,
						name: c.label ?? '',
						createdAt: timestampFromDate(new Date(c.createdAt))
					}));
			}
		})),

	// Mutations
	delete: () =>
		createMutation<void, Error, { id: string }>(() => ({
			mutationFn: ({ id }) => account.removeCredential(id),
			onSuccess: invalidateCredentials
		})),
	rename: () =>
		createMutation<void, Error, { id: string; name: string }>(() => ({
			mutationFn: ({ id, name }) => account.renameCredential(id, name),
			onSuccess: () => {
				void invalidateCredentials();
				toast.success('Passkey renamed', {
					description: 'The display name was updated.'
				});
			}
		}))
};

// Backup Codes ---------------------------------------------------------------

export interface BackupCode {
	id: string;
	createdAt: Timestamp;
}

export const backupCode = {
	// Queries
	list: () =>
		createQuery<BackupCode[]>(() => ({
			queryKey: ['account', 'backup-codes'],
			queryFn: async () => {
				const { codes } = await account.backupCodes();
				return codes.map((c) => ({
					id: c.id,
					createdAt: timestampFromDate(new Date(c.createdAt))
				}));
			}
		})),

	// Mutations
	create: () =>
		createMutation<{ codes: string[] }, Error, void>(() => ({
			mutationFn: () => account.rotateBackupCodes(),
			onSuccess: invalidateCredentials
		})),
	delete: () =>
		createMutation<void, Error, Record<string, never>>(() => ({
			mutationFn: () => account.removeBackupCodes(),
			onSuccess: invalidateCredentials
		}))
};
