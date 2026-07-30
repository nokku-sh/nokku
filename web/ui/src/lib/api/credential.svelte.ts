import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { CredentialService } from '$lib/gen/nokku/v1/credential_pb';

export const password = {
	update: () => useMutation(CredentialService.method.updatePassword),
	delete: () =>
		useMutation(CredentialService.method.deletePassword, {
			onSuccess: () =>
				toast.success('Password deleted', {
					description: 'You can now only sign in with passkeys.'
				})
		})
};

// Passkeys -------------------------------------------------------------------

export const passkey = {
	// Queries
	list: () =>
		useQuery(CredentialService.method.listPasskeys, undefined, {
			select: (res) => res.passkeys
		}),

	// Mutations
	update: () => useMutation(CredentialService.method.updatePasskey),
	delete: () => useMutation(CredentialService.method.deletePasskey)
};

// Backup Codes ---------------------------------------------------------------

export const backupCode = {
	// Queries
	list: () =>
		useQuery(CredentialService.method.listBackupCodes, undefined, {
			select: (res) => res.codes
		}),

	// Mutations
	create: () => useMutation(CredentialService.method.createBackupCodes, {}),
	delete: () => useMutation(CredentialService.method.deleteBackupCodes)
};
