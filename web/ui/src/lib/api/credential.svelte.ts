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
	delete: () => useMutation(CredentialService.method.deletePasskey),
	rename: () =>
		useMutation(CredentialService.method.renamePasskey, {
			onSuccess: () =>
				toast.success('Passkey renamed', {
					description: 'The display name was updated.'
				})
		})
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
