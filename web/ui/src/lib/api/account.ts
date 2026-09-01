import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { AccountService } from '$lib/gen/nokku/v1/account_pb';
import type { AccountCredential, AccountSession } from '$lib/gen/nokku/v1/account_pb';
import type { User } from '$lib/gen/nokku/v1/account_pb';
import { authTransport, handleSessionExpired } from './client';

// The account surface is the Connect AccountService: profile, password,
// credentials, linked identities, backup codes, sessions, and deletion. The
// calls carry the HttpOnly session cookie through authTransport.

export type { AccountCredential, AccountSession, User };

const client = createClient(AccountService, authTransport);

// guard sends an expired or revoked session to /login, exactly like the
// fetch layer used to; every other error propagates to the caller.
async function guard<T>(p: Promise<T>): Promise<T> {
	try {
		return await p;
	} catch (err) {
		if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
			handleSessionExpired();
		}
		throw err;
	}
}

export const account = {
	user: (): Promise<User> => guard(client.getAccount({})).then((r) => r.user as User),

	update: (patch: { displayName?: string; picture?: string; disablePasswordReset?: boolean }) =>
		guard(
			client.updateAccount({
				name: patch.displayName,
				picture: patch.picture,
				disablePasswordReset: patch.disablePasswordReset
			})
		).then((r) => r.user as User),

	changePassword: (currentPassword: string, newPassword: string): Promise<void> =>
		guard(client.changePassword({ currentPassword, newPassword })).then(() => undefined),

	removePassword: (currentPassword: string): Promise<void> =>
		guard(client.removePassword({ currentPassword })).then(() => undefined),

	credentials: (): Promise<AccountCredential[]> =>
		guard(client.listCredentials({})).then((r) => r.credentials),

	renameCredential: (id: string, label: string): Promise<void> =>
		guard(client.renameCredential({ id, label })).then(() => undefined),

	removeCredential: (id: string): Promise<void> =>
		guard(client.removeCredential({ id })).then(() => undefined),

	removeIdentity: (provider: string): Promise<void> =>
		guard(client.removeIdentity({ provider })).then(() => undefined),

	backupCodes: (): Promise<AccountCredential[]> =>
		guard(client.listBackupCodes({})).then((r) => r.codes),

	rotateBackupCodes: (): Promise<string[]> =>
		guard(client.rotateBackupCodes({})).then((r) => r.codes),

	removeBackupCodes: (): Promise<void> => guard(client.removeBackupCodes({})).then(() => undefined),

	sessions: (): Promise<AccountSession[]> =>
		guard(client.listAccountSessions({})).then((r) => r.sessions),

	removeSession: (id: string): Promise<void> =>
		guard(client.removeSession({ id })).then(() => undefined),

	deleteAccount: (): Promise<void> => guard(client.deleteAccount({})).then(() => undefined)
};
