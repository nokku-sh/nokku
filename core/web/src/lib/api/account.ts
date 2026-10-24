import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { AccountService } from '#lib/gen/nokku/v1/account_pb.js';
import type { AccountCredential, AccountSession } from '#lib/gen/nokku/v1/account_pb.js';
import type { User } from '#lib/gen/nokku/v1/account_pb.js';
import { authTransport, handleSessionExpired } from './client';

export type { AccountCredential, AccountSession, User };

const client = createClient(AccountService, authTransport);

// guard sends an expired session to /login, other errors propagate.
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

	update: (patch: { name?: string }) =>
		guard(client.updateAccount({ name: patch.name })).then((r) => r.user as User),

	/** An empty image removes the avatar. */
	setAvatar: (image: Uint8Array): Promise<User> =>
		guard(client.setAvatar({ image })).then((r) => r.user as User),

	requestEmailChange: (newEmail: string): Promise<void> =>
		guard(client.requestEmailChange({ newEmail })).then(() => undefined),

	credentials: (): Promise<AccountCredential[]> =>
		guard(client.listCredentials({})).then((r) => r.credentials),

	renameCredential: (id: string, label: string): Promise<void> =>
		guard(client.renameCredential({ id, label })).then(() => undefined),

	removeCredential: (id: string): Promise<void> =>
		guard(client.removeCredential({ id })).then(() => undefined),

	sessions: (): Promise<AccountSession[]> =>
		guard(client.listAccountSessions({})).then((r) => r.sessions),

	removeSession: (id: string): Promise<void> =>
		guard(client.removeSession({ id })).then(() => undefined),

	deleteAccount: (): Promise<void> => guard(client.deleteAccount({})).then(() => undefined)
};
