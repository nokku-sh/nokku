import { Code, ConnectError, createClient } from '@connectrpc/connect';
import {
	AccountService,
	type AccountSession,
	type ListCredentialsResponse
} from '#lib/gen/nokku/v1/account_pb.js';
import { type User } from '#lib/gen/nokku/v1/user_pb.js';
import { authTransport, handleSessionExpired } from './client';

export type { AccountSession, ListCredentialsResponse, User };

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
		guard(client.updateAccount({ name: patch.name, updateMask: { paths: ['name'] } })).then(
			(r) => r.user as User
		),

	requestEmailChange: (newEmail: string): Promise<void> =>
		guard(client.requestEmailChange({ newEmail })).then(() => undefined),

	credentials: (): Promise<ListCredentialsResponse> => guard(client.listCredentials({})),

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
