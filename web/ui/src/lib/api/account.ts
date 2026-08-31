import { Code, ConnectError } from '@connectrpc/connect';
import { handleSessionExpired, httpFetch } from './client';

// The account surface is kagi's /auth/account/*: profile, password,
// credentials, backup codes, sessions, and deletion. These helpers carry the
// HttpOnly session cookie and parse kagi's JSON.

export interface AccountUser {
	id: string;
	email: string;
	displayName: string;
	active: boolean;
	emailVerified: boolean;
	disablePasswordReset: boolean;
	picture?: string;
	createdAt: string;
	updatedAt: string;
}

export interface AccountCredential {
	id: string;
	type: string;
	provider?: string;
	subject?: string;
	label?: string;
	createdAt: string;
}

export interface AccountSession {
	id: string;
	kind: string;
	method: string;
	identityId?: string;
	binding?: string;
	current: boolean;
	expiresAt?: string;
	lastSeenAt?: string;
}

// accountFetch wraps httpFetch: an expired or revoked session (401) bounces
// to /login exactly like a failed whoami used to.
async function accountFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
	try {
		return await httpFetch(input, init);
	} catch (err) {
		if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
			handleSessionExpired();
		}
		throw err;
	}
}

function post(url: string, body: unknown): Promise<Response> {
	return accountFetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
}

async function json<T>(res: Response): Promise<T> {
	return (await res.json()) as T;
}

export const account = {
	user: (): Promise<AccountUser> => accountFetch('/auth/account').then((r) => json<AccountUser>(r)),

	update: (patch: { displayName?: string; picture?: string; disablePasswordReset?: boolean }) =>
		post('/auth/account/update', patch).then((r) => json<AccountUser>(r)),

	changePassword: (currentPassword: string, newPassword: string): Promise<void> =>
		post('/auth/account/password', { currentPassword, newPassword }).then(() => undefined),

	removePassword: (currentPassword: string): Promise<void> =>
		post('/auth/account/password/remove', { currentPassword }).then(() => undefined),

	credentials: (): Promise<{ credentials: AccountCredential[] }> =>
		accountFetch('/auth/account/credentials').then((r) => json(r)),

	renameCredential: (id: string, label: string): Promise<void> =>
		post('/auth/account/credentials/rename', { id, label }).then(() => undefined),

	removeCredential: (id: string): Promise<void> =>
		post('/auth/account/credentials/remove', { id }).then(() => undefined),

	removeIdentity: (provider: string): Promise<void> =>
		post('/auth/account/identities/remove', { provider }).then(() => undefined),

	backupCodes: (): Promise<{ codes: AccountCredential[] }> =>
		accountFetch('/auth/account/backup-codes').then((r) => json(r)),

	rotateBackupCodes: (): Promise<{ codes: string[] }> =>
		post('/auth/account/backup-codes/rotate', {}).then((r) => json(r)),

	removeBackupCodes: (): Promise<void> =>
		post('/auth/account/backup-codes/remove', {}).then(() => undefined),

	sessions: (): Promise<{ sessions: AccountSession[] }> =>
		accountFetch('/auth/account/sessions').then((r) => json(r)),

	removeSession: (id: string): Promise<void> =>
		post('/auth/account/sessions/remove', { id }).then(() => undefined),

	deleteAccount: (): Promise<void> => post('/auth/account/delete', {}).then(() => undefined)
};
