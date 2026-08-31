import { create } from '@bufbuild/protobuf';
import { timestampFromDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import { createMutation, createQuery } from '@tanstack/svelte-query';
import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account, type AccountUser } from './account';
import { useQuery } from '$lib/query';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import { UserSchema, type User } from '$lib/gen/nokku/v1/user_pb';
import { pageIndex, pageSize } from '$lib/store.svelte';

// The account reads and mutations are the /auth/account surface. This
// module maps its JSON onto the proto shapes the pages already consume,
// so the components keep working unchanged.

const invalidateAccount = () => queryClient.invalidateQueries({ queryKey: ['account'] });

function toTimestamp(iso: string): Timestamp {
	return timestampFromDate(new Date(iso));
}

function toUser(u: AccountUser): User {
	return create(UserSchema, {
		id: u.id,
		name: u.displayName,
		email: u.email,
		emailVerified: u.emailVerified,
		picture: u.picture === '' ? undefined : u.picture,
		enableEmailRecovery: !u.disablePasswordReset,
		createdAt: toTimestamp(u.createdAt),
		updatedAt: toTimestamp(u.updatedAt)
	});
}

const identityTypes = ['oidc', 'oauth2', 'saml'];

// The account endpoint returns raw JSON credentials; linked identities are
// mapped onto this local shape. The proto type was dropped from user.proto
// because this is not a proto-backed surface.
export interface LinkedAccount {
	providerId: string;
	provider: string;
	protocol: string;
	createdAt: Timestamp;
}

export const user = {
	// Queries
	self: () =>
		createQuery<User>(() => ({
			queryKey: ['account'],
			queryFn: async () => toUser(await account.user())
		})),
	listLinkedAccounts: () =>
		createQuery<LinkedAccount[]>(() => ({
			queryKey: ['account', 'credentials'],
			queryFn: async () => {
				const { credentials } = await account.credentials();
				return credentials
					.filter((c) => identityTypes.includes(c.type))
					.map((c) => ({
						providerId: c.subject ?? '',
						provider: c.provider ?? '',
						protocol: c.type,
						createdAt: toTimestamp(c.createdAt)
					}));
			}
		})),
	activity: (filters: {
		userID: string;
		search?: string;
		startDate?: Timestamp;
		endDate?: Timestamp;
	}) => {
		// userID selects the actor for the query; the rest are extra filters.
		const { userID, ...rest } = filters;
		const cleanFilters = Object.fromEntries(
			Object.entries(rest ?? {}).filter(([, v]) => v !== undefined && v !== '' && v !== null)
		);

		return useQuery(
			UtilService.method.listAuditLogs,
			{
				// Empty workspaceId deliberately opts out of the workspace
				// interceptor so this stays a personal (global) read.
				workspaceId: '',
				actorIds: [userID],
				limit: pageSize.current,
				offset: pageIndex.current,
				...cleanFilters
			},
			{}
		);
	},

	// Mutations
	updateProfile: () =>
		createMutation<AccountUser, Error, { name?: string; picture?: string; email?: string }>(() => ({
			mutationFn: (variables) =>
				account.update({
					displayName: variables.name,
					picture: variables.picture
				}),
			onSuccess: (updated) => {
				queryClient.setQueryData(['account'], toUser(updated));
			}
		})),
	deleteAccount: () =>
		createMutation<void, Error, Record<string, never>>(() => ({
			mutationFn: () => account.deleteAccount(),
			onSuccess: () => {
				void queryClient.cancelQueries();
				queryClient.clear();
				void goto('/login');
				toast.success('Account deleted, bye 👋');
			}
		})),
	unlinkAccount: () =>
		createMutation<void, Error, { provider: string }>(() => ({
			mutationFn: ({ provider }) => account.removeIdentity(provider),
			onSuccess: invalidateAccount
		})),
	setEmailRecovery: () =>
		createMutation<AccountUser, Error, { enable: boolean }>(() => ({
			mutationFn: ({ enable }) => account.update({ disablePasswordReset: !enable }),
			onSuccess: (updated) => {
				queryClient.setQueryData(['account'], toUser(updated));
				toast.success(`Email recovery ${updated.disablePasswordReset ? 'disabled' : 'enabled'}`);
			}
		}))
};
