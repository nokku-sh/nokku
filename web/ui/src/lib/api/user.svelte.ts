import { createMutation, createQuery } from '@tanstack/svelte-query';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account, type AccountCredential } from './account';
import { useQuery } from '$lib/query';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import type { User } from '$lib/gen/nokku/v1/account_pb';
import { pageIndex, pageSize } from '$lib/store.svelte';

const invalidateAccount = () => queryClient.invalidateQueries({ queryKey: ['account'] });

const identityTypes = ['oidc', 'oauth2', 'saml'];

export interface LinkedAccount {
	providerId: string;
	provider: string;
	protocol: string;
	createdAt?: Timestamp;
}

function toLinkedAccount(c: AccountCredential): LinkedAccount {
	return {
		providerId: c.subject ?? '',
		provider: c.provider ?? '',
		protocol: c.type,
		createdAt: c.createdAt
	};
}

export const user = {
	self: () =>
		createQuery<User>(() => ({
			queryKey: ['account'],
			queryFn: () => account.user()
		})),
	listLinkedAccounts: () =>
		createQuery<LinkedAccount[]>(() => ({
			queryKey: ['account', 'credentials', 'linked'],
			queryFn: async () => {
				const credentials = await account.credentials();
				return credentials.filter((c) => identityTypes.includes(c.type)).map(toLinkedAccount);
			}
		})),
	activity: (filters: {
		userID: string;
		search?: string;
		startDate?: Timestamp;
		endDate?: Timestamp;
	}) => {
		const { userID, ...rest } = filters;
		const cleanFilters = Object.fromEntries(
			Object.entries(rest ?? {}).filter(([, v]) => v !== undefined && v !== '' && v !== null)
		);

		return useQuery(
			UtilService.method.listAuditLogs,
			{
				// Empty opts out of the workspace interceptor, a personal read.
				workspaceId: '',
				actorIds: [userID],
				limit: pageSize.current,
				offset: pageIndex.current,
				...cleanFilters
			},
			{}
		);
	},

	updateProfile: () =>
		createMutation<User, Error, { name?: string; picture?: string; email?: string }>(() => ({
			mutationFn: (variables) =>
				account.update({
					displayName: variables.name,
					picture: variables.picture
				}),
			onSuccess: (updated) => {
				queryClient.setQueryData(['account'], updated);
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
		createMutation<User, Error, { enable: boolean }>(() => ({
			mutationFn: ({ enable }) => account.update({ disablePasswordReset: !enable }),
			onSuccess: (updated) => {
				queryClient.setQueryData(['account'], updated);
				toast.success(`Email recovery ${updated.disablePasswordReset ? 'disabled' : 'enabled'}`);
			}
		}))
};
