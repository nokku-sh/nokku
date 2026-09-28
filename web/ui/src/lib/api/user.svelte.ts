import { MAX_PAGE_SIZE } from '$lib/config';
import { createInfiniteQuery, createMutation, createQuery } from '@tanstack/svelte-query';
import { callUnaryMethod } from '@connectrpc/connect-query-core';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { queryClient } from './client';
import { account, type AccountCredential } from './account';
import { useQuery, useTransport } from '$lib/query';
import { cleanFilters, type AuditFilter, type AuditQuery } from './workspaces.svelte';
import { UtilService, type ListAuditLogsResponse } from '$lib/gen/nokku/v1/util_pb';
import type { User } from '$lib/gen/nokku/v1/account_pb';

const invalidateAccount = () => queryClient.invalidateQueries({ queryKey: ['account'] });

const FEED_PAGE = 25;

const identityTypes = ['oidc', 'oauth2', 'saml'];

export interface LinkedAccount {
	providerId: string;
	provider: string;
	protocol: string;
	createdAt?: Timestamp;
	lastUsedAt?: Timestamp;
}

function toLinkedAccount(c: AccountCredential): LinkedAccount {
	return {
		providerId: c.subject ?? '',
		provider: c.provider ?? '',
		protocol: c.type,
		createdAt: c.createdAt,
		lastUsedAt: c.lastUsedAt
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
	// The personal log is always the caller's own, across workspaces.
	activity: (opts: () => AuditQuery & { enabled: boolean }) =>
		useQuery(
			UtilService.method.listAuditLogs,
			() => {
				const { filter, limit, offset } = opts();
				return {
					// Empty opts out of the workspace interceptor, a personal read.
					workspaceId: '',
					limit: limit ?? MAX_PAGE_SIZE,
					offset: offset ?? 0,
					filter: cleanFilters(filter) as AuditFilter
				};
			},
			() => ({ enabled: opts().enabled })
		),

	// Pages by offset for "Load more". The key is plain strings, timestamps
	// hold bigints that can't be hashed into a query key.
	activityFeed: (opts: () => { enabled: boolean; filter: AuditFilter; key: string[] }) => {
		const transport = useTransport();
		return createInfiniteQuery(() => ({
			queryKey: ['account', 'activity', ...opts().key],
			queryFn: ({ pageParam }: { pageParam: number }) =>
				callUnaryMethod(transport, UtilService.method.listAuditLogs, {
					workspaceId: '',
					limit: FEED_PAGE,
					offset: pageParam,
					filter: cleanFilters(opts().filter) as AuditFilter
				}),
			initialPageParam: 0,
			getNextPageParam: (last: ListAuditLogsResponse, pages: ListAuditLogsResponse[]) => {
				const loaded = pages.reduce((n, p) => n + p.logs.length, 0);
				return loaded < last.total ? loaded : undefined;
			},
			enabled: opts().enabled
		}));
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
