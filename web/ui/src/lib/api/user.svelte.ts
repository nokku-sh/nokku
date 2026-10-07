import { createInfiniteQuery, createMutation, createQuery } from '@tanstack/svelte-query';
import { callUnaryMethod } from '@connectrpc/connect-query-core';
import { toast } from 'svelte-sonner';
import { leave, queryClient } from './client';
import { account } from './account';
import { useTransport } from '#lib/query/index.js';
import { UtilService, type ListMyActivityResponse } from '#lib/gen/nokku/v1/util_pb.js';
import type { User } from '#lib/gen/nokku/v1/account_pb.js';
import { atLeast } from '#lib/roles.js';

const invalidateAccount = () => queryClient.invalidateQueries({ queryKey: ['account'] });

const FEED_PAGE = 25;

export const user = {
	self: () =>
		createQuery<User>(() => ({
			queryKey: ['account'],
			queryFn: () => account.user()
		})),

	// What the caller's role allows, matching the (access) option of the RPCs.
	// The backend enforces it, this only hides what it would refuse.
	can: () => {
		const me = user.self();
		return {
			/** The workspace overview: lists, audit log, recordings. */
			get view() {
				return atLeast(me.data?.role, 'viewer');
			},
			/** Targets, daemons, CAs, teams, service accounts and grants. */
			get edit() {
				return atLeast(me.data?.role, 'editor');
			},
			/** People, invites, tokens and workspace settings. */
			get admin() {
				return atLeast(me.data?.role, 'admin');
			},
			/** SSO, SCIM, the license and the workspace itself. */
			get own() {
				return atLeast(me.data?.role, 'owner');
			}
		};
	},

	// The caller's own events, newest first. Pages by offset for "Load more".
	activityFeed: (enabled: () => boolean) => {
		const transport = useTransport();
		return createInfiniteQuery(() => ({
			queryKey: ['account', 'activity'],
			queryFn: ({ pageParam }: { pageParam: number }) =>
				callUnaryMethod(transport, UtilService.method.listMyActivity, {
					limit: FEED_PAGE,
					offset: pageParam
				}),
			initialPageParam: 0,
			getNextPageParam: (last: ListMyActivityResponse, pages: ListMyActivityResponse[]) => {
				const loaded = pages.reduce((n, p) => n + p.logs.length, 0);
				return loaded < last.total ? loaded : undefined;
			},
			enabled: enabled()
		}));
	},

	updateProfile: () =>
		createMutation<User, Error, { name?: string; picture?: string }>(() => ({
			mutationFn: (variables) => account.update(variables),
			onSuccess: (updated) => {
				queryClient.setQueryData(['account'], updated);
			}
		})),
	requestEmailChange: () =>
		createMutation<void, Error, { newEmail: string }>(() => ({
			mutationFn: ({ newEmail }) => account.requestEmailChange(newEmail),
			onSuccess: invalidateAccount
		})),
	deleteAccount: () =>
		createMutation<void, Error, Record<string, never>>(() => ({
			mutationFn: () => account.deleteAccount(),
			onSuccess: () => {
				void queryClient.cancelQueries();
				queryClient.clear();
				toast.success('Account deleted, bye');
				leave();
			}
		}))
};
