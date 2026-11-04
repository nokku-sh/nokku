import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
import { createInfiniteQuery, createMutation, createQuery } from '@tanstack/svelte-query';
import { callUnaryMethod } from '@connectrpc/connect-query-core';
import { toast } from 'svelte-sonner';
import { leave, queryClient } from './client';
import { account } from './account';
import { useQuery, useTransport } from '#lib/query/index.js';
import {
	UtilService,
	type AuditLogFilterSchema,
	type ListMyActivityResponse
} from '#lib/gen/nokku/v1/util_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import type { User } from '#lib/gen/nokku/v1/account_pb.js';
import { atLeast } from '#lib/roles.js';

const invalidateAccount = () => queryClient.invalidateQueries({ queryKey: ['account'] });

const FEED_PAGE = 25;

export type ActivityFilter = MessageInitShape<typeof AuditLogFilterSchema>;

export const user = {
	self: () =>
		createQuery<User>(() => ({
			queryKey: ['account'],
			queryFn: () => account.user()
		})),

	// What the caller's role allows. The server enforces it, this only hides what it would refuse.
	can: () => {
		const me = user.self();
		return {
			/** The workspace overview: lists, audit log, recordings. */
			get view() {
				return atLeast(me.data?.role, WorkspaceRole.VIEWER);
			},
			/** Targets, daemons, the CA, teams, service accounts and grants. */
			get edit() {
				return atLeast(me.data?.role, WorkspaceRole.EDITOR);
			},
			/** People, invites and tokens. */
			get admin() {
				return atLeast(me.data?.role, WorkspaceRole.ADMIN);
			},
			/** Workspace settings, SSO, SCIM, the license and the workspace itself. */
			get own() {
				return atLeast(me.data?.role, WorkspaceRole.OWNER);
			}
		};
	},

	// The caller's own events, newest first, filtered on the server. Pages by offset for "Load more".
	activityFeed: (filter: () => ActivityFilter | undefined, enabled: () => boolean) => {
		const transport = useTransport();
		return createInfiniteQuery(() => ({
			queryKey: ['account', 'activity', filter() ?? {}],
			queryFn: ({ pageParam }: { pageParam: number }) =>
				callUnaryMethod(transport, UtilService.method.listMyActivity, {
					limit: FEED_PAGE,
					offset: pageParam,
					filter: filter()
				}),
			initialPageParam: 0,
			getNextPageParam: (last: ListMyActivityResponse, pages: ListMyActivityResponse[]) => {
				const loaded = pages.reduce((n, p) => n + p.logs.length, 0);
				return loaded < last.total ? loaded : undefined;
			},
			// A poll would fetch every loaded page again.
			refetchInterval: false,
			enabled: enabled()
		}));
	},

	// The newest of the caller's events that match, with how many there are.
	activity: (filter: () => ActivityFilter, enabled: () => boolean, limit = 1) =>
		useQuery(
			UtilService.method.listMyActivity,
			() => ({ limit, filter: filter() }),
			() => ({
				enabled: enabled()
			})
		),

	updateProfile: () =>
		createMutation<User, Error, { name?: string }>(() => ({
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
