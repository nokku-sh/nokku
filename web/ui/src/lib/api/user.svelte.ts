import { UserService } from '$lib/gen/nokku/v1/user_pb';
import { goto } from '$app/navigation';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { queryClient } from './client';
import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { pageIndex, pageSize } from '$lib/store.svelte';

export const user = {
	// Queries
	self: () => useQuery(UserService.method.whoami, {}, { select: (res) => res.user }),
	listLinkedAccounts: () =>
		useQuery(UserService.method.listLinkedAccounts, {}, { select: (res) => res.accounts }),
	activity: (filters: {
		userID: string;
		search?: string;
		startDate?: Timestamp;
		endDate?: Timestamp;
	}) => {
		// Filter out undefined/empty values
		const cleanFilters = Object.fromEntries(
			Object.entries(filters ?? {}).filter(([_, v]) => v !== undefined && v !== '' && v !== null)
		);

		return useQuery(
			UtilService.method.listAuditLogs,
			{
				actorIds: [filters.userID],
				limit: pageSize.current,
				offset: pageIndex.current,
				...cleanFilters
			},
			{}
		);
	},
	listUserDevices: () =>
		useQuery(UserService.method.listUserDevices, undefined, { select: (res) => res.devices }),

	// Mutations
	updateProfile: () => useMutation(UserService.method.updateProfile),
	deleteAccount: () =>
		useMutation(UserService.method.deleteAccount, {
			onSuccess: () => {
				void queryClient.cancelQueries();
				queryClient.clear();
				void goto('/login');
				toast.success('Account deleted, bye 👋');
			}
		}),
	deleteUserDevice: () => useMutation(UserService.method.deleteUserDevice),
	unlinkAccount: () => useMutation(UserService.method.unlinkAccount),
	setEmailRecovery: () =>
		useMutation(UserService.method.setEmailRecovery, {
			onSuccess: (_, variables) =>
				toast.success(`Email recovery ${variables.enable ? 'enabled' : 'disabled'}`)
		})
};
