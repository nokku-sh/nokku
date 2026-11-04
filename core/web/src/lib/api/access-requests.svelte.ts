import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import {
	AccessRequestService,
	type ListAccessRequestsRequestSchema
} from '#lib/gen/nokku/v1/access_request_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { LIVE } from './client';

export const accessRequests = {
	requestable: (when: () => boolean) =>
		useQuery(AccessRequestService.method.listRequestableAccounts, {}, () => ({
			enabled: when(),
			select: (res) => res.targets
		})),
	// Newest first, members get their own. Only views that show them poll, the sidebar reads the same answer.
	list: (
		input: MessageInitShape<typeof ListAccessRequestsRequestSchema> = { limit: 100 },
		{ when = () => true, live = true }: { when?: () => boolean; live?: boolean } = {}
	) =>
		useQuery(AccessRequestService.method.listAccessRequests, input, () => ({
			enabled: when(),
			...(live && { refetchInterval: LIVE })
		})),

	create: () =>
		useMutation(AccessRequestService.method.createAccessRequest, {
			onSuccess: () => toast.success('Request sent')
		}),
	approve: () =>
		useMutation(AccessRequestService.method.approveAccessRequest, {
			onSuccess: () => toast.success('Request approved')
		}),
	deny: () =>
		useMutation(AccessRequestService.method.denyAccessRequest, {
			onSuccess: () => toast.success('Request denied')
		}),
	cancel: () =>
		useMutation(AccessRequestService.method.cancelAccessRequest, {
			onSuccess: () => toast.success('Request cancelled')
		}),
	setTags: () =>
		useMutation(AccessRequestService.method.setRequestableTags, {
			onSuccess: () => toast.success('Requestable servers saved')
		})
};
