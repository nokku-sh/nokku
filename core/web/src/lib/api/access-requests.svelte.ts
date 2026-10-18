import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { AccessRequestService } from '#lib/gen/nokku/v1/access_request_pb.js';

export const accessRequests = {
	requestable: (when: () => boolean) =>
		useQuery(AccessRequestService.method.listRequestableAccounts, {}, () => ({
			enabled: when(),
			select: (res) => res.targets
		})),
	// The newest hundred, every status. Members get only their own.
	list: () => useQuery(AccessRequestService.method.listAccessRequests, { limit: 100 }),

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
