import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { SSOService } from '#lib/gen/nokku/v1/sso_pb.js';

export const sso = {
	list: () => useQuery(SSOService.method.listSSOProviders, {}, { select: (res) => res.providers }),

	put: () =>
		useMutation(SSOService.method.putSSOProvider, {
			onSuccess: () => toast.success('Provider saved')
		}),
	delete: () =>
		useMutation(SSOService.method.deleteSSOProvider, {
			onSuccess: () => toast.success('Provider removed')
		})
};
