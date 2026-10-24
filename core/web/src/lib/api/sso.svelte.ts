import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { SSOService } from '#lib/gen/nokku/v1/sso_pb.js';

export const sso = {
	list: () => useQuery(SSOService.method.listSSOProviders, {}, { select: (res) => res.providers }),
	redirectUri: () =>
		useQuery(SSOService.method.listSSOProviders, {}, { select: (res) => res.redirectUri }),

	// Silent, a sheet reports through its footer and adding opens the new provider's sheet.
	put: () => useMutation(SSOService.method.putSSOProvider),
	delete: () =>
		useMutation(SSOService.method.deleteSSOProvider, {
			onSuccess: () => toast.success('Provider removed')
		})
};
