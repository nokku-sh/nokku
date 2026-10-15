import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { SSOService } from '#lib/gen/nokku/v1/sso_pb.js';

/** Starts a test sign-in. It is a full page load, the provider sends the browser back to the settings page. */
export const testHref = (providerId: string) =>
	`/oidc/test?provider=${encodeURIComponent(providerId)}`;

export const sso = {
	list: () => useQuery(SSOService.method.listSSOProviders, {}, { select: (res) => res.providers }),
	redirectUri: () =>
		useQuery(SSOService.method.listSSOProviders, {}, { select: (res) => res.redirectUri }),

	/** A test sign-in, read once the provider sends the owner back. */
	test: (id: () => string | undefined) =>
		useQuery(
			SSOService.method.getSSOTest,
			() => ({ id: id() ?? '' }),
			// A result never changes. Refetching it only risks showing it as expired.
			() => ({
				enabled: !!id(),
				select: (res) => res.test,
				retry: false,
				staleTime: Infinity,
				refetchOnWindowFocus: false,
				refetchInterval: false
			})
		),

	// Silent, a sheet reports through its footer and adding moves on to the test.
	put: () => useMutation(SSOService.method.putSSOProvider),
	delete: () =>
		useMutation(SSOService.method.deleteSSOProvider, {
			onSuccess: () => toast.success('Provider removed')
		})
};
