import { toast } from 'svelte-sonner';
import { createMutation } from '@tanstack/svelte-query';
import { createClient } from '@connectrpc/connect';
import { useMutation, useQuery } from '$lib/query';
import { WorkspaceDomainService } from '$lib/gen/nokku/v1/workspace_domain_pb';
import { SSOService } from '$lib/gen/nokku/v1/sso_pb';
import { AuthService, type DiscoverSSOResponse } from '$lib/gen/nokku/v1/auth_pb';
import { workspaceID } from '$lib/store.svelte';
import { authTransport } from './client';

const authClient = createClient(AuthService, authTransport);

// Home realm discovery is the Connect DiscoverSSO RPC: it answers which
// providers cover the email's domain. The domain rides along so the login
// buttons can hand it to the SSO flows, which resolve the provider's
// workspace from it. A half-typed email fails the schema's email rule; that
// is not a discovery failure, it just means "no provider yet", so it
// resolves to the empty result like an unknown domain does.
const emptyDiscovery = (): Discovery => ({
	hasSSO: false,
	enforce: false,
	domain: '',
	providers: []
});

export const sso = {
	// Queries
	// The API reports an unconfigured provider as an unset provider field
	// (not 404), so this never errors while the workspace has no SSO set up.
	// The oneof discriminates the protocol: config.case is 'oidc' or 'saml'.
	getProvider: () =>
		useQuery(
			SSOService.method.getSSOProvider,
			{ workspaceId: workspaceID.current },
			{ select: (res) => res.provider }
		),

	// Mutations
	updateProvider: () =>
		useMutation(SSOService.method.updateSSOProvider, {
			onSuccess: () => toast.success('SSO provider updated')
		}),
	// See emptyDiscovery note above.
	check: () =>
		createMutation<Discovery, Error, string>(() => ({
			mutationFn: async (email: string) => {
				const domain = email.split('@')[1] ?? '';
				let res: DiscoverSSOResponse;
				try {
					res = await authClient.discoverSSO({ email });
				} catch {
					return { ...emptyDiscovery(), domain };
				}
				return {
					hasSSO: res.hasSso ?? false,
					enforce: res.enforce ?? false,
					domain,
					providers: res.providers.map((p) => ({
						method: p.method ?? '',
						provider: p.provider ?? '',
						name: p.name ?? ''
					}))
				};
			}
		}))
};

interface Discovery {
	hasSSO: boolean;
	enforce: boolean;
	domain: string;
	providers: { method: string; provider: string; name: string }[];
}

export const domain = {
	// Queries
	list: () =>
		useQuery(
			WorkspaceDomainService.method.listWorkspaceDomains,
			{ workspaceId: workspaceID.current },
			{ select: (res) => res.domains }
		),

	// Mutations
	create: () =>
		useMutation(WorkspaceDomainService.method.createWorkspaceDomain, {
			onSuccess: () => toast.success('Domain created')
		}),
	delete: () =>
		useMutation(WorkspaceDomainService.method.deleteWorkspaceDomain, {
			onSuccess: () => toast.success('Domain deleted')
		}),
	verify: () =>
		useMutation(WorkspaceDomainService.method.verifyWorkspaceDomain, {
			onSuccess: () => toast.success('Domain verified')
		}),
	regenerate: () =>
		useMutation(WorkspaceDomainService.method.regenerateWorkspaceDomainToken, {
			onSuccess: () => toast.success('New token generated')
		})
};
