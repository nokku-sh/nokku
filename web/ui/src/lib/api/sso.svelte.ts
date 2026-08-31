import { toast } from 'svelte-sonner';
import { createMutation } from '@tanstack/svelte-query';
import { useMutation, useQuery } from '$lib/query';
import { WorkspaceDomainService } from '$lib/gen/nokku/v1/workspace_domain_pb';
import { SSOService } from '$lib/gen/nokku/v1/sso_pb';
import { workspaceID } from '$lib/store.svelte';

export const sso = {
	// Queries
	// The API reports an unconfigured provider as an empty provider (not
	// 404), so these never error while the workspace has no SSO set up yet.
	getOIDC: () =>
		useQuery(
			SSOService.method.getOIDCProvider,
			{ workspaceId: workspaceID.current },
			{ select: (res) => res.oidcProvider }
		),
	getSAML: () =>
		useQuery(
			SSOService.method.getSAMLProvider,
			{ workspaceId: workspaceID.current },
			{ select: (res) => res.samlProvider }
		),

	// Mutations
	updateOIDC: () =>
		useMutation(SSOService.method.updateOIDCProvider, {
			onSuccess: () => toast.success('OIDC provider updated')
		}),
	updateSAML: () =>
		useMutation(SSOService.method.updateSAMLProvider, {
			onSuccess: () => toast.success('SAML provider updated')
		}),
	// Home realm discovery is the backend's mounted endpoint: it answers which
	// providers cover the email's domain. The domain rides along so the
	// login buttons can hand it to the SSO flows, which resolve the
	// provider's workspace from it.
	check: () =>
		createMutation<Discovery, Error, string>(() => ({
			mutationFn: async (email: string) => {
				const domain = email.split('@')[1] ?? '';
				const res = await fetch(`/auth/sso/discover?email=${encodeURIComponent(email)}`);
				const data = (await res.json()) as Omit<Discovery, 'domain'>;
				return { ...data, domain };
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
