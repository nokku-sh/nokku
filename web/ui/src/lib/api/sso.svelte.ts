import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { WorkspaceDomainService } from '$lib/gen/nokku/v1/workspace_domain_pb';
import { SSOService } from '$lib/gen/nokku/v1/sso_pb';
import { workspaceID } from '$lib/store.svelte';

export const sso = {
	// Queries
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
			onSuccess: () => toast.success('OIDC provider updated'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	updateSAML: () =>
		useMutation(SSOService.method.updateSAMLProvider, {
			onSuccess: () => toast.success('SAML provider updated'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	check: () => useMutation(SSOService.method.checkSSO)
};

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
			onSuccess: () => toast.success('Domain created'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	delete: () =>
		useMutation(WorkspaceDomainService.method.deleteWorkspaceDomain, {
			onSuccess: () => toast.success('Domain deleted'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	verify: () =>
		useMutation(WorkspaceDomainService.method.verifyWorkspaceDomain, {
			onSuccess: () => toast.success('Domain verified'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	regenerate: () =>
		useMutation(WorkspaceDomainService.method.regenerateWorkspaceDomainToken, {
			onSuccess: () => toast.success('New token generated'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		})
};
