import { PrincipalService, PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';

export const principal = {
	// Queries
	list: (
		opts: () => {
			targetId?: string;
			limit?: number;
			offset?: number;
			query?: string;
			type?: PrincipalType;
		}
	) =>
		useQuery(
			PrincipalService.method.listPrincipals,
			() => ({
				targetId: opts().targetId || '',
				limit: opts().limit,
				offset: opts().offset,
				query: opts().query,
				type: opts().type,
				workspaceId: workspaceID.current
			}),
			() => ({
				enabled: !!opts().targetId
			})
		),

	// Mutations
	set: () =>
		useMutation(PrincipalService.method.setPrincipals, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	addSubjects: () =>
		useMutation(PrincipalService.method.addSubjectsToPrincipal, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	removeSubjects: () =>
		useMutation(PrincipalService.method.removeSubjectsFromPrincipal, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	revokeSubject: () =>
		useMutation(PrincipalService.method.revokeAllAccess, {
			onSuccess: (_, variables) => {
				switch (variables.type) {
					case PrincipalType.USER:
						toast.success('User access revoked');
						break;
					case PrincipalType.TEAM:
						toast.success('Team access revoked');
						break;
					case PrincipalType.SERVICE_ACCOUNT:
						toast.success('Service account access revoked');
						break;
				}
			},
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		})
};
