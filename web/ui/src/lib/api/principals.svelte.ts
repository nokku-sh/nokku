import { PrincipalService, PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { pageIndex, pageSize, workspaceID } from '$lib/store.svelte';

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
				query: opts().query,
				type: opts().type,
				limit: pageSize.current,
				offset: pageIndex.current,
				workspaceId: workspaceID.current
			}),
			() => ({
				enabled: !!opts().targetId
			})
		),

	// Mutations
	set: () => useMutation(PrincipalService.method.setPrincipals),
	addSubjects: () => useMutation(PrincipalService.method.addSubjectsToPrincipal),
	removeSubjects: () => useMutation(PrincipalService.method.removeSubjectsFromPrincipal),
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
			}
		})
};
