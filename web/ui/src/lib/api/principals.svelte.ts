import { PrincipalService, PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
import { TargetService } from '$lib/gen/nokku/v1/target_pb';
import { queryClient } from '$lib/api/client';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { pageIndex, pageSize, workspaceID } from '$lib/store.svelte';

// A grant change also moves the subject's access snapshot
// (TargetService.GetSubjectAccess), which the assign page and dashboard read
// for their access badges. The global mutation cache only invalidates the
// mutating service, so refresh the snapshot alongside it.
const invalidateAccess = () =>
	queryClient.invalidateQueries({ queryKey: ['connect-query', TargetService.typeName] });

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
				limit: opts().limit ?? pageSize.current,
				offset: opts().offset ?? pageIndex.current,
				workspaceId: workspaceID.current
			}),
			() => ({
				enabled: !!opts().targetId
			})
		),

	// Mutations
	set: () => useMutation(PrincipalService.method.setPrincipals, { onSuccess: invalidateAccess }),
	addAccount: () =>
		useMutation(PrincipalService.method.addPrincipal, { onSuccess: invalidateAccess }),
	removeAccount: () =>
		useMutation(PrincipalService.method.removePrincipal, { onSuccess: invalidateAccess }),
	addSubjects: () =>
		useMutation(PrincipalService.method.addSubjectsToPrincipal, { onSuccess: invalidateAccess }),
	removeSubjects: () =>
		useMutation(PrincipalService.method.removeSubjectsFromPrincipal, {
			onSuccess: invalidateAccess
		}),
	revokeSubject: () =>
		useMutation(PrincipalService.method.revokeAllAccess, {
			onSuccess: (_, variables) => {
				invalidateAccess();
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
