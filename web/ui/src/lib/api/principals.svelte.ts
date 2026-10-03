import { MAX_PAGE_SIZE } from '#lib/config.js';
import { PrincipalService, SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
import { TargetService } from '#lib/gen/nokku/v1/target_pb.js';
import { queryClient } from '#lib/api/client.js';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';

// The global mutation cache only invalidates the mutating service, but grant
// changes also move TargetService.GetSubjectAccess.
const invalidateAccess = () =>
	queryClient.invalidateQueries({ queryKey: ['connect-query', TargetService.typeName] });

export const principal = {
	list: (
		opts: () => {
			targetId?: string;
			limit?: number;
			offset?: number;
			query?: string;
		}
	) =>
		useQuery(
			PrincipalService.method.listPrincipals,
			() => ({
				targetId: opts().targetId || '',
				query: opts().query,
				limit: opts().limit ?? MAX_PAGE_SIZE,
				offset: opts().offset ?? 0,
				workspaceId: workspaceID.current
			}),
			() => ({
				enabled: !!workspaceID.current && !!opts().targetId
			})
		),

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
				switch (variables.kind) {
					case SubjectKind.USER:
						toast.success('User access revoked');
						break;
					case SubjectKind.TEAM:
						toast.success('Team access revoked');
						break;
					case SubjectKind.SERVICE_ACCOUNT:
						toast.success('Service account access revoked');
						break;
				}
			}
		})
};
