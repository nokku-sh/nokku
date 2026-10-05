import { MAX_PAGE_SIZE } from '#lib/config.js';
import { PrincipalService, SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';

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

	addAccount: () => useMutation(PrincipalService.method.addPrincipal),
	removeAccount: () => useMutation(PrincipalService.method.removePrincipal),
	addSubjects: () => useMutation(PrincipalService.method.addSubjectsToPrincipal),
	removeSubjects: () => useMutation(PrincipalService.method.removeSubjectsFromPrincipal),
	revokeSubject: () =>
		useMutation(PrincipalService.method.revokeAllAccess, {
			onSuccess: (_, variables) => {
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
