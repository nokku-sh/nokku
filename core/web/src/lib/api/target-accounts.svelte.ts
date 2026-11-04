import { MAX_PAGE_SIZE } from '#lib/config.js';
import { TargetAccountService, SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { useBulkMutation } from './bulk';

export const targetAccount = {
	list: (
		opts: () => {
			targetId?: string;
			limit?: number;
			offset?: number;
			query?: string;
		}
	) =>
		useQuery(
			TargetAccountService.method.listTargetAccounts,
			() => ({
				targetId: opts().targetId || '',
				query: opts().query,
				limit: opts().limit ?? MAX_PAGE_SIZE,
				offset: opts().offset ?? 0
			}),
			() => ({
				enabled: !!opts().targetId
			})
		),

	addAccount: () => useMutation(TargetAccountService.method.addTargetAccount),
	removeAccount: () => useMutation(TargetAccountService.method.removeTargetAccount),
	// One call per account and kind, the toast says what the whole grant did.
	grant: (done: (ok: number) => string) =>
		useBulkMutation(TargetAccountService.method.addSubjects, done),
	revoke: (done: (ok: number) => string) =>
		useBulkMutation(TargetAccountService.method.removeSubjects, done),
	removeSubjects: () => useMutation(TargetAccountService.method.removeSubjects),
	revokeSubject: () =>
		useMutation(TargetAccountService.method.revokeAllAccess, {
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
