import { MAX_PAGE_SIZE } from '#lib/config.js';
import {
	TargetAccountService,
	SubjectKind,
	type GrantSpecSchema,
	type RevokeSpecSchema
} from '#lib/gen/nokku/v1/target_account_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { keepPreviousData } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';

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
	// What a grant on many servers would do, asked again whenever the form changes.
	planGrant: (spec: () => MessageInitShape<typeof GrantSpecSchema>, when: () => boolean) =>
		useQuery(
			TargetAccountService.method.planGrant,
			() => ({ grant: spec() }),
			() => ({ enabled: when(), placeholderData: keepPreviousData })
		),
	grant: () => useMutation(TargetAccountService.method.grant),
	planRevoke: (spec: () => MessageInitShape<typeof RevokeSpecSchema>, when: () => boolean) =>
		useQuery(
			TargetAccountService.method.planRevoke,
			() => ({ revoke: spec() }),
			() => ({ enabled: when(), placeholderData: keepPreviousData })
		),
	revoke: () => useMutation(TargetAccountService.method.revoke),
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
