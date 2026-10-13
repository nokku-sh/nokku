import { JoinTokenKind, JoinTokenService } from '#lib/gen/nokku/v1/join_token_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { toast } from 'svelte-sonner';

export const token = {
	list: (kind: MaybeGetter<JoinTokenKind>) =>
		useQuery(JoinTokenService.method.listJoinTokens, () => ({ kind: extract(kind) })),

	create: () => useMutation(JoinTokenService.method.createJoinToken),
	remove: () =>
		useMutation(JoinTokenService.method.deleteJoinToken, {
			onSuccess: () => toast.success('Token revoked')
		})
};
