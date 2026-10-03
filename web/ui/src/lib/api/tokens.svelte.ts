import { TokenKind, TokenService } from '#lib/gen/nokku/v1/token_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { workspaceID } from '#lib/store.svelte.js';
import { toast } from 'svelte-sonner';

export const token = {
	list: (kind: MaybeGetter<TokenKind>) =>
		useQuery(
			TokenService.method.listTokens,
			() => ({ workspaceId: workspaceID.current, kind: extract(kind) }),
			() => ({ enabled: !!workspaceID.current })
		),

	create: () => useMutation(TokenService.method.createToken),
	remove: () =>
		useMutation(TokenService.method.deleteToken, {
			onSuccess: () => toast.success('Token revoked')
		})
};
