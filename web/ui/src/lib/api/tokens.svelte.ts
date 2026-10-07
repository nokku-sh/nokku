import { TokenKind, TokenService } from '#lib/gen/nokku/v1/token_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { toast } from 'svelte-sonner';

export const token = {
	list: (kind: MaybeGetter<TokenKind>) =>
		useQuery(TokenService.method.listTokens, () => ({ kind: extract(kind) })),

	create: () => useMutation(TokenService.method.createToken),
	remove: () =>
		useMutation(TokenService.method.deleteToken, {
			onSuccess: () => toast.success('Token revoked')
		})
};
