import { TokenKind, TokenService } from '$lib/gen/nokku/v1/token_pb';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';
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
