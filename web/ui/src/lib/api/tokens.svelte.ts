import { TokenKind, TokenService } from '$lib/gen/nokku/v1/token_pb';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';
import { toast } from 'svelte-sonner';

export const token = {
	list: (kind: TokenKind) =>
		useQuery(
			TokenService.method.listTokens,
			{ workspaceId: workspaceID.current, kind },
			{ enabled: !!workspaceID.current }
		),

	create: () => useMutation(TokenService.method.createToken),
	remove: () =>
		useMutation(TokenService.method.deleteToken, {
			onSuccess: () => toast.success('Token revoked')
		})
};
