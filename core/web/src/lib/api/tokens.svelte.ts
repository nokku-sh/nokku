import { JoinTokenService } from '#lib/gen/nokku/v1/join_token_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { toast } from 'svelte-sonner';

export const token = {
	list: () => useQuery(JoinTokenService.method.listJoinTokens, {}),
	create: () => useMutation(JoinTokenService.method.createJoinToken),
	remove: () =>
		useMutation(JoinTokenService.method.deleteJoinToken, {
			onSuccess: () => toast.success('Token revoked')
		})
};
