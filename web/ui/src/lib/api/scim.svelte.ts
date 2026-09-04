import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { SCIMService } from '$lib/gen/nokku/v1/scim_pb';
import { workspaceID } from '$lib/store.svelte';

// SCIM connector token management. The SCIM endpoint itself lives at
// /scim/v2/{workspaceId} and authenticates with these tokens; the plaintext
// is only ever seen in the create-token response.
export const scim = {
	// Queries
	listTokens: () =>
		useQuery(
			SCIMService.method.listSCIMTokens,
			{ workspaceId: workspaceID.current },
			{ select: (res) => res.tokens ?? [] }
		),

	// Mutations
	createToken: () =>
		useMutation(SCIMService.method.createSCIMToken, {
			onSuccess: () => toast.success('Connector token created')
		}),
	deleteToken: () =>
		useMutation(SCIMService.method.deleteSCIMToken, {
			onSuccess: () => toast.success('Connector token revoked')
		})
};
