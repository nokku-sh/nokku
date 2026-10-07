import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { SCIMService } from '#lib/gen/nokku/v1/scim_pb.js';

export const scim = {
	listTokens: () =>
		useQuery(SCIMService.method.listSCIMTokens, {}, () => ({ select: (res) => res.tokens ?? [] })),

	createToken: () =>
		useMutation(SCIMService.method.createSCIMToken, {
			onSuccess: () => toast.success('Connector token created')
		}),
	deleteToken: () =>
		useMutation(SCIMService.method.deleteSCIMToken, {
			onSuccess: () => toast.success('Connector token revoked')
		})
};
