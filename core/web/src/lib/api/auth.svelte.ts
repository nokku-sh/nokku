import { createMutation } from '@tanstack/svelte-query';
import { createClient } from '@connectrpc/connect';
import { durationMs } from '@bufbuild/protobuf/wkt';
import { AuthService } from '#lib/gen/nokku/v1/auth_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { account } from './account';
import { queryClient, authTransport, leave, handleSessionExpired } from './client';

const client = createClient(AuthService, authTransport);

// Filling in a form for a call marked fresh has to fit in what is left of the 10 minutes.
const FORM_TIME = 5 * 60_000;

// whenFresh opens a form for a call marked fresh, like handing out a token. A session too old for it signs out and
// goes to the sign-in page, which comes back to back, so nothing typed is lost to the step-up.
export async function whenFresh(open: () => void, back?: string) {
	let freshFor: number;
	try {
		const current = (await account.sessions()).find((s) => s.current);
		freshFor = current?.freshFor ? durationMs(current.freshFor) : 0;
	} catch {
		// The server refuses an old session either way, this only saves the typing.
		open();
		return;
	}
	if (freshFor >= FORM_TIME) {
		open();
		return;
	}
	await client.logout({}).catch(() => {});
	handleSessionExpired(back);
}

export const auth = {
	// What this workspace lets people sign in with. Public.
	options: () =>
		useQuery(
			AuthService.method.getLoginOptions,
			{},
			{ staleTime: Infinity, refetchInterval: false }
		),

	// Always succeeds from the outside, so the form reveals no accounts.
	requestMagicLink: () => useMutation(AuthService.method.requestMagicLink),
	consumeMagicLink: () => useMutation(AuthService.method.consumeMagicLink),
	logout: () =>
		createMutation(() => ({
			mutationFn: () => client.logout({}),
			onSuccess: () => leave()
		})),
	confirmEmailChange: () =>
		useMutation(AuthService.method.confirmEmailChange, {
			onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['account'] })
		}),
	cancelEmailChange: () =>
		useMutation(AuthService.method.cancelEmailChange, {
			onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['account'] })
		})
};
