import { cliToken, inviteToken } from '$lib/store.svelte';
import type { LayoutLoad } from './$types';

export const ssr = false;
export const prerender = true;

export const load: LayoutLoad = async ({ url }) => {
	inviteToken.current = url.searchParams.get('invite') ?? undefined;
	cliToken.current = url.searchParams.get('token') ?? undefined;
};
