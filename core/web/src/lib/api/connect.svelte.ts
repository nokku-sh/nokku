import { goto } from '$app/navigation';
import { page } from '$app/state';
import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
import { recentTargets } from '#lib/store.svelte.js';
import { nkLoginCommand } from '#lib/utils.js';
import { toast } from 'svelte-sonner';
import { daemon } from './daemons.svelte';
import { target } from './targets.svelte';
import { user } from './user.svelte';
import { util } from './workspaces.svelte';

function remember(id: string) {
	recentTargets.current = [id, ...recentTargets.current.filter((r) => r !== id)].slice(0, 6);
}

// useConnect is the one way into a server from the UI: a web shell, or the ssh command for the user's own terminal.
export function useConnect() {
	const createSession = daemon.createSession();
	const info = util.instanceInfo();

	return {
		get pending() {
			return createSession.isPending;
		},
		async shell(t: Pick<Target, 'id' | 'daemonId'>, username: string) {
			remember(t.id);
			try {
				await createSession.mutateAsync({ daemonId: t.daemonId, username });
			} catch {
				// The global mutation handler already toasted it.
				return;
			}
			if (page.url.pathname !== '/sessions') await goto('/sessions');
		},
		async copy(t: Pick<Target, 'id' | 'name'>, username: string) {
			remember(t.id);
			await navigator.clipboard.writeText(`ssh ${username}@${t.name}`);
			toast.success('SSH command copied', {
				description: 'On a new machine, sign in once with nk login first.',
				action: {
					label: 'Copy nk login',
					onClick: () => navigator.clipboard.writeText(nkLoginCommand(info.data?.caPin))
				}
			});
		}
	};
}

// useServers lists in the same order everywhere: recently used first, then reachable, then by name.
export function useServers(when: () => boolean = () => true) {
	const me = user.self();
	const access = target.access(() => (when() ? me.data?.id : undefined));

	const online = $derived(
		new Set((access.data?.daemons ?? []).filter((d) => d.online).map((d) => d.id))
	);
	const canShell = (t: Pick<Target, 'daemonId'>) => !!t.daemonId && online.has(t.daemonId);

	const list = $derived.by(() => {
		const recent = recentTargets.current;
		const rank = (t: Target) => {
			const i = recent.indexOf(t.id);
			return i < 0 ? recent.length : i;
		};
		return (access.data?.targets ?? []).toSorted(
			(a, b) =>
				rank(a) - rank(b) ||
				Number(canShell(b)) - Number(canShell(a)) ||
				a.name.localeCompare(b.name)
		);
	});

	return {
		get loading() {
			return access.isLoading || me.isLoading;
		},
		get list() {
			return list;
		},
		canShell
	};
}

/** Whether a server matches a typed filter, by name, host or login account. */
export function serverMatches(t: Target, query: string): boolean {
	const q = query.trim().toLowerCase();
	return (
		!q ||
		t.name.toLowerCase().includes(q) ||
		!!t.metadata?.hostname?.toLowerCase().includes(q) ||
		t.endpoints.some((e) => e.toLowerCase().includes(q)) ||
		t.usernames.some((a) => a.toLowerCase().includes(q))
	);
}
