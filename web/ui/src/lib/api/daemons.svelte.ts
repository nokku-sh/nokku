import { MAX_PAGE_SIZE } from '$lib/config';
import { DaemonService, DaemonStatus } from '$lib/gen/nokku/v1/daemon_pb';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '$lib/query';
import { plural, useBulkMutation } from './bulk';
import { addSession, removeSession, validateActiveSession } from './terminal.svelte';
import { activeSessionID, workspaceID } from '$lib/store.svelte';

export const daemon = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			DaemonService.method.getDaemon,
			() => ({ workspaceId: workspaceID.current, id: extract(id) }),
			() => ({ enabled: !!workspaceID.current && !!extract(id) })
		),
	list: (
		opts?: () => {
			query?: string;
			status?: DaemonStatus;
			online?: boolean;
			limit?: number;
			offset?: number;
		}
	) =>
		useQuery(
			DaemonService.method.listDaemons,
			() => ({
				workspaceId: workspaceID.current,
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ enabled: !!workspaceID.current, refetchInterval: 15000 })
		),
	listSessions: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			DaemonService.method.listSessions,
			() => ({ workspaceId: workspaceID.current, daemonId: extract(id) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(id),
				select: (res) => {
					const daemonId = extract(id);
					validateActiveSession(res.sessions);
					if (!res.sessions || !daemonId) return [];
					res.sessions.forEach((s) => {
						addSession({
							id: s.sessionId,
							daemonID: daemonId,
							daemonName: res.daemonName,
							username: s.username
						});
					});
					return res.sessions;
				},
				refetchInterval: 15000
			})
		),

	createSession: () =>
		useMutation(DaemonService.method.createSession, {
			onSuccess: (data, vars) => {
				if (!data.session || !vars.daemonId) return;
				addSession({
					id: data.session.sessionId,
					daemonID: vars.daemonId,
					daemonName: data.daemonName,
					username: data.session.username
				});
				activeSessionID.current = data.session.sessionId;
			}
		}),
	closeSession: () =>
		useMutation(DaemonService.method.closeSession, {
			onSuccess: (_, vars) => vars.sessionId && removeSession(vars.sessionId)
		}),
	update: () => useMutation(DaemonService.method.updateDaemon),
	delete: () => useMutation(DaemonService.method.deleteDaemon),
	approveMany: () =>
		useBulkMutation(DaemonService.method.updateDaemon, (n) => `${plural(n, 'daemon')} approved`),
	deleteMany: () =>
		useBulkMutation(DaemonService.method.deleteDaemon, (n) => `${plural(n, 'daemon')} deleted`)
};
