import { DaemonService, DaemonStatus } from '$lib/gen/nokku/v1/daemon_pb';
import { useMutation, useQuery } from '$lib/query';
import { addSession, removeSession, validateActiveSession } from './terminal.svelte';
import { activeSessionID, pageIndex, pageSize, workspaceID } from '$lib/store.svelte';

export const daemon = {
	// Queries
	get: (id?: string) =>
		useQuery(
			DaemonService.method.getDaemon,
			{ workspaceId: workspaceID.current, id },
			{ enabled: !!workspaceID.current && !!id }
		),
	list: (
		opts?: () => {
			query?: string;
			status?: DaemonStatus;
			online?: boolean;
		}
	) =>
		useQuery(
			DaemonService.method.listDaemons,
			() => ({
				workspaceId: workspaceID.current,
				limit: pageSize.current,
				offset: pageIndex.current,
				...opts?.()
			}),
			{ enabled: !!workspaceID.current, refetchInterval: 15000 }
		),
	listSessions: (daemonId?: string) =>
		useQuery(
			DaemonService.method.listSessions,
			{ workspaceId: workspaceID.current, daemonId },
			{
				enabled: !!workspaceID.current && !!daemonId,
				select: (res) => {
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
			}
		),

	// Mutations
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
	refreshToken: () => useMutation(DaemonService.method.refreshEnrollToken),
	revokeToken: () => useMutation(DaemonService.method.revokeEnrollToken),
	update: () => useMutation(DaemonService.method.updateDaemon),
	delete: () => useMutation(DaemonService.method.deleteDaemon)
};
