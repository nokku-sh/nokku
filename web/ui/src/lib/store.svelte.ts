import { PersistedState } from 'runed';

export const NS = 'nokku';

export const workspaceID = new PersistedState<string>(`${NS}:workspace:id`, '');

export const pageIndex = new PersistedState<number>(`${NS}:page:index`, 0);
export const pageSize = new PersistedState<number>(`${NS}:page:size`, 10);

export const activeSessionID = new PersistedState<string>(`${NS}:session:active`, ``);

export const inviteToken = new PersistedState<string | undefined>(`${NS}:token:invite`, undefined, {
	storage: `session`,
	syncTabs: true
});

// pendingDeviceCode brings a signed-out user back to /device after login.
export const pendingDeviceCode = new PersistedState<string | undefined>(
	`${NS}:device:code`,
	undefined,
	{
		storage: `session`,
		syncTabs: false
	}
);

export const activeDashboardTab = new PersistedState<string>(`${NS}:tab:dashboard`, `admin`);

export const activeSSOTab = new PersistedState<string>(`${NS}:tab:sso`, `oidc`);
