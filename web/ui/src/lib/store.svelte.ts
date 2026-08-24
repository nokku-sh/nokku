import { PersistedState } from 'runed';

export const NS = 'nokku';

// State
export const workspaceID = new PersistedState<string>(`${NS}:workspace:id`, '');

// Tables
export const pageIndex = new PersistedState<number>(`${NS}:page:index`, 0);
export const pageSize = new PersistedState<number>(`${NS}:page:size`, 10);

// Terminal
export const activeSessionID = new PersistedState<string>(`${NS}:session:active`, ``);

// Tokens
export const inviteToken = new PersistedState<string | undefined>(`${NS}:token:invite`, undefined, {
	storage: `session`,
	syncTabs: true
});

// A device-flow user code awaiting authorization. Set when a signed-out user
// tries to authorize a CLI device; consumed by the app layout after login so
// they land back on /device with the code intact.
export const pendingDeviceCode = new PersistedState<string | undefined>(
	`${NS}:device:code`,
	undefined,
	{
		storage: `session`,
		syncTabs: false
	}
);

// Tabs
export const activeDashboardTab = new PersistedState<string>(`${NS}:tab:dashboard`, `admin`);

export const activeSSOTab = new PersistedState<string>(`${NS}:tab:sso`, `oidc`);
