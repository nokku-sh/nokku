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
export const cliToken = new PersistedState<string | undefined>(`${NS}:token:cli`, undefined, {
	storage: `session`,
	syncTabs: false
});
export const inviteToken = new PersistedState<string | undefined>(`${NS}:token:invite`, undefined, {
	storage: `session`,
	syncTabs: true
});

// Tabs
export const activeDashboardTab = new PersistedState<string>(`${NS}:tab:dashboard`, `admin`);

export const activeSSOTab = new PersistedState<string>(`${NS}:tab:sso`, `oidc`);
