import { PersistedState } from 'runed';

const NS = 'nokku';

export const workspaceID = new PersistedState<string>(`${NS}:workspace:id`, '');

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

// Targets this browser connected to last, so the dashboard lists them first.
export const recentTargets = new PersistedState<string[]>(`${NS}:targets:recent`, []);

export const activeSSOTab = new PersistedState<string>(`${NS}:tab:sso`, `oidc`);

// Auditors compare timestamps with other systems, so they can pin UTC.
export const auditUTC = new PersistedState<boolean>(`${NS}:audit:utc`, false);
