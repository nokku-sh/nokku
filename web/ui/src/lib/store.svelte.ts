import { PersistedState } from 'runed';

const NS = 'nokku';

export const pageSize = new PersistedState<number>(`${NS}:page:size`, 10);

export const activeSessionID = new PersistedState<string>(`${NS}:session:active`, ``);

// pendingDeviceCode brings a signed-out user back to /device after login.
export const pendingDeviceCode = new PersistedState<string | undefined>(
	`${NS}:device:code`,
	undefined,
	{
		storage: `session`,
		syncTabs: false
	}
);

// Where a session expired, so signing in again lands on the same page. Not
// per tab, the sign-in link from the mail opens a new one.
export const returnTo = new PersistedState<{ path: string; at: number } | undefined>(
	`${NS}:return`,
	undefined
);

// Targets this browser connected to last, so the dashboard lists them first.
export const recentTargets = new PersistedState<string[]>(`${NS}:targets:recent`, []);

// The setup card on the dashboard, once someone waved it away.
export const setupDismissed = new PersistedState<boolean>(`${NS}:setup:dismissed`, false);

// Auditors compare timestamps with other systems, so they can pin UTC.
export const auditUTC = new PersistedState<boolean>(`${NS}:audit:utc`, false);
