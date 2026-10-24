import { goto } from '$app/navigation';
import { page } from '$app/state';
import { AuditOutcome, type EventLog } from '#lib/gen/nokku/v1/util_pb.js';
import { PAGE_PARAM } from '#lib/hooks/index.js';
import {
	Bot,
	CircleCheck,
	CircleUser,
	CircleX,
	KeyRound,
	LogIn,
	RefreshCw,
	Server,
	Settings,
	Shield,
	ShieldCheck,
	ShieldX,
	SquareTerminal,
	Terminal,
	Users,
	type LucideIcon
} from '@lucide/svelte';

export type Area = {
	value: string;
	label: string;
	icon: LucideIcon;
	/** Exact action names, matched on the server. */
	actions: string[];
};

export const areas: Area[] = [
	{
		value: 'access',
		label: 'Access',
		icon: ShieldCheck,
		actions: [
			'AddSubjects',
			'RemoveSubjects',
			'RevokeAllAccess',
			'AddTargetAccount',
			'RemoveTargetAccount',
			'GrantExpired',
			'CreateAccessRequest',
			'ApproveAccessRequest',
			'DenyAccessRequest',
			'CancelAccessRequest',
			'AccessRequestExpired',
			'SetRequestableTags',
			'ExportAccessReport'
		]
	},
	{
		value: 'people',
		label: 'People & roles',
		icon: Users,
		actions: [
			'UpdateUserRole',
			'SetUserActive',
			'DeleteUser',
			'TransferOwnership',
			'AcceptInvitation',
			'CreateTeam',
			'UpdateTeam',
			'DeleteTeam',
			'AddTeamMember',
			'RemoveTeamMember',
			'CreateServiceAccount',
			'UpdateServiceAccount',
			'DeleteServiceAccount',
			'CreateServiceAccountToken',
			'RevokeServiceAccountToken',
			'CreateJoinToken',
			'DeleteJoinToken',
			'UserCreated',
			'UserDeleted',
			'UserActivated',
			'UserDeactivated'
		]
	},
	{
		value: 'infrastructure',
		label: 'Infrastructure',
		icon: Server,
		actions: [
			'CreateTarget',
			'UpdateTarget',
			'DeleteTarget',
			'SyncTargetUsers',
			'EnrollDaemon',
			'UpdateDaemon',
			'DeleteDaemon'
		]
	},
	{
		value: 'certificates',
		label: 'Certificates',
		icon: Shield,
		actions: [
			'CreateCertificateAuthority',
			'UpdateCertificateAuthority',
			'DeleteCertificateAuthority',
			'RolloverCertificateAuthority',
			'SignSSHCertificate'
		]
	},
	{
		value: 'sessions',
		label: 'Sessions',
		icon: SquareTerminal,
		actions: ['CreateSession', 'CloseSession', 'RelayOpen', 'RelayClose', 'GetRecording']
	},
	{
		value: 'signins',
		label: 'Sign-ins',
		icon: LogIn,
		actions: [
			'Login',
			'LoginDenied',
			'SessionIssued',
			'SessionRevoked',
			'CredentialAdded',
			'EmailChanged'
		]
	},
	{
		value: 'workspace',
		label: 'Workspace & SSO',
		icon: Settings,
		actions: [
			'CreateWorkspace',
			'UpdateWorkspace',
			'DeleteWorkspace',
			'PutSSOProvider',
			'DeleteSSOProvider',
			'CreateSCIMToken',
			'DeleteSCIMToken',
			'CreateLegalHold',
			'DeleteLegalHold',
			'CreateAuditStream',
			'UpdateAuditStream',
			'DeleteAuditStream',
			'TestAuditStream'
		]
	}
];

const areaByAction = new Map(areas.flatMap((a) => a.actions.map((action) => [action, a])));
export const areaOf = (action: string) => areaByAction.get(action);

export const outcomes = [
	{ value: 'failed', label: 'Failed', icon: CircleX, enum: AuditOutcome.FAILED },
	{ value: 'denied', label: 'Denied only', icon: ShieldX, enum: AuditOutcome.DENIED },
	{ value: 'succeeded', label: 'Succeeded', icon: CircleCheck, enum: AuditOutcome.SUCCEEDED }
];

/** `label` names the group in filters, `one` names a single actor in a row. */
export const actorKinds: { value: string; label: string; one: string; icon: LucideIcon }[] = [
	{ value: 'user', label: 'People', one: 'Person', icon: CircleUser },
	{ value: 'cli', label: 'CLI', one: 'CLI', icon: Terminal },
	{ value: 'service_account', label: 'Service accounts', one: 'Service account', icon: Bot },
	{ value: 'daemon', label: 'Daemons', one: 'Daemon', icon: Server },
	{ value: 'scim', label: 'SCIM', one: 'SCIM', icon: RefreshCw }
];
export const kindOf = (kind: string) => actorKinds.find((k) => k.value === kind);

/** Params owned by the quick views, clicking one replaces all of them. */
const filterParams = ['q', 'area', 'outcome', 'kind', 'actor', 'target'];

export const quickViews: { label: string; params: Record<string, string> }[] = [
	{ label: 'Everything', params: {} },
	{ label: 'Access changes', params: { area: 'access' } },
	{ label: 'Failed & denied', params: { outcome: 'failed' } },
	{ label: 'People & roles', params: { area: 'people' } },
	{ label: 'Certificates', params: { area: 'certificates' } },
	{ label: 'Sign-ins', params: { area: 'signins' } }
];

// Auth and relay events aren't RPC names, so they read better spelled out.
const labels: Record<string, string> = {
	Login: 'Signed in',
	LoginDenied: 'Sign-in denied',
	SessionIssued: 'Session started',
	SessionRevoked: 'Session revoked',
	CredentialAdded: 'Credential added',
	EmailChanged: 'Email changed',
	UserCreated: 'Account created',
	UserDeleted: 'Account deleted',
	UserActivated: 'Account activated',
	UserDeactivated: 'Account deactivated',
	RelayOpen: 'Relay opened',
	RelayClose: 'Relay closed',
	GetRecording: 'Played a recording',
	AddSubjects: 'Granted access',
	RemoveSubjects: 'Revoked access',
	RevokeAllAccess: 'Revoked all access',
	AddTargetAccount: 'Added login account',
	RemoveTargetAccount: 'Removed login account',
	GrantExpired: 'Access expired',
	CreateAccessRequest: 'Asked for access',
	ApproveAccessRequest: 'Approved a request',
	DenyAccessRequest: 'Denied a request',
	CancelAccessRequest: 'Cancelled a request',
	AccessRequestExpired: 'Request expired',
	SetRequestableTags: 'Changed requestable servers',
	ExportAccessReport: 'Exported the access report',
	CreateLegalHold: 'Placed a legal hold',
	DeleteLegalHold: 'Released a legal hold'
};

/** "DeleteTarget" reads as "Delete target". */
export function eventLabel(action: string) {
	if (labels[action]) return labels[action];
	const words = action.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(' ');
	return words.map((w, i) => (i === 0 || /^[A-Z0-9]{2,}$/.test(w) ? w : w.toLowerCase())).join(' ');
}

export type Outcome = 'succeeded' | 'failed' | 'denied';

export function outcomeOf(log: EventLog): Outcome {
	if (log.ok) return 'succeeded';
	const code = log.details?.['code'];
	if (log.action === 'LoginDenied' || code === 'permission_denied' || code === 'unauthenticated') {
		return 'denied';
	}
	return 'failed';
}

export const csv = (param: string) =>
	page.url.searchParams.get(param)?.split(',').filter(Boolean) ?? [];

// setParams changes filters and goes back to page 1, since the result set moved.
export function setParams(params: Record<string, string | undefined>, replaceFilters = false) {
	const url = new URL(page.url.href);
	if (replaceFilters) filterParams.forEach((p) => url.searchParams.delete(p));
	for (const [key, value] of Object.entries(params)) {
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
	}
	url.searchParams.delete(PAGE_PARAM);
	void goto(url, { replace: true, reset: false });
}

export const kindIcon = (kind: string): LucideIcon => kindOf(kind)?.icon ?? KeyRound;

/** Failures and denials read as destructive, successes stay quiet. */
export const outcomeLabel: Record<Outcome, string> = {
	succeeded: 'Succeeded',
	failed: 'Failed',
	denied: 'Denied'
};
