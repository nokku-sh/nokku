import type { DaemonConfig } from '#lib/gen/nokku/v1/daemon_pb.js';

export type DaemonRule = keyof Pick<
	DaemonConfig,
	'recordSessions' | 'allowForwarding' | 'allowAgentForwarding' | 'gatewayPorts'
>;

export type RuleValues = Partial<Record<DaemonRule, boolean>>;

/**
 * The SSH rules a daemon follows, named the same on the daemon and in the defaults new ones start with. A fresh rule
 * takes a recent sign-in to change on a daemon. The directive is what sshd_config calls the same thing.
 */
export const daemonRules: {
	key: DaemonRule;
	title: string;
	description: string;
	directive?: string;
	fresh?: boolean;
}[] = [
	{
		key: 'recordSessions',
		title: 'Record sessions',
		description:
			'Keep an encrypted recording of every SSH session for playback. People who log in are told.',
		fresh: true
	},
	{
		key: 'allowForwarding',
		title: 'Port forwarding',
		description: 'People can tunnel with -L, -D and -R.',
		directive: 'AllowTcpForwarding'
	},
	{
		key: 'allowAgentForwarding',
		title: 'Agent forwarding',
		description: "A session can use the keys in the person's own ssh-agent.",
		directive: 'AllowAgentForwarding'
	},
	{
		key: 'gatewayPorts',
		title: 'Public remote forwards',
		description: 'A -R forward may listen on every address, not only on localhost.',
		directive: 'GatewayPorts'
	}
];

/** One rule as a patch, typed so it fits a DaemonConfig. */
export const ruleValue = (key: DaemonRule, value: boolean): RuleValues => ({ [key]: value });

/** How many rules of a daemon are set another way than the defaults. */
export function differing(config: RuleValues | undefined, defaults: RuleValues | undefined) {
	return daemonRules.filter((r) => (config?.[r.key] ?? false) !== (defaults?.[r.key] ?? false))
		.length;
}
