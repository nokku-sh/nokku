import type { DaemonConfig } from '#lib/gen/nokku/v1/daemon_pb.js';

export type DaemonRule = keyof Pick<
	DaemonConfig,
	'recordSessions' | 'allowForwarding' | 'allowAgentForwarding' | 'gatewayPorts'
>;

/** The SSH rules a daemon follows, named the same on the daemon and in the defaults new ones start with. */
export const daemonRules: { key: DaemonRule; title: string; description: string }[] = [
	{
		key: 'recordSessions',
		title: 'Record sessions',
		description:
			'Keep an encrypted recording of every SSH session for playback. People who log in are told.'
	},
	{
		key: 'allowForwarding',
		title: 'Port forwarding',
		description: 'Allow -L, -D and -R port forwards.'
	},
	{
		key: 'allowAgentForwarding',
		title: 'Agent forwarding',
		description: "Let sessions use the client's ssh-agent."
	},
	{
		key: 'gatewayPorts',
		title: 'Public remote forwards',
		description:
			'Let -R forwards listen on addresses other than localhost, what sshd calls GatewayPorts.'
	}
];
