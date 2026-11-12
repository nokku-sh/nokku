type Entry = {
	title: string;
	text: string;
	/** A command that shows the word at work. */
	example?: string;
};

export type TermName = 'login account' | 'ephemeral';

/** The words of Nokku a newcomer trips over, each in a sentence. Term shows one on hover. */
export const glossary: Record<TermName, Entry> = {
	'login account': {
		title: 'Login account',
		text: 'The Linux user someone becomes on the server, like deploy or ubuntu. It has to exist on the server, Nokku does not create it.',
		example: 'ssh deploy@web-prod-1'
	},
	ephemeral: {
		title: 'Ephemeral server',
		text: 'A server that is meant to go away, like a container or a devbox. It leaves the workspace when it stops or stays offline, so the list does not fill up with dead ones.'
	}
};
