import { Terminal, type ITerminalOptions, type ITheme } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SvelteMap } from 'svelte/reactivity';
import { activeSessionID } from '#lib/store.svelte.js';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';

// The backend closes with this when the shell ended on its own (exit, Ctrl+D).
const SHELL_EXITED = 4000;

let sessions = new SvelteMap<string, TerminalSession>();

export function getSessions() {
	return sessions;
}
export function addSession(session: TerminalSession) {
	sessions.set(session.id, session);
	activeSessionID.current = session.id;
}
export function removeSession(id: string) {
	sessions.get(id)?.dispose();
	sessions.delete(id);
	if (activeSessionID.current === id) {
		activeSessionID.current = [...sessions.keys()].at(-1) ?? '';
	}
}

const ansiNames = [
	'black',
	'red',
	'green',
	'yellow',
	'blue',
	'magenta',
	'cyan',
	'white',
	'brightBlack',
	'brightRed',
	'brightGreen',
	'brightYellow',
	'brightBlue',
	'brightMagenta',
	'brightCyan',
	'brightWhite'
] as const;

// The palette lives in layout.css so the live terminal and recordings match.
function terminalTheme(): Pick<ITerminalOptions, 'fontFamily' | 'theme'> {
	const css = getComputedStyle(document.documentElement);
	const v = (name: string) => css.getPropertyValue(`--${name}`).trim();
	const theme: ITheme = {
		background: v('terminal'),
		foreground: v('terminal-foreground'),
		cursor: v('terminal-cursor'),
		cursorAccent: v('terminal'),
		selectionBackground: v('terminal-selection')
	};
	ansiNames.forEach((name, i) => (theme[name] = v(`ansi-${i}`)));
	return { fontFamily: v('terminal-font'), theme };
}

// TerminalSession owns the socket and the terminal, so a shell survives
// navigation. The shell on the server lives exactly as long as the socket.
export class TerminalSession {
	state = $state<ConnectionState>('connecting');

	readonly #ws: WebSocket;
	readonly #term = new Terminal({ cursorBlink: true, fontSize: 14, ...terminalTheme() });
	readonly #fit = new FitAddon();
	// xterm opens into its own node, which each view mount adopts.
	readonly #el = document.createElement('div');

	constructor(
		readonly id: string,
		readonly daemonID: string,
		readonly daemonName: string,
		readonly username: string
	) {
		this.#el.className = 'h-full w-full';
		this.#term.loadAddon(this.#fit);

		const ws = new WebSocket(`/terminal/ws?session_id=${id}`);
		ws.binaryType = 'arraybuffer';
		this.#ws = ws;

		const sendSize = () => {
			if (ws.readyState !== WebSocket.OPEN) return;
			ws.send(JSON.stringify({ type: 'resize', cols: this.#term.cols, rows: this.#term.rows }));
		};
		ws.onopen = () => {
			this.state = 'connected';
			sendSize();
		};
		ws.onmessage = (e) => this.#term.write(new Uint8Array(e.data));
		ws.onclose = (e) => {
			if (e.code === SHELL_EXITED) {
				removeSession(id);
				return;
			}
			this.state = e.code === 1000 ? 'disconnected' : 'error';
			this.#term.write(`\r\n\x1b[2m${e.reason || 'connection lost'}\x1b[0m\r\n`);
		};

		const encoder = new TextEncoder();
		this.#term.onData((data) => {
			if (ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(data));
		});
		this.#term.onResize(sendSize);
	}

	attach(container: HTMLElement) {
		container.appendChild(this.#el);
		if (!this.#term.element) this.#term.open(this.#el);
		this.#fit.fit();
	}

	fit() {
		this.#fit.fit();
	}

	focus() {
		this.#term.focus();
	}

	dispose() {
		this.#ws.onclose = null;
		this.#ws.close();
		this.#term.dispose();
	}
}
