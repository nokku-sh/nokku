import { Terminal, type ITerminalOptions, type ITheme } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SvelteMap } from 'svelte/reactivity';
import { activeSessionID } from '$lib/store.svelte';
import type { DaemonSession } from '$lib/gen/nokku/v1/daemon_pb';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';

export type TerminalHandle = {
	dispose: () => void;
	terminal: Terminal;
	fitAddon: FitAddon;
};

export type TerminalSession = {
	id: string;
	daemonID: string;
	daemonName: string;
	username: string;
	state?: ConnectionState;
};

let sessions = new SvelteMap<string, TerminalSession>();

export function getSessions() {
	return sessions;
}
export function addSession(session: TerminalSession) {
	sessions.set(session.id, session);
	if (activeSessionID.current === '') {
		activeSessionID.current = session.id;
	}
}
export function removeSession(id: string) {
	if (activeSessionID.current === id) {
		activeSessionID.current = '';
	}
	sessions.delete(id);
}
export function validateActiveSession(sessions: DaemonSession[]) {
	if (!activeSessionID.current) return;

	const isValid = sessions.some((s) => s.sessionId === activeSessionID.current);
	if (!isValid) activeSessionID.current = '';
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

export function openTerminal(
	daemonID: string,
	sessionID: string,
	containerEl: HTMLElement
): TerminalHandle {
	const ws = new WebSocket(`/terminal/ws?daemon_id=${daemonID}&session_id=${sessionID}`);
	ws.binaryType = 'arraybuffer';

	const term = new Terminal({ cursorBlink: true, fontSize: 14, ...terminalTheme() });
	const fitAddon = new FitAddon();
	term.loadAddon(fitAddon);
	term.open(containerEl);
	fitAddon.fit();

	const resizeObserver = new ResizeObserver(() => fitAddon.fit());
	resizeObserver.observe(containerEl);

	const handle: TerminalHandle = {
		dispose: () => {},
		terminal: term,
		fitAddon
	};

	const setState = (s: ConnectionState) => {
		let session = sessions.get(sessionID);
		if (!session) return;
		session.state = s;
	};

	setState('connecting');

	ws.onopen = () => {
		setState('connected');
		const { cols, rows } = term;
		ws.send(JSON.stringify({ type: 'resize', cols, rows }));
	};

	ws.onmessage = (e) => term.write(new Uint8Array(e.data));

	ws.onerror = () => setState('error');

	ws.onclose = () => setState('disconnected');

	const encoder = new TextEncoder();
	term.onData((data) => {
		if (ws.readyState === WebSocket.OPEN) {
			ws.send(encoder.encode(data));
		}
	});

	term.onResize(({ cols, rows }) => {
		if (ws.readyState === WebSocket.OPEN) {
			ws.send(JSON.stringify({ type: 'resize', cols, rows }));
		}
	});

	handle.dispose = () => {
		if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
			ws.close();
		}
		term.dispose();
	};

	return handle;
}
