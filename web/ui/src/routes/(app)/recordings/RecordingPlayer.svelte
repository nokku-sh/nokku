<script lang="ts">
	import { untrack } from 'svelte';
	import { create as createAsciinemaPlayer, type Player } from 'asciinema-player';
	import 'asciinema-player/dist/bundle/asciinema-player.css';
	import { recordings } from '$lib/api/recordings.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { Recording } from '$lib/gen/nokku/v1/recordings_pb';
	import { AlertTriangle, RefreshCw } from '@lucide/svelte';

	interface Props {
		recording: Recording | null;
		open: boolean;
		onOpenChange: (open: boolean) => void;
	}

	let { recording, open, onOpenChange }: Props = $props();

	let playerEl = $state<HTMLDivElement | null>(null);
	// The asciinema player is a foreign embed, it mounts into a wrapper div
	// that only we touch so Svelte never sees the player's DOM.
	let playerHost: HTMLDivElement | null = null;
	let playState = $state<'loading' | 'ready' | 'error'>('loading');
	let error = $state('');
	let abortCtrl: AbortController | null = null;
	let player: Player | null = null;
	// asciinema sizes its container to the natural width at the base font
	// (15px), with 'small' the actual player is narrower and empty dialog
	// background shows on the sides. Watch the player and re-hug the host on
	// every resize so the modal is exactly the video once it settles.
	let playerObserver: ResizeObserver | null = null;
	let hugTimer: ReturnType<typeof setTimeout> | null = null;
	let observeRetry: ReturnType<typeof setTimeout> | null = null;
	let scaled = false;
	let castText = '';

	// The player container mounts in the dialog portal, the action wires it
	// and cleans up on unmount.
	function mountPlayer(el: HTMLDivElement) {
		playerEl = el;
		return {
			destroy() {
				abortCtrl?.abort();
				disposePlayer();
				playerEl = null;
			}
		};
	}

	async function play() {
		if (!recording || !playerEl) return;
		playState = 'loading';
		error = '';
		abortCtrl = new AbortController();
		disposePlayer();

		const chunks: Uint8Array[] = [];
		try {
			await recordings.stream(
				recording.id,
				() => {},
				(chunk) => chunks.push(chunk),
				abortCtrl.signal
			);
		} catch (err) {
			if (abortCtrl.signal.aborted) return;
			playState = 'error';
			error = err instanceof Error ? err.message : 'Failed to fetch recording';
			return;
		}

		try {
			await renderCast(concatBytes(chunks));
		} catch (err) {
			playState = 'error';
			error = err instanceof Error ? err.message : 'Failed to render recording';
		}
	}

	// The published Player type only declares a subset of events, "ready" and
	// "error" are dispatched at runtime and wired through a structural cast.
	type PlayerEvents = { addEventListener(name: string, handler: () => void): void };

	function wirePlayerEvents(p: Player) {
		(p as unknown as PlayerEvents).addEventListener('error', () => {
			playState = 'error';
			error = 'The recording could not be parsed.';
		});
	}

	// Tear down the resize watcher so a closed dialog never resizes a host
	// that no longer exists.
	function cleanupPlayerObserver() {
		playerObserver?.disconnect();
		playerObserver = null;
		if (hugTimer) clearTimeout(hugTimer);
		hugTimer = null;
		if (observeRetry) clearTimeout(observeRetry);
		observeRetry = null;
	}

	function scheduleHug() {
		if (hugTimer) clearTimeout(hugTimer);
		hugTimer = setTimeout(hug, 300);
	}

	function attachPlayerObserver() {
		cleanupPlayerObserver();
		if (!playerHost) return;
		const video = playerHost.querySelector<HTMLElement>('.ap-player');
		if (!video) {
			// asciinema renders the player a moment after create, retry
			// until it exists.
			observeRetry = setTimeout(attachPlayerObserver, 100);
			return;
		}
		playerObserver = new ResizeObserver(scheduleHug);
		playerObserver.observe(video);
		scheduleHug();
	}

	// Size the host to the rendered player, or to a scaled copy when the
	// terminal is too large for the viewport. Every player resize re-runs
	// this, so the dialog follows the terminal until it settles.
	function hug() {
		if (!playerHost) return;
		const video = playerHost.querySelector<HTMLElement>('.ap-player');
		if (!video) return;
		const w = video.offsetWidth;
		const h = video.offsetHeight;
		if (w <= 0 || h <= 0) return;
		const maxW = Math.round(window.innerWidth * 0.92);
		const maxH = Math.round(window.innerHeight * 0.78);
		if (!scaled && (w > maxW || h > maxH)) {
			scaled = true;
			const s = Math.min(maxW / w, maxH / h, 1);
			playerHost.style.width = `${Math.round(w * s)}px`;
			playerHost.style.height = `${Math.round(h * s)}px`;
			// Re-create with fit 'both' so the terminal fills the scaled
			// host instead of overflowing it.
			player?.dispose();
			player = createAsciinemaPlayer({ data: castText }, playerHost, {
				autoPlay: true,
				theme: 'dracula',
				idleTimeLimit: 2,
				fit: 'both',
				terminalFontSize: 'small',
				cursorMode: 'steady'
			});
			wirePlayerEvents(player);
			attachPlayerObserver();
		} else {
			playerHost.style.width = `${w}px`;
			playerHost.style.height = `${h}px`;
		}
		playState = 'ready';
	}

	async function renderCast(gzipData: Uint8Array<ArrayBuffer>) {
		if (!playerEl) return;
		// The object is one gzip stream, inflate it and hand the cast text
		// to the asciinema player, it parses the v3 header and events.
		const stream = new Blob([gzipData]).stream().pipeThrough(new DecompressionStream('gzip'));
		const text = await new Response(stream).text();
		if (!text.trim()) {
			playState = 'error';
			error = 'The recording is empty.';
			return;
		}

		castText = text;
		scaled = false;
		playerHost = document.createElement('div');
		playerEl.appendChild(playerHost);

		// fit 'none' renders the terminal at its natural size (cast dims +
		// font metrics), hug() then sizes the dialog to the player.
		player = createAsciinemaPlayer({ data: text }, playerHost, {
			autoPlay: true,
			theme: 'dracula',
			idleTimeLimit: 2,
			fit: 'none',
			terminalFontSize: 'small',
			cursorMode: 'steady'
		});
		wirePlayerEvents(player);
		attachPlayerObserver();
	}

	function disposePlayer() {
		cleanupPlayerObserver();
		player?.dispose();
		player = null;
		playerHost?.remove();
		playerHost = null;
	}

	function onDialogOpenChange(next: boolean) {
		onOpenChange(next);
		if (!next) {
			abortCtrl?.abort();
			disposePlayer();
		}
	}

	// Track only the dialog state here. play() mutates $state variables and
	// would otherwise re-trigger this effect and restart playback in a loop.
	$effect(() => {
		if (!open || !recording || !playerEl) return;
		untrack(() => void play());
	});

	function concatBytes(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
		const total = chunks.reduce((n, c) => n + c.length, 0);
		const out = new Uint8Array(total);
		let offset = 0;
		for (const c of chunks) {
			out.set(c, offset);
			offset += c.length;
		}
		return out;
	}
</script>

<Dialog.Root bind:open onOpenChange={onDialogOpenChange}>
	<!-- Borderless, shrink-wrapped: the modal is exactly the size of the
	     terminal recording. -->
	<Dialog.Content
		class="max-h-[85vh] w-fit! max-w-[calc(100vw-2rem)]! gap-0! overflow-hidden rounded-xl p-0! ring-0! sm:max-w-[calc(100vw-2rem)]!"
	>
		<div class="relative">
			{#if playState === 'loading'}
				<div class="flex h-40 w-[36rem] max-w-full items-center justify-center">
					<Spinner />
				</div>
			{:else if playState === 'error'}
				<div
					class="flex h-40 w-[36rem] max-w-full flex-col items-center justify-center gap-3 p-6 text-center"
				>
					<AlertTriangle class="text-destructive" size={24} />
					<p class="max-w-md text-sm text-destructive">{error}</p>
					<Button variant="outline" size="sm" onclick={() => void play()}>
						<RefreshCw size={14} /> Retry
					</Button>
				</div>
			{/if}
			<!-- The player stays out of flow until it is ready so the
			     modal keeps the spinner size while loading. -->
			<div class={playState === 'ready' ? '' : 'invisible absolute'} use:mountPlayer></div>
		</div>
	</Dialog.Content>
</Dialog.Root>
