<script lang="ts">
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import CopyCommand from '#lib/components/blocks/CopyCommand.svelte';
	import { Check, Minus } from '@lucide/svelte';

	interface Props {
		open?: boolean;
		/** Admins make enrollment tokens. Everyone else is told to ask one. */
		canEnroll: boolean;
		onDaemon: () => void;
		onManual: () => void;
	}

	let { open = $bindable(false), canEnroll, onDaemon, onManual }: Props = $props();

	let content = $state<HTMLElement | null>(null);

	// What each way gives, and what it leaves out.
	const ways = [
		{
			id: 'daemon',
			title: 'With the daemon',
			points: [
				{ text: 'Access changes sync by themselves', has: true },
				{ text: 'Shells in the browser, session recording', has: true },
				{ text: 'Reached through the relay, no port to open', has: true }
			],
			command: 'sudo nokkud enroll'
		},
		{
			id: 'manual',
			title: 'Over plain SSH',
			points: [
				{ text: 'Nothing to install on the server', has: true },
				{ text: 'A revoke waits for the certificate to run out, an hour at most', has: false },
				{ text: 'No browser shell, no recording', has: false }
			],
			command: 'nk sync root@your-server'
		}
	];
</script>

<Dialog.Root bind:open>
	<!-- Focus starts on the dialog itself. The first control is a copy button whose tooltip would cover the list. -->
	<Dialog.Content
		bind:ref={content}
		tabindex={-1}
		onOpenAutoFocus={(e) => {
			e.preventDefault();
			content?.focus();
		}}
		class="no-scrollbar max-h-[95vh] overflow-y-auto outline-none sm:max-w-2xl"
	>
		<Dialog.Header>
			<Dialog.Title>Add a server</Dialog.Title>
			<Dialog.Description>Two ways in. A workspace can mix both.</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-3 sm:grid-cols-2">
			{#each ways as way (way.id)}
				{@const daemon = way.id === 'daemon'}
				<Card.Root class={['gap-4 py-4', daemon && 'border-primary']}>
					<Card.Header class="px-4">
						<Card.Title class="flex items-center justify-between gap-2">
							<h3>{way.title}</h3>
							{#if daemon}<Badge variant="info">Recommended</Badge>{/if}
						</Card.Title>
					</Card.Header>
					<Card.Content class="flex flex-1 flex-col gap-3 px-4">
						<ul class="flex flex-col gap-1.5 text-sm">
							{#each way.points as point (point.text)}
								<li class={['flex items-start gap-2', !point.has && 'text-muted-foreground']}>
									{#if point.has}
										<Check class="mt-0.5 size-4 shrink-0 text-success" aria-hidden="true" />
									{:else}
										<Minus class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
									{/if}
									{point.text}
								</li>
							{/each}
						</ul>
						<CopyCommand command={way.command} class="mt-auto self-start" />
					</Card.Content>
					<Card.Footer class="px-4">
						{#if daemon && !canEnroll}
							<p class="text-sm text-muted-foreground">An admin creates the enrollment token.</p>
						{:else}
							<Button
								class="w-full"
								variant={daemon ? 'default' : 'outline'}
								onclick={daemon ? onDaemon : onManual}
							>
								{daemon ? 'Create an enrollment token' : 'Add it by hand'}
							</Button>
						{/if}
					</Card.Footer>
				</Card.Root>
			{/each}
		</div>
	</Dialog.Content>
</Dialog.Root>
