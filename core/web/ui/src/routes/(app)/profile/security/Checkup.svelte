<script lang="ts">
	import { credentials } from '#lib/api/credential.svelte.js';
	import { session } from '#lib/api/session.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import { Check, CircleAlert } from '@lucide/svelte';

	const creds = credentials.all();
	const sessions = session.list();

	const passkeyCount = $derived((creds.data ?? []).filter((c) => c.type === 'passkey').length);
	const linkCount = $derived((creds.data ?? []).filter((c) => c.type === 'oidc').length);
	const strangers = $derived((sessions.data ?? []).filter((s) => !s.current).length);

	const checks = $derived([
		{
			done: passkeyCount > 0,
			label: 'Add a passkey',
			doneLabel: `${passkeyCount} ${passkeyCount === 1 ? 'passkey' : 'passkeys'}`,
			hint: 'Phishing proof, and no link to wait for.',
			href: '#sign-in'
		},
		{
			done: passkeyCount + linkCount > 1,
			label: 'Add a second way in',
			doneLabel: 'Two or more ways in',
			hint: 'Losing one device never locks you out.',
			href: '#sign-in'
		},
		{
			done: strangers === 0,
			label: 'Review signed-in devices',
			doneLabel: 'Only this device',
			hint: strangers
				? `${strangers} other ${strangers === 1 ? 'device is' : 'devices are'} signed in.`
				: 'Sign out what you do not recognize.',
			href: '#sessions'
		}
	]);

	const doneCount = $derived(checks.filter((c) => c.done).length);

	const status = $derived(
		doneCount === checks.length
			? { label: 'Strong', variant: 'success' as const }
			: doneCount === checks.length - 1
				? { label: 'Good', variant: 'info' as const }
				: { label: 'Needs attention', variant: 'warning' as const }
	);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			Security checkup
			<Badge variant={status.variant}>{status.label}</Badge>
		</Card.Title>
		<Card.Description>{doneCount} of {checks.length} done.</Card.Description>
		<Card.Action>
			<Progress value={(doneCount / checks.length) * 100} class="h-1.5 w-28" />
		</Card.Action>
	</Card.Header>
	<Card.Content class="grid gap-2 sm:grid-cols-3">
		{#each checks as c (c.label)}
			<a
				href={c.href}
				class={[
					'flex items-start gap-2.5 rounded-lg border p-3 transition-colors hover:bg-muted/40',
					!c.done && 'border-warning/40 bg-warning/5'
				]}
			>
				{#if c.done}
					<Check class="mt-0.5 size-4 shrink-0 text-success" />
				{:else}
					<CircleAlert class="mt-0.5 size-4 shrink-0 text-warning" />
				{/if}
				<span class="flex flex-col">
					<span class="text-sm font-medium">{c.done ? c.doneLabel : c.label}</span>
					<span class="text-xs text-muted-foreground">{c.hint}</span>
				</span>
			</a>
		{/each}
	</Card.Content>
</Card.Root>
