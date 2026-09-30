<script lang="ts">
	import { backupCode, passkey, password } from '$lib/api/credential.svelte';
	import { user } from '$lib/api/user.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import { Progress } from '$lib/components/ui/progress';
	import { Check, CircleAlert } from '@lucide/svelte';

	const me = user.self();

	const passkeys = passkey.list();

	const codes = backupCode.list();

	const passkeyCount = $derived(passkeys.data?.length ?? 0);

	const codeCount = $derived(codes.data?.length ?? 0);

	const checks = $derived([
		{
			done: passkeyCount > 0,
			label: 'Add a passkey',
			doneLabel: `${passkeyCount} ${passkeyCount === 1 ? 'passkey' : 'passkeys'}`,
			hint: 'Phishing proof, and faster than a password.',
			href: '#sign-in'
		},
		{
			done: codeCount > 0,
			label: 'Create backup codes',
			doneLabel: `${codeCount} backup codes left`,
			hint: 'Your way back in if you lose every device.',
			href: '#recovery'
		},
		{
			done: !!me.data?.emailVerified,
			label: 'Verify your email',
			doneLabel: 'Email verified',
			hint: 'Needed for password resets and important notices.',
			href: '/profile'
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
