<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { sso, testHref } from '#lib/api/sso.svelte.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { SSOTestOutcome, SSOTestStep, type SSOProvider } from '#lib/gen/nokku/v1/sso_pb.js';
	import type { AlertVariant } from '#lib/components/ext/alert/index.js';
	import { Code } from '@connectrpc/connect';
	import { toast } from 'svelte-sonner';
	import {
		Circle,
		CircleCheck,
		CircleX,
		FlaskConical,
		Info,
		RotateCw,
		ShieldAlert,
		TriangleAlert
	} from '@lucide/svelte';

	let { providers, mode }: { providers?: SSOProvider[]; mode?: string } = $props();

	const id = $derived(page.url.searchParams.get('test') ?? undefined);
	const result = sso.test(() => id);
	const test = $derived(result.data);

	const provider = $derived(providers?.find((p) => p.providerId === test?.providerId));
	const name = $derived(provider?.name || test?.providerId || 'Provider');

	const steps = [
		{
			step: SSOTestStep.SSO_TEST_STEP_DISCOVERY,
			label: 'Discovery document',
			hint: 'Check the issuer URL, and that this server can reach it.'
		},
		{
			step: SSOTestStep.SSO_TEST_STEP_AUTHORIZE,
			label: 'Sign-in at the provider',
			hint: 'The provider turned the sign-in down. Check that your account is assigned to the app.'
		},
		{
			step: SSOTestStep.SSO_TEST_STEP_TOKEN,
			label: 'Client ID and secret',
			hint: 'The provider did not take the client ID and secret, or the redirect URI differs from the registered one.'
		},
		{
			step: SSOTestStep.SSO_TEST_STEP_ID_TOKEN,
			label: 'ID token',
			hint: 'The ID token did not check out. The client ID may belong to another app.'
		}
	];
	const failedAt = $derived(
		test?.failedStep ? steps.findIndex((s) => s.step === test.failedStep) : -1
	);

	type Outcome = {
		tone: AlertVariant;
		icon: typeof Info;
		text: (email: string, member: string) => string;
	};
	const ok = { tone: 'success', icon: CircleCheck } as const;
	const refused = { tone: 'warning', icon: ShieldAlert } as const;
	const outcomes: Partial<Record<SSOTestOutcome, Outcome>> = {
		[SSOTestOutcome.SSO_TEST_OUTCOME_SIGNS_IN]: {
			...ok,
			text: (_, member) => `A sign-in lands on ${member}.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_CREATES]: {
			...ok,
			text: (email) =>
				`Nobody here has ${email} yet. A sign-in creates a member account${mode === 'saas' ? ', which takes a seat' : ''}.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_NO_ACCOUNT]: {
			...refused,
			text: (email) =>
				`Nobody here has ${email}, so a sign-in is refused. Invite them first, or let the provider create accounts.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_NO_SEAT]: {
			...refused,
			text: (email) => `A sign-in would create an account for ${email}, but every seat is taken.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_NO_EMAIL]: {
			...refused,
			text: () =>
				'The provider sent no email, so a sign-in is refused. Add the email scope, and check that the account has an address.'
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_EMAIL_UNVERIFIED]: {
			...refused,
			text: (email) => `The provider says ${email} is not verified, so a sign-in is refused.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_INACTIVE]: {
			...refused,
			text: (_, member) => `${member} is deactivated, so a sign-in is refused.`
		},
		[SSOTestOutcome.SSO_TEST_OUTCOME_OWNER_LINK]: {
			tone: 'info',
			icon: Info,
			text: (_, member) =>
				`${member} is the owner, who is never matched by email. Link the provider under Profile, Security to sign in with it.`
		}
	};
	const unknown: Outcome = {
		tone: 'default',
		icon: Info,
		text: () => 'The provider works, but what a sign-in does could not be checked.'
	};
	const outcome = $derived((test && outcomes[test.outcome]) || unknown);

	const put = sso.put();
	// A fresh provider is saved off. Once its test signs someone in, it can go on the sign-in page.
	const canEnable = $derived(
		!!provider && !provider.enabled && failedAt < 0 && outcome.tone === 'success'
	);

	function close(open?: { id: string; tab: string }) {
		const url = new URL(page.url.href);
		url.searchParams.delete('test');
		if (open) {
			url.searchParams.set('id', open.id);
			url.searchParams.set('tab', open.tab);
		}
		void goto(url, { replace: true, reset: false });
	}

	async function enable() {
		if (!provider) return;
		const { providerId, name, issuerUrl, clientId, scopes, jitProvisioning } = provider;
		await put.mutateAsync({
			providerId,
			name,
			issuerUrl,
			clientId,
			scopes,
			jitProvisioning,
			enabled: true
		});
		toast.success(`${provider.name} is on the sign-in page`);
		close();
	}
</script>

<Dialog.Root open={!!id} onOpenChange={(open) => !open && close()}>
	<Dialog.Content class="no-scrollbar max-h-[95vh] overflow-y-auto sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<span class="rounded-md bg-primary/10 p-1.5 text-primary">
					<FlaskConical class="size-4" />
				</span>
				{test ? `${name} test sign-in` : 'Test sign-in'}
			</Dialog.Title>
			<Dialog.Description>
				{#if test}
					{failedAt < 0
						? 'Every check passed. Nobody was signed in, linked or created.'
						: `It stopped at: ${steps[failedAt].label.toLowerCase()}.`}
				{:else}
					Runs a sign-in and stops before anyone is signed in, linked or created.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		{#if result.isLoading}
			<div class="flex flex-col gap-3">
				<Skeleton class="h-28 w-full" />
				<Skeleton class="h-16 w-full" />
			</div>
		{:else if result.isError}
			<Alert.Root variant={result.error.code === Code.NotFound ? 'default' : 'destructive'}>
				<TriangleAlert />
				{#if result.error.code === Code.NotFound}
					<Alert.Title>This result is gone</Alert.Title>
					<Alert.Description>Results are kept for 10 minutes. Run the test again.</Alert.Description
					>
				{:else}
					<Alert.Title>The result did not load</Alert.Title>
					<Alert.Description class="flex flex-col items-start gap-3">
						<p>The test itself ran.</p>
						<Button variant="outline" size="sm" onclick={() => result.refetch()}>
							<RotateCw data-icon="inline-start" />
							Try again
						</Button>
					</Alert.Description>
				{/if}
			</Alert.Root>
		{:else if test}
			<ol class="flex flex-col divide-y rounded-lg border text-sm">
				{#each steps as s, i (s.step)}
					{@const state =
						failedAt < 0 || i < failedAt ? 'passed' : i === failedAt ? 'failed' : 'skipped'}
					<li class="flex items-center gap-2.5 px-3 py-2">
						{#if state === 'passed'}
							<CircleCheck class="size-4 shrink-0 text-success" aria-hidden="true" />
						{:else if state === 'failed'}
							<CircleX class="size-4 shrink-0 text-destructive" aria-hidden="true" />
						{:else}
							<Circle class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
						{/if}
						<span class={state === 'skipped' ? 'text-muted-foreground' : undefined}>
							{s.label}<span class="sr-only">, {state === 'skipped' ? 'not reached' : state}</span>
						</span>
					</li>
				{/each}
			</ol>

			{#if failedAt >= 0}
				<Alert.Root variant="destructive">
					<CircleX />
					<Alert.Title>{steps[failedAt].hint}</Alert.Title>
					<Alert.Description>
						<p class="font-mono text-xs break-all">{test.error}</p>
					</Alert.Description>
				</Alert.Root>
			{:else}
				<Alert.Root variant={outcome.tone}>
					<outcome.icon />
					<Alert.Title>What a real sign-in does</Alert.Title>
					<Alert.Description>{outcome.text(test.email, test.memberEmail)}</Alert.Description>
				</Alert.Root>

				<dl class="flex flex-col divide-y rounded-lg border text-sm">
					<div class="flex items-center justify-between gap-4 px-3 py-2">
						<dt class="text-muted-foreground">Email</dt>
						<dd class="flex min-w-0 items-center gap-2">
							<span class="truncate">{test.email || 'None'}</span>
							{#if test.email}
								<Badge variant={test.emailVerified ? 'success' : 'warning'}>
									{test.emailVerified ? 'Verified' : 'Not verified'}
								</Badge>
							{/if}
						</dd>
					</div>
					{#if test.name}
						<div class="flex items-center justify-between gap-4 px-3 py-2">
							<dt class="text-muted-foreground">Name</dt>
							<dd class="truncate">{test.name}</dd>
						</div>
					{/if}
					<div class="flex items-center justify-between gap-4 px-3 py-2">
						<dt class="text-muted-foreground">Subject</dt>
						<dd class="truncate font-mono text-xs" title={test.subject}>{test.subject}</dd>
					</div>
					<div class="flex flex-col gap-1 px-3 py-2">
						<dt class="text-muted-foreground">Claims in the ID token</dt>
						<dd class="font-mono text-xs break-words">{test.claims.join(', ')}</dd>
					</div>
				</dl>
			{/if}
		{/if}

		<Dialog.Footer class="gap-2">
			{#if test?.providerId}
				<Button variant="outline" href={testHref(test.providerId)} data-sveltekit-reload>
					<RotateCw data-icon="inline-start" />
					Test again
				</Button>
			{/if}
			{#if test?.providerId && failedAt >= 0}
				<Button
					variant="outline"
					onclick={() => close({ id: test?.providerId ?? '', tab: 'settings' })}
				>
					Open settings
				</Button>
			{/if}
			{#if canEnable}
				<Button variant="outline" onclick={() => close()}>Not now</Button>
				<Button onclick={enable} disabled={put.isPending}>Enable {name}</Button>
			{:else}
				<Button onclick={() => close()}>Done</Button>
			{/if}
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
