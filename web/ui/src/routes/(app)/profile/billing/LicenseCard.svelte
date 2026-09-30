<script lang="ts">
	import { license } from '$lib/api/license.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { LicensePurchaseURL } from '$lib/config';
	import { formatTs } from '$lib/utils';
	import { Check, ExternalLink } from '@lucide/svelte';

	const data = license.get();

	const benefits = [
		'Unlimited members and infrastructure',
		'SAML, enforced SSO and audit export',
		'365-day audit retention',
		'Offline, air-gapped activation'
	];
</script>

{#if data.isLoading}
	<Skeleton class="h-56 w-full rounded-xl" />
{:else}
	<Card.Root>
		<Card.Header>
			<span class="spec-label">Self-hosted license</span>
			<Card.Title class="text-3xl font-semibold tracking-tight">
				{data.data?.active ? 'Enterprise' : 'Community'}
			</Card.Title>
			<Card.Description>
				{data.data?.active
					? 'This instance is licensed for every Enterprise feature.'
					: 'Everything you need to start. Enterprise unlocks the rest.'}
			</Card.Description>
			<Card.Action>
				<Badge variant={data.data?.active ? 'success' : 'muted'}>
					{data.data?.active ? 'Active' : 'Free'}
				</Badge>
			</Card.Action>
		</Card.Header>
		<Card.Content>
			{#if data.data?.active}
				{#if data.data.expiresAt}
					<div class="flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3">
						<span class="spec-label">Valid until</span>
						<span class="font-mono text-sm tabular-nums">{formatTs(data.data.expiresAt)}</span>
					</div>
				{/if}
			{:else}
				<ul class="flex flex-col gap-2.5">
					{#each benefits as b (b)}
						<li class="flex items-start gap-2.5 text-sm text-muted-foreground">
							<Check class="mt-0.5 size-4 shrink-0 text-primary" />
							{b}
						</li>
					{/each}
				</ul>
			{/if}
		</Card.Content>
		{#if !data.data?.active}
			<Card.Footer class="flex flex-col items-stretch gap-3 border-t">
				<Button href={LicensePurchaseURL} target="_blank" rel="noopener">
					Buy an Enterprise license
					<ExternalLink data-icon="inline-end" />
				</Button>
				<p class="text-center text-xs text-muted-foreground">
					Set <code class="font-mono text-foreground">NOKKU_LICENSE_KEY</code> on your server and restart
					to activate.
				</p>
			</Card.Footer>
		{/if}
	</Card.Root>
{/if}
