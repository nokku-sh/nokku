<script lang="ts">
	import SecretReveal from '$lib/components/blocks/SecretReveal.svelte';
	import { UseClipboard } from '$lib/hooks/use-clipboard.svelte';
	import { Check } from '@lucide/svelte';
	import { backupCode, password } from '$lib/api/credential.svelte';
	import { user } from '$lib/api/user.svelte';
	import Section from '$lib/components/sheets/Section.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Spinner } from '$lib/components/ui/spinner';
	import { Switch } from '$lib/components/ui/switch';
	import { Binary, Copy, Download, Mail } from '@lucide/svelte';
	import { confirm } from '$lib/hooks';

	const me = user.self();

	const codes = backupCode.list();

	const createCodes = backupCode.create();

	const deleteCodes = backupCode.delete();

	const setEmailRecovery = user.setEmailRecovery();

	const codeCount = $derived(codes.data?.length ?? 0);

	const emailRecovery = $derived(!me.data?.disablePasswordReset);

	const clipboard = new UseClipboard();

	function download(list: string[]) {
		const content = `Nokku backup codes\nCreated ${new Date().toLocaleString()}\n\nEach code works once.\n\n${list.join('\n')}\n`;
		const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = `nokku-backup-codes-${new Date().toISOString().slice(0, 10)}.txt`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<Card.Root id="recovery">
	<Card.Header>
		<Card.Title>Recovery</Card.Title>
		<Card.Description>Your way back in when every device is gone.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col divide-y">
		<Section title="Backup codes" icon={Binary}>
			{#snippet action()}
				<Button
					size="sm"
					variant="ghost"
					disabled={createCodes.isPending}
					onclick={() =>
						codeCount
							? confirm({
									title: 'Create new backup codes?',
									description: 'Your current codes stop working right away.',
									confirmText: 'Create new codes',
									destructive: false,
									onConfirm: () => createCodes.mutateAsync()
								})
							: createCodes.mutate()}
				>
					{#if createCodes.isPending}<Spinner data-icon="inline-start" />{/if}
					{codeCount ? 'Regenerate' : 'Create codes'}
				</Button>
			{/snippet}
			{#if createCodes.isSuccess}
				<SecretReveal note="Each code works once. Keep them in your password manager.">
					<div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
						{#each createCodes.data.codes as code (code)}
							<code
								class="rounded-md border bg-muted/40 px-2 py-2 text-center font-mono text-sm tracking-widest select-all"
							>
								{code}
							</code>
						{/each}
					</div>
					<div class="flex flex-wrap gap-2">
						<Button
							size="sm"
							variant="outline"
							onclick={() => clipboard.copy(createCodes.data.codes.join('\n'))}
						>
							{#if clipboard.copied}<Check data-icon="inline-start" />{:else}<Copy
									data-icon="inline-start"
								/>{/if}
							Copy
						</Button>
						<Button size="sm" variant="outline" onclick={() => download(createCodes.data.codes)}>
							<Download data-icon="inline-start" /> Download
						</Button>
						<Button size="sm" variant="ghost" onclick={() => createCodes.reset()}
							>I saved them</Button
						>
					</div>
				</SecretReveal>
			{:else}
				<div class="flex items-center justify-between gap-3">
					<p class="text-sm text-muted-foreground">
						{codeCount
							? `${codeCount} codes left. Regenerate if you lost them.`
							: 'No backup codes yet.'}
					</p>
					{#if codeCount}
						<Button
							size="sm"
							variant="ghost"
							onclick={() =>
								confirm({
									title: 'Delete backup codes?',
									description: 'They stop working and can no longer recover your account.',
									onConfirm: () => deleteCodes.mutateAsync({})
								})}
						>
							Delete
						</Button>
					{/if}
				</div>
			{/if}
		</Section>

		<Section title="Email recovery" icon={Mail}>
			<Field.Field orientation="horizontal">
				<Field.Content>
					<Field.Label for="email-recovery">Allow password resets by email</Field.Label>
					<Field.Description>
						Turn it off for stricter security. Then only your passkeys, password, backup codes and
						connected accounts get you in, and losing all of them locks you out for good.
					</Field.Description>
				</Field.Content>
				<Switch
					id="email-recovery"
					checked={emailRecovery}
					disabled={setEmailRecovery.isPending}
					onCheckedChange={(on) =>
						on
							? setEmailRecovery.mutate({ enable: true })
							: confirm({
									title: 'Turn off email recovery?',
									description:
										'Nobody, including support, can reset your password by email anymore. Make sure you have backup codes.',
									confirmText: 'Turn off',
									onConfirm: () => setEmailRecovery.mutateAsync({ enable: false })
								})}
				/>
			</Field.Field>
		</Section>
	</Card.Content>
</Card.Root>
