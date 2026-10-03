<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import * as InputOTP from '#lib/components/ui/input-otp/index.js';
	import { auth } from '#lib/api/auth.svelte.js';
	import { BinaryIcon, ShieldCheck, Undo2Icon } from '@lucide/svelte';
	import { REGEXP_ONLY_DIGITS_AND_CHARS, type PinInputCell } from 'bits-ui';

	let email = $state('');
	let code = $state('');

	const loginWithBackupCode = auth.loginWithBackupCode();

	let isValid = $derived(email.length > 0 && code.length === 16);
	let isDisabled = $derived(loginWithBackupCode.isPending || !isValid);

	function handleSubmit(e: Event) {
		e.preventDefault();
		loginWithBackupCode.mutate({ email, code: code.toUpperCase() });
	}
</script>

{#snippet slots(cells: PinInputCell[])}
	<InputOTP.Group class="flex-1">
		{#each cells as cell, i (i)}
			<InputOTP.Slot {cell} class="h-10 flex-1 font-mono" />
		{/each}
	</InputOTP.Group>
{/snippet}

<AuthCard
	title="Sign in with a backup code"
	description="Your email and one of the codes you saved"
	icon={BinaryIcon}
>
	<form class="flex flex-col gap-6" onsubmit={handleSubmit}>
		<Field.Group class="gap-4">
			<Field.Field>
				<Field.Label for="email">Email</Field.Label>
				<Input
					id="email"
					type="email"
					autocomplete="username"
					bind:value={email}
					required
					placeholder="you@company.com"
				/>
			</Field.Field>
			<Field.Field>
				<Field.Label for="code">Backup code</Field.Label>
				<InputOTP.Root
					id="code"
					class="w-full"
					maxlength={16}
					pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
					bind:value={code}
					pasteTransformer={(text) => text.replace(/-/g, '')}
				>
					{#snippet children({ cells })}
						<div class="flex w-full flex-col gap-3">
							<div class="flex w-full items-center gap-2">
								{@render slots(cells.slice(0, 4))}
								<InputOTP.Separator />
								{@render slots(cells.slice(4, 8))}
							</div>
							<div class="flex w-full items-center gap-2">
								{@render slots(cells.slice(8, 12))}
								<InputOTP.Separator />
								{@render slots(cells.slice(12, 16))}
							</div>
						</div>
					{/snippet}
				</InputOTP.Root>
				<Field.Description>Each code works once. Dashes are optional.</Field.Description>
			</Field.Field>
		</Field.Group>

		<Button type="submit" disabled={isDisabled}>
			{#if loginWithBackupCode.isPending}<Spinner data-icon="inline-start" />{:else}<ShieldCheck
					data-icon="inline-start"
				/>{/if}
			Sign in
		</Button>
	</form>

	{#snippet footer()}
		<a
			href="/login"
			class="inline-flex items-center gap-1.5 font-medium text-primary hover:underline"
		>
			<Undo2Icon class="size-3.5" /> Back to sign in
		</a>
	{/snippet}
</AuthCard>
