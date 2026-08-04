<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import * as InputOTP from '$lib/components/ui/input-otp/index.js';
	import { auth } from '$lib/api/auth.svelte';
	import { BinaryIcon, ShieldCheck, Undo2Icon } from '@lucide/svelte';
	import { REGEXP_ONLY_DIGITS_AND_CHARS } from 'bits-ui';

	let email = $state('');
	let code = $state('');

	const loginWithBackupCode = auth.loginWithBackupCode();

	// Format code as XXXX-XXXX-XXXX-XXXX before sending
	function formatBackupCode(rawCode: string): string {
		const clean = rawCode.replace(/[^A-Z0-9]/gi, '').toUpperCase();
		return clean.match(/.{1,4}/g)?.join('-') || clean;
	}

	let isValid = $derived(email.length > 0 && code.length === 16);
	let isDisabled = $derived(loginWithBackupCode.isPending || !isValid);

	function handleSubmit(e: Event) {
		e.preventDefault();
		loginWithBackupCode.mutate({ email, code: formatBackupCode(code) });
	}
</script>

<div
	class="m-auto h-fit max-w-98 overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
>
	<div class="-m-px rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 pb-6">
		<div class="text-center">
			<div class="mx-auto mb-3 flex size-12 items-center justify-center rounded-full bg-primary/10">
				<BinaryIcon class="size-6 text-primary" />
			</div>
			<h1 class="mt-4 mb-1 text-xl font-semibold">Use Backup Code</h1>
			<p class="text-sm text-muted-foreground">
				Enter your email and one of your backup codes to sign in
			</p>
		</div>

		<form class="mt-4 space-y-6" onsubmit={handleSubmit}>
			<!-- Email Field -->
			<div class="space-y-2">
				<Label for="email">Email</Label>
				<Input
					id="email"
					type="email"
					bind:value={email}
					required
					placeholder="name@example.com"
					autofocus
				/>
			</div>

			<!-- Backup Code Field -->
			<div class="space-y-3">
				<Label for="code">Backup Code</Label>

				<!-- Centered OTP Wrapper -->
				<div class="flex w-full justify-center py-2">
					<InputOTP.Root
						maxlength={16}
						pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
						bind:value={code}
						pasteTransformer={(text) => text.replace(/-/g, '')}
					>
						{#snippet children({ cells })}
							<div class="flex flex-col items-center gap-3">
								<!-- Row 1 -->
								<div class="flex items-center gap-2 sm:gap-3">
									<InputOTP.Group>
										{#each cells.slice(0, 4) as cell}
											<InputOTP.Slot {cell} />
										{/each}
									</InputOTP.Group>
									<InputOTP.Separator />
									<InputOTP.Group>
										{#each cells.slice(4, 8) as cell}
											<InputOTP.Slot {cell} />
										{/each}
									</InputOTP.Group>
								</div>
								<!-- Row 2 -->
								<div class="flex items-center gap-2 sm:gap-3">
									<InputOTP.Group>
										{#each cells.slice(8, 12) as cell}
											<InputOTP.Slot {cell} />
										{/each}
									</InputOTP.Group>
									<InputOTP.Separator />
									<InputOTP.Group>
										{#each cells.slice(12, 16) as cell}
											<InputOTP.Slot {cell} />
										{/each}
									</InputOTP.Group>
								</div>
							</div>
						{/snippet}
					</InputOTP.Root>
				</div>
				<p class="text-xs text-muted-foreground">
					Enter the 16-character backup code from your saved list.
				</p>
			</div>

			<Button type="submit" class="w-full" disabled={isDisabled}>
				<ShieldCheck class="mr-2 size-4" />
				Sign In with Backup Code
			</Button>
		</form>
	</div>

	<div class="bg-muted/50 p-3">
		<div class="rounded-md border border-amber-500/20 bg-amber-500/10 p-3">
			<p class="text-center text-xs text-amber-700 dark:text-amber-400">
				<strong>Warning:</strong> Each backup code can only be used once. Make sure to generate new codes
				after using your last one.
			</p>
		</div>

		<Button
			variant="link"
			class="mt-3 w-full"
			href="/login"
			disabled={loginWithBackupCode.isPending}
		>
			Go back to login
			<Undo2Icon size={16} />
		</Button>
	</div>
</div>
