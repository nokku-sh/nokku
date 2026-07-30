<script lang="ts">
	import { auth } from '$lib/api/auth.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import { BinaryIcon, CircleCheckBig, Mail, RefreshCw, Undo2Icon } from '@lucide/svelte';

	let email = $state('');
	const forgotPassword = auth.forgotPassword();
</script>

<section class="flex flex-col dark:bg-transparent">
	{#if !forgotPassword.isSuccess}
		<form
			onsubmit={() => forgotPassword.mutate({ email })}
			class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
		>
			<div
				class="-m-px flex flex-col gap-4 rounded-[calc(var(--radius)+.125rem)] border bg-card p-6"
			>
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
						<Mail class="text-primary" size={22} />
					</div>
					<h1 class="text-2xl font-bold">Reset your password</h1>
					<p class="text-balance text-muted-foreground">
						Enter your email address and we'll send you a recovery link
					</p>
				</div>

				<div class="space-y-2">
					<Label for="email">Email address</Label>
					<Input id="email" type="email" bind:value={email} required />
				</div>

				<Button type="submit" class="w-full" disabled={forgotPassword.isPending}>
					{#if forgotPassword.isPending}
						<RefreshCw class="animate-spin" size={16} />
						Sending recovery email...
					{:else}
						Send recovery email
					{/if}
				</Button>

				<div class="grid grid-cols-[1fr_auto_1fr] items-center gap-3">
					<hr class="border-solid" />
					<span class="text-xs text-muted-foreground">Or</span>
					<hr class="border-solid" />
				</div>

				<Button href="/login/backup" variant="outline" class="group flex w-full items-center gap-2">
					<BinaryIcon
						size={16}
						class="transition-transform duration-300 group-hover:scale-110 group-hover:rotate-12"
					/>
					Sign in with a backup code
				</Button>
			</div>

			<div class="p-3">
				<Button variant="link" class="w-full" href="/login" disabled={forgotPassword.isPending}>
					Go back to login
					<Undo2Icon size={16} />
				</Button>
			</div>
		</form>
	{:else}
		<div
			class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
		>
			<div
				class="-m-px flex flex-col gap-4 rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 md:p-8"
			>
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
						<CircleCheckBig class="text-primary" size={22} />
					</div>
					<h1 class="text-2xl font-bold">Check your email</h1>
					<p class="text-balance text-muted-foreground">
						We've sent a recovery link to <strong>{email}</strong>
					</p>
				</div>
				<div class="rounded-lg bg-muted p-4 text-sm text-muted-foreground">
					<p class="mb-2 font-medium">What's next?</p>
					<ul class="space-y-1">
						<li>• Check your email inbox (and spam folder)</li>
						<li>• Click the recovery link</li>
						<li>• Follow the instructions to reset your password</li>
						<li>• The link will expire in 24 hours</li>
					</ul>
				</div>
				<div class="flex flex-col gap-2">
					<Button variant="outline" type="button" class="w-full" onclick={() => (email = '')}>
						<Mail size={16} />
						Try different email
					</Button>
				</div>
			</div>

			<div class="p-3">
				<Button variant="link" class="w-full" href="/login" disabled={forgotPassword.isPending}>
					Go back to login
					<Undo2Icon size={16} />
				</Button>
			</div>
		</div>
	{/if}

	<div class="mt-6 text-center text-xs text-balance text-muted-foreground">
		By continuing, you agree to our
		<a href="##" class="underline underline-offset-4 hover:text-primary">Terms of Service</a> and
		<a href="##" class="underline underline-offset-4 hover:text-primary">Privacy Policy</a>.
	</div>
</section>
