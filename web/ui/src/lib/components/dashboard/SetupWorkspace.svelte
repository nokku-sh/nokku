<script lang="ts">
	import { user } from '$lib/api/user.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { Logo } from '$lib/assets';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Spinner } from '$lib/components/ui/spinner';
	import { ArrowRight } from '@lucide/svelte';

	const me = user.self();
	const create = workspace.create();

	let name = $state('');
	let input = $state<HTMLInputElement | null>(null);
	const first = $derived(me.data?.name?.split(' ')[0]);

	function submit(e: SubmitEvent) {
		e.preventDefault();
		if (name.trim()) create.mutate({ name: name.trim() });
	}

	$effect(() => input?.focus());
</script>

<svelte:head>
	<title>Welcome · Nokku</title>
</svelte:head>

<div class="flex flex-1 items-center justify-center p-6">
	<div class="flex w-full max-w-xl flex-col gap-8">
		<div class="flex flex-col items-center gap-3 text-center">
			<Logo class="w-14" />
			<h1 class="text-3xl font-semibold tracking-tight">
				Welcome{first ? `, ${first}` : ''}
			</h1>
			<p class="text-balance text-muted-foreground">
				A workspace holds your servers, people and certificates. Most teams need just one.
			</p>
		</div>

		<form
			onsubmit={submit}
			class="flex flex-col gap-4 rounded-xl border bg-terminal p-5 font-terminal text-sm text-terminal-foreground"
		>
			<p class="text-terminal-dim"><span class="text-terminal-accent">$</span> nokku init</p>
			<label class="flex flex-wrap items-center gap-x-2 gap-y-1">
				<span class="text-terminal-ok">?</span>
				<span class="font-bold">Name your workspace</span>
				<span class="text-terminal-dim">›</span>
				<Input
					bind:ref={input}
					bind:value={name}
					placeholder="acme-prod"
					maxlength={64}
					class="h-auto min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 font-terminal text-sm text-terminal-accent caret-terminal-accent shadow-none placeholder:text-terminal-dim focus-visible:ring-0 dark:bg-transparent"
					aria-label="Workspace name"
				/>
			</label>
			<p class="text-xs text-terminal-dim">
				Comes with a default CA, so every login is a short-lived certificate from the start.
			</p>
			<Button
				type="submit"
				class="self-end bg-terminal-accent text-terminal hover:bg-terminal-accent/90"
				disabled={!name.trim() || create.isPending}
			>
				{#if create.isPending}<Spinner data-icon="inline-start" />{/if}
				Create workspace
				<ArrowRight data-icon="inline-end" />
			</Button>
		</form>

		<p class="text-center text-sm text-muted-foreground">
			Invited to a team? Open the link from your invite email and you land in their workspace.
		</p>
	</div>
</div>
