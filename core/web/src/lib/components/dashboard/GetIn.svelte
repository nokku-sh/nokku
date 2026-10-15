<script lang="ts">
	import { session } from '#lib/api/session.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { setupDismissed } from '#lib/store.svelte.js';
	import NkLogin from './NkLogin.svelte';

	// A CLI session is what nk login leaves behind, after that this card has done its job.
	const sessions = session.list();
	const show = $derived(
		!sessions.isLoading &&
			!setupDismissed.current &&
			!(sessions.data ?? []).some((s) => s.kind === 'cli')
	);
</script>

{#if show}
	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Get in from your terminal</h2></Card.Title>
			<Card.Description>
				Open a shell on a server below, right here in the browser. Or sign in your own terminal
				once, and use plain ssh like you always do. No keys to manage.
			</Card.Description>
			<Card.Action>
				<Button variant="ghost" size="sm" onclick={() => (setupDismissed.current = true)}>
					Dismiss
				</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content class="flex flex-col gap-3">
			<NkLogin />
		</Card.Content>
	</Card.Root>
{/if}
