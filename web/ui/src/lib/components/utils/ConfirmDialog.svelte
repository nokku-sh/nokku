<script lang="ts">
	import * as AlertDialog from '$lib/components/ui/alert-dialog';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Spinner } from '$lib/components/ui/spinner';
	import { confirmState } from '$lib/hooks';
	import { TriangleAlert } from '@lucide/svelte';
	import CopyText from './CopyText.svelte';

	const opts = $derived(confirmState.options);
	const destructive = $derived(opts?.destructive ?? true);
	const canConfirm = $derived(
		!!opts &&
			(!opts.typeToConfirm || confirmState.value === opts.typeToConfirm) &&
			(!opts.input || !!confirmState.value)
	);
</script>

<AlertDialog.Root open={!!opts} onOpenChange={(open) => !open && confirmState.cancel()}>
	<AlertDialog.Content interactOutsideBehavior={confirmState.pending ? 'ignore' : 'close'}>
		<form
			class="contents"
			onsubmit={(e) => {
				e.preventDefault();
				if (canConfirm) void confirmState.accept();
			}}
		>
			<AlertDialog.Header>
				{#if destructive}
					<AlertDialog.Media class="bg-destructive/10 text-destructive">
						<TriangleAlert />
					</AlertDialog.Media>
				{/if}
				<AlertDialog.Title>{opts?.title}</AlertDialog.Title>
				{#if opts?.description}
					<AlertDialog.Description>{opts.description}</AlertDialog.Description>
				{/if}
			</AlertDialog.Header>

			{#if opts?.typeToConfirm || opts?.input}
				<Field.Field>
					<Field.Label for="confirm-value">
						{#if opts.typeToConfirm}
							Type
							<CopyText value={opts.typeToConfirm} mono class="font-semibold text-foreground" />
							to confirm
						{:else}
							{opts.input?.label}
						{/if}
					</Field.Label>
					<Input
						id="confirm-value"
						type={opts.input?.type ?? 'text'}
						autocomplete="off"
						bind:value={confirmState.value}
						placeholder={opts.typeToConfirm}
						disabled={confirmState.pending}
					/>
				</Field.Field>
			{/if}

			<AlertDialog.Footer>
				<AlertDialog.Cancel type="button" disabled={confirmState.pending}>
					Cancel
				</AlertDialog.Cancel>
				<AlertDialog.Action
					type="submit"
					variant={destructive ? 'destructive' : 'default'}
					disabled={!canConfirm || confirmState.pending}
				>
					{#if confirmState.pending}
						<Spinner data-icon="inline-start" />
					{/if}
					{opts?.confirmText ?? (destructive ? 'Delete' : 'Confirm')}
				</AlertDialog.Action>
			</AlertDialog.Footer>
		</form>
	</AlertDialog.Content>
</AlertDialog.Root>
