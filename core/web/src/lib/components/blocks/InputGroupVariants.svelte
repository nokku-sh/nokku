<script lang="ts">
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { CheckIcon, CopyIcon, SearchIcon, DeleteIcon, EyeOffIcon, EyeIcon } from '@lucide/svelte';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import type { ComponentProps } from 'svelte';
	import type { Input } from '#lib/components/ui/input/index.js';

	type Variant = 'copy-input' | 'search' | 'password';

	interface Props {
		variant: Variant;
		value?: string;
		placeholder?: string;
		readonly?: boolean;
		class?: string;
		searchResults?: number;
		inputProps?: ComponentProps<typeof Input>;
		/** Names the copied value for screen readers, as in "Copy redirect URI". */
		copyLabel?: string;
	}

	let {
		variant,
		value = $bindable(''),
		placeholder = '',
		readonly = false,
		class: className = '',
		searchResults,
		inputProps = {},
		copyLabel
	}: Props = $props();

	const clipboard = new UseClipboard({ delay: 1200 });

	let showPassword = $state(false);
</script>

{#if variant === 'copy-input'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value class="truncate" {placeholder} {readonly} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label={copyLabel ? `Copy ${copyLabel}` : 'Copy'}
				title="Copy"
				size="icon-xs"
				onclick={() => clipboard.copy(value)}
			>
				{#if clipboard.copied}
					<CheckIcon />
				{:else}
					<CopyIcon />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
	<span class="sr-only" aria-live="polite">{clipboard.copied ? 'Copied' : ''}</span>
{:else if variant === 'search'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value placeholder={placeholder || 'Search...'} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			{#if value}
				{#if searchResults}
					<span class="text-xs text-muted-foreground">
						{searchResults}
						{searchResults === 1 ? 'result' : 'results'}
					</span>
				{/if}
				<InputGroup.Button variant="ghost" size="icon-xs" onclick={() => (value = '')}>
					<DeleteIcon />
				</InputGroup.Button>
			{/if}
		</InputGroup.Addon>
		<InputGroup.Addon>
			<SearchIcon />
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'password'}
	<InputGroup.Root class={className}>
		<InputGroup.Input
			type={showPassword ? 'text' : 'password'}
			bind:value
			placeholder={placeholder || 'Enter your password'}
			{...inputProps}
		/>
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label="Show password"
				title="Show password"
				variant="ghost"
				size="icon-xs"
				class="size-7"
				onclick={() => (showPassword = !showPassword)}
			>
				{#if showPassword}
					<EyeIcon size={16} />
				{:else}
					<EyeOffIcon size={16} />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
{/if}
