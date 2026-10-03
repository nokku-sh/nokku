<script lang="ts" module>
	import type { LucideIcon } from '@lucide/svelte';

	export type TagsInputProps = {
		value?: string[];
		onValueChange?: (value: string[]) => void;
		id?: string;
		placeholder?: string;
		/** Offered while typing. Already added ones are hidden. */
		suggestions?: string[];
		/** Return false or an error message to reject a tag. */
		validate?: (tag: string) => boolean | string;
		/** Normalizes each tag before it is added. Trims by default. */
		transform?: (tag: string) => string;
		/** Splits typed and pasted text into tags. */
		separator?: RegExp;
		max?: number;
		icon?: LucideIcon;
		disabled?: boolean;
		class?: string;
		'aria-invalid'?: boolean;
	};
</script>

<script lang="ts">
	import { Popover } from 'bits-ui';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { cn } from '#lib/utils.js';
	import { X } from '@lucide/svelte';

	let {
		value = $bindable([]),
		onValueChange,
		id,
		placeholder = 'Add…',
		suggestions = [],
		validate,
		transform = (tag) => tag.trim(),
		separator = /[,\n]+/,
		max,
		icon: Icon,
		disabled = false,
		class: className,
		'aria-invalid': ariaInvalid
	}: TagsInputProps = $props();

	const uid = $props.id();
	const listId = `${uid}-suggestions`;

	let root = $state<HTMLElement | null>(null);
	let input = $state<HTMLInputElement | null>(null);
	let text = $state('');
	let focused = $state(false);
	/** Chip picked by the arrow keys or a first Backspace, -1 when none. */
	let active = $state(-1);
	let highlighted = $state(0);
	let flash = $state('');
	let error = $state('');

	const full = $derived(max !== undefined && value.length >= max);
	const matches = $derived(
		suggestions
			.filter((s) => !value.includes(s) && s.toLowerCase().includes(text.trim().toLowerCase()))
			.slice(0, 8)
	);
	const open = $derived(focused && !full && matches.length > 0);

	function set(next: string[]) {
		value = next;
		onValueChange?.(next);
	}

	/** Adds every tag in `raw`, keeps the rejected rest in the input. */
	function commit(raw: string) {
		let next = [...value];
		const rejected: string[] = [];
		error = '';
		for (const part of raw.split(separator)) {
			const tag = transform(part);
			if (!tag) continue;
			if (next.includes(tag)) {
				flash = tag;
				setTimeout(() => flash === tag && (flash = ''), 600);
				continue;
			}
			const verdict = validate?.(tag) ?? true;
			if (verdict !== true || (max !== undefined && next.length >= max)) {
				rejected.push(part.trim());
				error =
					typeof verdict === 'string'
						? verdict
						: verdict
							? `Up to ${max} allowed`
							: `Invalid: ${tag}`;
				continue;
			}
			next = [...next, tag];
		}
		if (next.length !== value.length) set(next);
		text = rejected.join(', ');
		highlighted = 0;
	}

	function remove(index: number) {
		set(value.filter((_, i) => i !== index));
		active = -1;
		input?.focus();
	}

	function onkeydown(e: KeyboardEvent) {
		const empty = text === '';
		switch (e.key) {
			case 'Enter':
				if (open && matches[highlighted]) {
					e.preventDefault();
					commit(matches[highlighted]);
				} else if (!empty) {
					// Only an empty input lets Enter submit the surrounding form.
					e.preventDefault();
					commit(text);
				}
				return;
			case ',':
				e.preventDefault();
				commit(text);
				return;
			case 'Tab':
				if (!empty) commit(text);
				return;
			case 'Backspace':
			case 'Delete':
				if (!empty) break;
				e.preventDefault();
				if (active >= 0) remove(active);
				else if (e.key === 'Backspace' && value.length) active = value.length - 1;
				return;
			case 'ArrowLeft':
				if (!empty || !value.length) break;
				e.preventDefault();
				active = active < 0 ? value.length - 1 : Math.max(0, active - 1);
				return;
			case 'ArrowRight':
				if (active < 0) break;
				e.preventDefault();
				active = active + 1 < value.length ? active + 1 : -1;
				return;
			case 'ArrowDown':
			case 'ArrowUp':
				if (!open) break;
				e.preventDefault();
				highlighted =
					(highlighted + (e.key === 'ArrowDown' ? 1 : -1) + matches.length) % matches.length;
				return;
			case 'Escape':
				if (active >= 0 || text) {
					e.preventDefault();
					e.stopPropagation();
					active = -1;
					text = '';
				}
				return;
		}
		active = -1;
	}

	function onpaste(e: ClipboardEvent) {
		const pasted = e.clipboardData?.getData('text') ?? '';
		if (!separator.test(pasted)) return;
		e.preventDefault();
		commit(text + pasted);
	}
</script>

<div class="flex w-full flex-col gap-1">
	<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
	<div
		bind:this={root}
		data-slot="tags-input"
		data-disabled={disabled || undefined}
		aria-invalid={ariaInvalid || !!error || undefined}
		class={cn(
			'flex min-h-8 w-full cursor-text flex-wrap items-center gap-1 rounded-lg border border-input bg-transparent px-1.5 py-1 text-sm transition-colors focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:bg-input/30 data-disabled:cursor-not-allowed data-disabled:opacity-50',
			className
		)}
		onclick={() => input?.focus()}
	>
		{#if Icon}
			<Icon class="mx-1 size-4 shrink-0 text-muted-foreground" />
		{/if}
		{#each value as tag, i (tag)}
			<Badge
				variant="secondary"
				data-active={active === i || undefined}
				class={cn(
					'h-6 gap-0.5 rounded-full pr-0.5 pl-2 font-normal transition-all data-active:ring-2 data-active:ring-ring/60',
					flash === tag && 'animate-pulse ring-2 ring-warning/60'
				)}
			>
				<span class="max-w-48 truncate">{tag}</span>
				{#if !disabled}
					<button
						type="button"
						tabindex={-1}
						class="rounded-full p-0.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
						aria-label={`Remove ${tag}`}
						onclick={(e) => {
							e.stopPropagation();
							remove(i);
						}}
					>
						<X class="size-3" />
					</button>
				{/if}
			</Badge>
		{/each}
		<input
			bind:this={input}
			bind:value={text}
			{id}
			type="text"
			autocomplete="off"
			role="combobox"
			aria-expanded={open}
			aria-controls={listId}
			aria-activedescendant={open ? `${listId}-${highlighted}` : undefined}
			disabled={disabled || full}
			placeholder={value.length ? '' : placeholder}
			class="h-6 min-w-20 flex-1 bg-transparent px-1 outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed"
			{onkeydown}
			{onpaste}
			oninput={() => {
				error = '';
				highlighted = 0;
			}}
			onfocus={() => (focused = true)}
			onblur={() => {
				focused = false;
				active = -1;
				if (text) commit(text);
			}}
		/>
	</div>
	{#if error}
		<p class="text-xs text-destructive" role="alert">{error}</p>
	{/if}
</div>

<Popover.Root {open}>
	<Popover.Portal>
		<Popover.Content
			customAnchor={root}
			align="start"
			sideOffset={4}
			trapFocus={false}
			onOpenAutoFocus={(e) => e.preventDefault()}
			onCloseAutoFocus={(e) => e.preventDefault()}
			class="z-50 w-(--bits-popover-anchor-width) min-w-48 rounded-lg bg-popover p-1 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10"
		>
			<div id={listId} role="listbox">
				{#each matches as match, i (match)}
					<div
						id={`${listId}-${i}`}
						role="option"
						tabindex={-1}
						aria-selected={i === highlighted}
						class="cursor-default rounded-md px-2 py-1.5 aria-selected:bg-accent aria-selected:text-accent-foreground"
						onpointerdown={(e) => {
							// Keeps focus in the input so blur doesn't commit the half typed text.
							e.preventDefault();
							commit(match);
						}}
						onpointermove={() => (highlighted = i)}
					>
						{match}
					</div>
				{/each}
			</div>
		</Popover.Content>
	</Popover.Portal>
</Popover.Root>
