import type { Attachment } from 'svelte/attachments';

function isTyping(target: EventTarget | null) {
	return (
		target instanceof HTMLElement &&
		(target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))
	);
}

/** Focuses the field when / is pressed anywhere outside an input. */
export const focusOnSlash: Attachment<HTMLElement> = (el) => {
	const onkeydown = (e: KeyboardEvent) => {
		if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
		// A sheet or dialog on top owns the keyboard.
		if (document.querySelector('[role="dialog"], [role="alertdialog"]')) return;
		e.preventDefault();
		el.focus();
	};
	window.addEventListener('keydown', onkeydown);
	return () => window.removeEventListener('keydown', onkeydown);
};
