import adapter from '@sveltejs/adapter-static';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const proxy = {
	'^/(auth|oauth|oidc|saml|passkey|avatars|upload|nokku\\.)': {
		target: 'http://localhost:3000',
		secure: false
	},
	'/terminal': {
		target: 'http://localhost:3000',
		secure: false,
		ws: true
	}
};
export default defineConfig({
	preview: { proxy },
	server: { proxy },
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({ fallback: 'index.html', precompress: true })
		})
	]
});
