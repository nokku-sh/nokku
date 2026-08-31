import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { compression } from 'vite-plugin-compression2';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit(), compression()],
	server: {
		proxy: {
			// changeOrigin must stay off: kagi's CSRF guard compares the
			// browser's Origin against the received Host header, and rewriting
			// Host to the target makes every authenticated POST fail with 403
			// invalid_origin.
			'^/(auth|oauth|oidc|saml|passkey|avatars|upload|nokku\\.)': {
				target: 'http://localhost:3000',
				secure: false
			},
			'/terminal': {
				target: 'http://localhost:3000',
				secure: false,
				ws: true
			}
		}
	}
});
