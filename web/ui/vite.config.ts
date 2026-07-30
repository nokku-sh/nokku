import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { compression } from 'vite-plugin-compression2';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit(), compression()],
	server: {
		proxy: {
			'^/(oauth|saml|passkey|avatars|upload|nokku\\.)': {
				target: 'http://localhost:3000',
				changeOrigin: true,
				secure: false
			},
			'/terminal': {
				target: 'http://localhost:3000',
				changeOrigin: true,
				secure: false,
				ws: true
			}
		}
	}
});
