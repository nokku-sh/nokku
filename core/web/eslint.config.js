import svelte from 'eslint-plugin-svelte';
import ts from 'typescript-eslint';

// oxlint does the linting. ESLint is here for the one rule oxlint cannot run on Svelte files yet, since it needs
// types: a deprecated name, like a lucide icon that was renamed. Take this file out once oxlint can.
export default ts.config(
	{ ignores: ['build/', '.svelte-kit/', 'src/lib/gen/', 'src/lib/components/ui/', '*.config.*'] },
	// The files hold disable comments for rules that only oxlint runs.
	{ linterOptions: { reportUnusedDisableDirectives: 'off' } },
	...svelte.configs.base,
	{
		files: ['src/**/*.ts', 'src/**/*.svelte'],
		plugins: { '@typescript-eslint': ts.plugin },
		languageOptions: {
			parserOptions: { projectService: true, extraFileExtensions: ['.svelte'], parser: ts.parser }
		},
		rules: { '@typescript-eslint/no-deprecated': 'error' }
	},
	{ files: ['src/**/*.ts'], languageOptions: { parser: ts.parser } }
);
