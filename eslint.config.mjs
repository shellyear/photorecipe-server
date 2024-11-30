import globals from 'globals'
import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config({
  files: ['**/*.{js,mjs,cjs,ts}'],
  languageOptions: { globals: globals.node },
  extends: [pluginJs.configs.recommended, ...tseslint.configs.recommended],
  rules: {
    '@typescript-eslint/no-empty-object-type': 'off'
  }
})
