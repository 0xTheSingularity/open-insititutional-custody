# README artwork

The editable source is [custody-banner.vsvg.json](custody-banner.vsvg.json).
Its light and dark pages share the same layout and labels.

From the repository root, open the project with VibeSVG:

```sh
vibesvg docs/assets/custody-banner.vsvg.json
```

Use the active editor's MCP tools for changes so autosave and previews stay synchronized.
Render each page before exporting. After saving, regenerate both assets with:

```sh
vibesvg export docs/assets/custody-banner.vsvg.json --out docs/assets
```

Keep the header compact. Use strong type and the actual signer verification gate.
Maintain identical geometry across themes and readable contrast for all labels.
Design reference: [the README examples guide](https://readmebot.dev/blog/best-readme-examples).
