# Singularity brand assets

These are the supplied horizontal lockups from
[Singularity's brand repository](https://github.com/0xTheSingularity/singularity-design/tree/02f71ca57a4b5613016b13a1483aab1d1fb505d1/brand).
The files preserve the original paths, lettering, colors, and proportions.

| Local file | Upstream file | Git blob SHA |
| --- | --- | --- |
| `singularity-lockup-black.svg` | `brand/dist/brand/logo/lockup-horizontal-black.svg` | `7963ba6ea3ff094127fe20e9a8ad7b33db9816e0` |
| `singularity-lockup-white.svg` | `brand/dist/brand/logo/lockup-horizontal-white.svg` | `f6db23b86876a8baf0b360d44633500b55a4e0cc` |

Source commit: `02f71ca57a4b5613016b13a1483aab1d1fb505d1`.

## Use in this README

`../generate.py` embeds the supplied artwork in each hero. The generated SVGs
have no remote image or font dependencies. The product remains Open Institutional
Custody, with The Singularity named as its publisher.

The [brandbook](https://github.com/0xTheSingularity/singularity-design/blob/02f71ca57a4b5613016b13a1483aab1d1fb505d1/brand/dist/index.html)
specifies a minimum lockup width of 120 pixels and clearspace of one mark height.
Keep the logo static and separate from the technical illustration. Do not redraw,
stretch, recolor, or reconstruct the lockup.

The palette follows the
[current design tokens](https://github.com/0xTheSingularity/singularity-design/blob/02f71ca57a4b5613016b13a1483aab1d1fb505d1/design-system/assets/styles/tokens.css):
Paper `#F4F3F0`, Void `#08080A`, paper ink `#0E0E12`, and secondary text
`#5E5E66` / `#A6A6AD`. The small moving signal uses Accretion `#FF6A1A`.
All text and the static diagram remain neutral. Divider colors are adjusted for
the image's scale on GitHub.

The wordmark is already outlined. No font binaries are distributed with these
assets; explanatory text uses system fonts. Updating the source assets requires
regenerating and reviewing all four hero variants.
