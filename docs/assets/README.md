# README artwork

The root README uses two illustrations: the release boundary and the payment
lifecycle. Each has a light, dark, desktop, and mobile variant. The `<picture>`
elements select the appropriate file; the desktop light image is the fallback.

## Regenerate

Edit `generate.py`, then run from the repository root:

```sh
python3 docs/assets/generate.py
```

The generator uses only the Python standard library. Commit the generated SVGs
with their source so GitHub can render them without a build step.

## Design and behavior

- Singularity's Paper and Void backgrounds, neutral type, and an orange signal.
- The supplied Singularity logo stays static; its lettering is outlined vector artwork.
- Explanatory text uses system fonts. No font downloads, scripts, raster images, or external resources.
- The hero's signal pauses at the release boundary, then travels toward the signature.
- The animation runs once for 7.5 seconds and leaves the complete static illustration.
- Reduced-motion settings disable animation. The lifecycle diagram is always static.
- Every image has a title, description, and descriptive README alternative text.
- Essential product claims, lifecycle details, and limitations remain in Markdown.

The release-boundary mark is a conceptual illustration, not a count of signers or
approvers. The lifecycle diagram groups ordered steps into three phases. In the
current implementation, the authority is a trusted single writer. It commits
release before signers expose output. Chain finality is a later decision.

The hero embeds the [supplied brand assets](brand/README.md). Their geometry,
lettering, and colors are unchanged. The Singularity identifies the project's
publisher; the release-boundary illustration describes the custody flow.
Keep orange confined to the moving signal, with neutral text and diagram shapes.

When editing the images, check both themes and viewport sizes. The first static
frame must remain meaningful if a renderer ignores animation. Keep the diagrams
consistent with the [payment walkthrough](../payment-flow.md) and source tests.

## Earlier artwork

The [VibeSVG project](custody-banner.vsvg.json) retains the earlier banner design.
Export that project to a separate directory. `generate.py` produces the SVGs used
by the current README.
