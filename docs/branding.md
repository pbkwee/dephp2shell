# DePHP2Shell branding

Use **DePHP2Shell** with this spelling. The tagline is **“Check first. Patch carefully.”**
and the short description is “PHP security checks for mixed Linux fleets.”

The PHP document and magnifying glass represent inspecting PHP installations before attempting supported security updates.
Preserve the traced contours and PHP lettering when making colour variants.

## RimuHosting design system

The tool uses RimuHosting's brand colours and CartoGothic Std typography.
The banner follows the site's Warm Surface masthead style, with Warm Ink text,
a Bark edge, a small mono eyebrow and secondary RimuHosting attribution.
The official tree and wordmark retain their canonical logo colours.

| Token | Colour | Role |
| --- | --- | --- |
| `--rr-clr-brand-surface-warm` | `#F4EEDB` | Banner surface |
| `--rr-clr-brand-ink` | `#251D18` | Product name and description |
| `--rr-clr-brand-bark` | `#452008` | Tagline and top edge |
| `--rr-clr-brand-link` | `#255982` | PHP document and lettering |
| `--rr-clr-brand-clay` | `#996444` | Magnifying glass |
| `--rh-clr-clay-deep` | `#8A5A3C` | Small eyebrow and attribution text |
| `--rr-clr-brand-canvas` | `#FFFFFF` | PHP document and lettering on dark surfaces |
| `--rr-clr-brand-nav-tan` | `#BC9B85` | Magnifying glass on dark surfaces only |

CartoGothic lettering is converted to paths so viewers need no installed fonts.
The standalone tool symbol is transparent and contains no embedded fonts or images.

## Assets

| File | Use |
| --- | --- |
| [SVG logo](../assets/branding/logo.svg) | Editable tool symbol on a transparent background. |
| [PNG logo](../assets/branding/logo.png) | 1254 × 1254 transparent export for avatars and presentations. |
| [Dark-surface SVG logo](../assets/branding/logo-dark.svg) | White and Navigation Tan variant for Bark or other dark backgrounds. |
| [Dark-surface PNG logo](../assets/branding/logo-dark.png) | 1254 × 1254 transparent export of the dark-surface variant. |
| [SVG README banner](../assets/branding/readme-banner.svg) | Editable 2172 × 724 artwork, including outlined brand typography and the company lockup. |
| [PNG README banner](../assets/branding/readme-banner.png) | README masthead with an opaque surface for either GitHub theme. |

Keep the symbol's proportions and clear space. Prefer at least 48 pixels for
the standalone logo. Use the banner when the name and tagline are needed.
Use `logo.svg` or `logo.png` on light surfaces and the `logo-dark` variant on dark surfaces.
Describe supported operations and their limits alongside the artwork.

## Editing and export

The SVG files are the current source artwork. The logo was recoloured with the built-in image-generation tool, then its contours were traced into editable vector paths.
The banner combines that same logo with outlined brand typography.
To change wording, set it in CartoGothic Std and convert the lettering to paths.
Preserve the official company lockup. Regenerate PNGs after editing:

```sh
cairosvg assets/branding/logo.svg -o assets/branding/logo.png -s 1
cairosvg assets/branding/logo-dark.svg -o assets/branding/logo-dark.png -s 1
cairosvg assets/branding/readme-banner.svg -o assets/branding/readme-banner.png
```

CairoSVG is a maintainer export tool, not a dependency of the server tools.

## Recreation brief

Use the PHP-file-and-magnifying-glass logo as the identity reference.
Preserve its document silhouette, folded corner, PHP lettering, lens and diagonal handle.
Use RimuHosting Link Blue `#255982` for the file and Clay `#996444` for the magnifier.
Keep the background, document interior and lens interior transparent.
Use white and Navigation Tan `#BC9B85` on dark surfaces.
Retain the banner's Warm Surface, CartoGothic typography, official company lockup and exact wording.

The SVG files preserve the traced contours and exact colours. Keep their silhouette and letterforms when making variants.

The artwork uses the repository's existing [licence](../LICENSE).
Retain the [trademark notice](../NOTICE); the assets do not imply endorsement of modified versions.
