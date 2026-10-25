# DePHP2Shell branding

DePHP2Shell checks PHP first and attempts a supported update without changing
package providers. The visual identity combines a terminal prompt with an open,
angular shell. A copper join suggests a careful repair.

Use **DePHP2Shell** with this capitalisation. The short description is
“PHP security checks for mixed Linux fleets.” The tagline is
**“Check first. Patch carefully.”** Neither is a guarantee of complete detection
or a successful fix.

## Assets

| File | Use |
| --- | --- |
| [Vector logo](../assets/branding/logo.svg) | Editable paths on a transparent background; scales to any size. |
| [Transparent logo](../assets/branding/logo.png) | Square avatars, icons and presentations; 1254 × 1254 PNG with transparency. |
| [README banner](../assets/branding/readme-banner.png) | Repository masthead; 2172 × 724 PNG, with its own dark background for either GitHub theme. |

The SVG is a clean vector reconstruction of the original PNG mark, with separate
paths for the shell, prompt and copper join. It contains no embedded bitmap,
fonts or external resources. Use it for resizing and editing.

The README uses the banner through a relative image link, so it travels with a
clone or fork. The transparent mark is readable on light and dark backgrounds.
Prefer at least 48 pixels for an icon where space permits. Keep the clear space
around the mark, preserve its proportions, and use the full-resolution files for
larger placements. Avoid recolouring, stretching or putting the mark over a busy
background.

## Palette

These are the reference colours for future companion assets. The generated PNGs
include subtle tonal variation.

| Colour | Hex | Role |
| --- | --- | --- |
| Ink navy | `#10222D` | Banner background |
| Deep teal | `#187D80` | Main mark |
| Bright teal | `#36B6AC` | Mark accent |
| Copper | `#D48851` | Repair join |
| Warm white | `#F5F3EE` | Text on navy |

Use a plain sans-serif for headings and body text. Reserve monospace for commands.
Keep language practical and calm: describe checks, supported updates and limits
rather than promising that a server is safe.

RimuHosting attribution is secondary to the project name. Retain the existing
[licence](../LICENSE) and [trademark notice](../NOTICE); these assets do not imply
endorsement of modified versions.

## Generation prompts

Both PNGs were created with the built-in OpenAI image-generation tool. The banner
used the transparent logo as its identity reference. These prompts record the
creative brief; inspect any regenerated artwork for lettering, transparency and
small-size legibility before replacing an asset.

### Logo

```text
Use case: logo-brand. Asset: standalone square logo mark for an open-source Linux PHP security maintenance tool named DePHP2Shell. Generate ONE finished, original logo mark, centered on a genuinely transparent background, no text or lettering. Design a compact geometric protective shell from two substantial interlocking angular terminal-bracket forms: an open hexagonal silhouette, with a terminal chevron and underscore thoughtfully formed in the negative space. A small warm copper join or repair segment should be the distinctive detail, suggesting careful patching and repair. Simple silhouette, precise flat shapes, consistent thick geometry, comfortable internal spacing, excellent legibility at small avatar sizes. Main color deep teal #187D80 with a lighter teal #36B6AC face so it stands out on both light and dark surfaces; copper accent #D48851. No gradients, no shadows, no glow, no 3D, no texture, no mockup, no background, no shield-with-checkmark stock icon, no padlock, no mascots. Restrained, confident Unix utility branding with a custom, memorable terminal-shell motif. Keep generous transparent clear space around the single mark. Do not draw a wordmark or any typography.
```

### README banner

Reference image: `assets/branding/logo.png`.

```text
Use case: logo-brand. Asset: polished horizontal GitHub README masthead for DePHP2Shell. Input image 1 is the existing logo identity reference. Reuse its distinctive open hexagonal teal shell / terminal prompt / small copper repair join faithfully; do not invent another logo. Create a finished ultra-wide landscape banner with a 3:1 aspect ratio, approximately 2400x800. Opaque solid very dark ink-navy background #10222D, with exceptionally restrained thin darker-teal terminal-grid line details only near the corners, no decorative clutter. Comfortable clear space and balanced editorial typography. Place the reference logo at the left, sized to roughly two thirds of the banner height. To its right put the EXACT product name "DePHP2Shell" in large, crisp warm-white modern sans-serif typography, accurately capitalised D e P H P 2 S h e l l. Below the name, smaller but easily readable: "Check first. Patch carefully." Under that, a subtle smaller line: "PHP security checks for mixed Linux fleets." At the lower right put a tiny restrained "by RimuHosting" attribution. Three text lines plus attribution only; no extra words, no fake command text, no badges. Teal #36B6AC and copper #D48851 should be subtle accents; text #F5F3EE. Professional, calm, useful open-source infrastructure software branding. This is a final flat digital artwork, not a photograph, not a browser screenshot, not a mockup on a surface. No gradients or neon effects, no 3D, no drop shadows, no bevels, no padlocks, no promises of guaranteed security. The banner must remain clear when scaled to a GitHub README column about 800 pixels wide. Preserve generous padding on all edges.
```
