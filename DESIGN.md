---
version: alpha
name: Tokyo3 Auth Control Plane
description: A restrained, security-oriented operations console with warm neutral surfaces and precise indigo interaction cues.
colors:
  primary: "#4F63D9"
  primary-hover: "#4053C4"
  primary-active: "#3444A5"
  on-primary: "#FFFFFF"
  surface: "#F5F5F3"
  surface-subtle: "#F0F1EE"
  surface-card: "#FBFAF8"
  secondary-action: "#F3F4F1"
  secondary-action-hover: "#F0F1EE"
  dark-secondary-action: "#303631"
  dark-secondary-action-hover: "#3A423B"
  dark-surface: "#151714"
  dark-surface-subtle: "#242823"
  dark-surface-card: "#1B1E1A"
  dark-on-surface: "#F0F2ED"
  dark-on-surface-muted: "#AEB4AA"
  dark-placeholder: "#777E75"
  dark-error-action: "#A52834"
  dark-error-action-hover: "#8E202B"
  surface-selected: "#EEF1FF"
  on-surface: "#20231F"
  on-surface-subtle: "#363A35"
  on-surface-muted: "#5F635D"
  outline: "#EEEEEB"
  outline-strong: "#D1D3CE"
  success: "#18794E"
  success-container: "#EDF8F2"
  warning: "#8F4F00"
  warning-container: "#FFF7E6"
  error: "#B4232C"
  error-action: "#B4232C"
  error-action-hover: "#941B24"
  error-container: "#FFF0F1"
  info: "#245EA8"
  info-container: "#EEF6FF"
typography:
  auth-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 28px
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: -0.025em
  page-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 22px
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: -0.02em
  section-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 18px
    fontWeight: 650
    lineHeight: 1.25
  card-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: -0.006em
  control:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 1.2
  metadata:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  navigation:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 500
    lineHeight: 1.25
  helper:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
  badge-label:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 12px
    fontWeight: 650
    lineHeight: 1.2
  label-caps:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 11px
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: 0.08em
  code:
    fontFamily: "SFMono-Regular, Cascadia Code, Consolas, monospace"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: 4px
  md: 6px
  lg: 10px
  full: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  base: 16px
  lg: 20px
  xl: 24px
  2xl: 32px
  3xl: 40px
  4xl: 48px
  sidebar-width: 240px
  content-max: 1280px
  form-max: 680px
  auth-card-width: 420px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-primary-active:
    backgroundColor: "{colors.primary-active}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.secondary-action}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-secondary-hover:
    backgroundColor: "{colors.secondary-action-hover}"
  button-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-danger:
    backgroundColor: "{colors.error-action}"
    textColor: "{colors.on-primary}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-danger-hover:
    backgroundColor: "{colors.error-action-hover}"
    textColor: "{colors.on-primary}"
  input-field:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px 12px
    height: 38px
  card:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  navigation-active:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.primary-active}"
    typography: "{typography.navigation}"
    rounded: "{rounded.md}"
    padding: 8px 12px
  badge-neutral:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.success}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-danger:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.error}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-info:
    backgroundColor: "{colors.info-container}"
    textColor: "{colors.info}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  table-heading:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.label-caps}"
  helper-text:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.helper}"
  page-canvas:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
  page-canvas-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-on-surface}"
  card-dark:
    backgroundColor: "{colors.dark-surface-card}"
    textColor: "{colors.dark-on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  input-field-dark:
    backgroundColor: "{colors.dark-surface-subtle}"
    textColor: "{colors.dark-on-surface}"
    rounded: "{rounded.md}"
    height: 38px
  helper-text-dark:
    textColor: "{colors.dark-on-surface-muted}"
    typography: "{typography.helper}"
  placeholder-dark:
    textColor: "{colors.dark-placeholder}"
    typography: "{typography.body}"
  button-danger-dark:
    backgroundColor: "{colors.dark-error-action}"
    textColor: "{colors.on-primary}"
  button-danger-dark-hover:
    backgroundColor: "{colors.dark-error-action-hover}"
  button-secondary-dark:
    backgroundColor: "{colors.dark-secondary-action}"
    textColor: "{colors.dark-on-surface}"
  button-secondary-dark-hover:
    backgroundColor: "{colors.dark-secondary-action-hover}"
  divider:
    backgroundColor: "{colors.outline}"
    size: 1px
  control-outline:
    backgroundColor: "{colors.outline-strong}"
    size: 1px
---

# Tokyo3 Auth Design System

## Overview

Tokyo3 Auth should feel like a **well-kept control room logbook translated into a modern operations console**. It has the precision and restraint of infrastructure tooling, but the calm reading rhythm of a carefully typeset technical handbook. The interface is for operators and users making consequential identity and access decisions; it must inspire confidence without looking theatrical or severe.

The visual character is quiet, warm, and exact:

- Warm off-white canvas rather than cold blue-gray or pure white.
- White instrument panels separated by fine rules.
- Indigo interaction cues used with discipline.
- Compact information density with enough space to prevent mistakes.
- Explicit language and visible consequences for security actions.

This is not a marketing dashboard. There are no hero metrics, decorative charts, glass effects, oversized headings, or ornamental gradients. Authentication pages are focused checkpoints. Administrative pages are durable working surfaces designed for repeated use.

### Look-and-feel tuning

The easiest safe places to twist the visual character later are:

1. The `primary`, `primary-hover`, `primary-active`, and `surface-selected` colors.
2. The `sm`, `md`, and `lg` corner radii.
3. The amount of elevation described below.
4. The system font stack and heading weights.
5. The balance between `surface` and `surface-subtle`.

Keep semantic success, warning, error, and information colors stable unless their accessibility and meaning are reviewed together. Do not change route behavior, field names, native input semantics, autocomplete, or security confirmations as part of a visual experiment.

## Colors

The palette uses **warm paper neutrals with a single indigo control signal**. Dark mode preserves the same semantic hierarchy with charcoal surfaces and softened indigo controls rather than inverting every color mechanically.

- **Primary Indigo (`{colors.primary}`):** Primary actions, focus, active navigation, and selected controls. It signals that something is actionable, not merely important.
- **Warm Canvas (`{colors.surface}`):** The application background. It is intentionally softer than white so cards and forms remain legible without heavy shadows.
- **Soft Card (`{colors.surface-card}`):** Forms, grouped settings, resource panels, and authentication cards. It is warm rather than stark white to reduce glare on long pages.
- **Soft Surface (`{colors.surface-subtle}`):** Hover states, disabled fields, quiet metadata, and nested option groups.
- **Ink (`{colors.on-surface}`):** Primary text. Near-black but not absolute black.
- **Muted Ink (`{colors.on-surface-muted}`):** Descriptions, timestamps, field help, and secondary identifiers. It remains dark enough to retain readable contrast on the warm surfaces.
- **Outlines (`{colors.outline}`, `{colors.outline-strong}`):** Hairline grouping and control boundaries. Borders should remain visible but never dominate the page.

Semantic colors communicate state rather than branding:

- **Success (`{colors.success}`):** Active, connected, enrolled, or completed.
- **Warning (`{colors.warning}`):** Recoverable but consequential actions and states requiring attention.
- **Error (`{colors.error}`):** Failure, compromise response, blocked access, and irreversible deletion.
- **Information (`{colors.info}`):** Policies, capabilities, role labels, and one-time disclosures.

Never communicate status through color alone. Pair color with clear text, and use an icon or status dot only as reinforcement.

## Typography

Tokyo3 Auth uses the native system sans-serif stack. The intention is operational familiarity: text should look at home on the operator's platform, render immediately, and remain highly legible without introducing a font-download dependency.

- **Authentication titles** use `{typography.auth-title}` and are the strongest text in focused sign-in flows.
- **Page titles** use `{typography.page-title}`. They are compact because the application is a working console, not an editorial landing page.
- **Section titles** use `{typography.section-title}` for meaningful page divisions.
- **Card titles** use `{typography.card-title}` and should describe one bounded responsibility.
- **Body text** uses `{typography.body}` for the default reading rhythm.
- **Controls** use `{typography.control}` so action labels remain clear at compact sizes.
- **Metadata** uses `{typography.metadata}` for timestamps, descriptions, and secondary identifiers.
- **Caps labels** use `{typography.label-caps}` only for table headings and sidebar domain labels.
- **Technical values** use `{typography.code}` for UUIDs, client IDs, ARNs, scopes, temporary passwords, and secrets.

Use sentence case for headings, navigation, labels, and buttons. Avoid title case, all-caps prose, ultra-light text, and oversized display typography. Technical identifiers may truncate visually only when the full value remains available through selection, title text, or a copy action.

## Layout

The desktop application uses a fixed `{spacing.sidebar-width}` sidebar and a fluid content region capped at `{spacing.content-max}`. Forms remain readable at `{spacing.form-max}` rather than stretching across the entire viewport. Focused authentication cards use `{spacing.auth-card-width}`.

The layout follows a 4px base rhythm expressed by the spacing scale. Use smaller steps inside controls and tightly related groups, `{spacing.xl}` to `{spacing.2xl}` around page regions, and larger gaps only when separating different tasks.

Information architecture follows stable operational patterns:

- **Resource list:** Page header, optional status, resource table, complete empty state.
- **Resource detail:** Breadcrumb, identity, settings, recovery operations, danger zone.
- **Settings:** Named sections with local explanations and honest form boundaries.
- **Authentication:** Brand, task title, an optional one-sentence context, form, one primary action. When the flow continues to a known client application, the context sentence names the destination as a highlighted chip — `{colors.surface-selected}` background with a fine `{colors.primary}`-tinted outline, `{colors.primary-active}` text, body-sized 650-weight text, `{rounded.full}` — so the user can verify where they are signing in to at a glance without the chip competing with the primary action. Context sentences that add no information (restating that a sign-in form signs you in) are omitted.
- **Application launcher:** Product identity, relevant access metadata, one launch action.
- **Event list:** Freshness state followed by chronological technical data.

At widths below 1024px, navigation becomes an off-canvas panel when JavaScript is available and remains in normal flow without JavaScript. At widths below 640px, forms become single-column, page actions wrap, and cards use reduced padding. Dense tables scroll only inside their table region; the document itself must never scroll horizontally.

Descriptions use an explicit hierarchy: page descriptions explain the screen in muted but readable text; section descriptions use stronger body-sized text; field help remains compact but readable beneath its control. This hierarchy should preserve orientation on long edit pages.

Dark mode is the default. Use `{colors.dark-surface}` for the canvas, `{colors.dark-surface-card}` for cards, `{colors.dark-surface-subtle}` for quiet controls, and `{colors.dark-on-surface}` / `{colors.dark-on-surface-muted}` for text. Dark primary actions use a deeper indigo so white labels retain clear contrast. Keep the same spacing, shapes, status meanings, and action hierarchy in both modes. Users may explicitly switch between light and dark mode; an explicit choice is persisted locally and overrides the default.

Do not add search, filters, pagination, tabs, or overflow menus unless the behavior exists. Visual completeness must not imply unsupported functionality.

## Elevation & Depth

Tokyo3 Auth is primarily flat. Depth comes from **tonal layers and borders**, not floating cards.

- The warm canvas is level zero.
- White cards and resource panels sit one tonal step above it with a 1px outline.
- Default cards may use only a nearly imperceptible `0 1px 2px` shadow at roughly 6% opacity.
- Menus, mobile navigation, popovers, and dialogs may use a broader `0 12px 32px` shadow at roughly 16% opacity because they genuinely overlap content.
- Authentication cards may use the subtle default shadow, never a dramatic floating treatment.

Avoid nested cards. Use headings, spacing, and dividers when a border does not add meaningful grouping. Hover must not lift ordinary table rows or settings panels.

## Shapes

The shape language is **soft precision**: enough rounding to feel contemporary, but never pillowy or playful.

- Controls and buttons use `{rounded.md}`.
- Cards and resource panels use `{rounded.lg}`.
- Small technical elements may use `{rounded.sm}`.
- Badges and status chips use `{rounded.full}`.
- Danger zones use the same card geometry as ordinary sections; risk is communicated through border color, placement, language, and action styling rather than a different silhouette.

Icons, when present, use one consistent outline family with matching stroke weight and rounded line caps. Icons never replace text labels for navigation or security actions.

## Components

### Application shell

The sidebar groups Auth destinations into Identity, Access, Connections, and Operations. Section labels use a quiet surface and border so they read as group headers rather than ordinary links. Active navigation uses `{components.navigation-active}` plus a visible leading indicator and `aria-current`. The current user and icon-only theme toggle share one footer row; Profile and the POST-based Sign out action remain on the row below. The icon must retain an accessible label and tooltip.

Mobile navigation uses a labeled toggle, `aria-expanded`, `aria-hidden`, `inert`, focus containment, Escape handling, backdrop dismissal, and focus restoration. Without JavaScript, navigation remains usable in document flow.

### Page headers

A page header may contain a breadcrumb, one H1, a one-sentence description, and page-level actions. On narrow screens, actions remain fully labeled and wrap beneath or beside the title. Do not repeat the same title inside the first card.

### Buttons

- **Primary:** `{components.button-primary}`. Use once per page or bounded section for the main forward action.
- **Secondary:** `{components.button-secondary}`. Use for cancellation, neutral actions, and action-like navigation. In dark mode it uses a charcoal green-gray surface so it remains visible against cards without competing with indigo primary actions.
- **Warning:** `{components.button-warning}`. Use for recoverable security operations such as password reset, MFA clearing, or session revocation.
- **Danger:** `{components.button-danger}`. Use for compromise response and irreversible deletion.

Button text begins with a specific verb and names the target when ambiguity is possible. Pending buttons retain their width and block duplicate submission. Disabled buttons are never the only explanation for an unavailable action.

### Forms

Inputs follow `{components.input-field}`. Every control has a programmatic label. Placeholder text is intentionally dimmer than entered text and never replaces a label. Help text appears beneath the field; validation errors explain how to recover. Preserve native input types and meaningful autocomplete values. Disabled and read-only states must look and behave differently.

Long edit forms are divided into named sections with a short explanation and a divider between unrelated responsibilities. OAuth client editing uses Identity and protocol, Security and authorization, Portal presentation, and Portal access sections. Keep the final save/cancel actions outside those sections so the user has one clear completion point.

Related choices use semantic grouping. Secret values remain masked until deliberately revealed. One-time passwords and client secrets use a dedicated information disclosure stating that the value will not be shown again.

### Cards and sections

Cards follow `{components.card}` and represent one meaningful responsibility. Ordinary page sections may use only a heading and spacing. A danger zone appears last, names the consequence, identifies the affected resource, and requires deliberate confirmation.

### Resource tables

The resource name is the strongest element in each row, with stable secondary metadata directly beneath it when useful. Status combines text with a dot or semantic badge. Column headings use `{components.table-heading}`. Long technical identifiers use monospace, safe truncation, and copy affordances.

One frequent action may remain visible. Rare actions should move into a menu only after that behavior is implemented accessibly. Hover styling must not imply that an entire row is clickable unless it actually is.

### Status and alerts

Badges use the neutral, success, warning, danger, and information component tokens. Success alerts confirm completed operations rather than passive health. Errors remain visible until resolved. Dynamic WebAuthn and connection statuses use polite live-region behavior; high-frequency audit rows do not announce continuously.

### Security hierarchy

Security actions have four levels:

1. **Ordinary:** Save profile or update metadata.
2. **Recoverable:** Reset password, clear MFA, or revoke current sessions.
3. **Compromise response:** Rotate credentials, wipe factors, terminate sessions, and revoke federation access.
4. **Irreversible:** Delete an identity, client, group, integration, account, role, or assignment.

Do not render every consequential operation as an identical red button. Placement, supporting text, confirmation language, and color must explain whether the result is recoverable, disruptive, or permanent.

## Do's and Don'ts

- **Do** make identity, status, risk, and the next safe action obvious before adding visual decoration.
- **Do** keep one primary action per page or bounded task.
- **Do** use warm neutral surfaces, fine outlines, and compact typography to create hierarchy.
- **Do** pair every semantic color with meaningful text.
- **Do** preserve keyboard access, visible focus, native semantics, and WCAG AA contrast.
- **Do** keep technical identifiers selectable, copyable, and visually distinct.
- **Do** state the scope and consequence of every security-sensitive action.
- **Do** keep forms narrow enough to scan and tables wide enough to compare.
- **Don't** add hero cards, vanity metrics, decorative charts, or marketing copy to operational pages.
- **Don't** use gradients, glassmorphism, glows, large ambient shadows, or animated elevation.
- **Don't** use multiple accent colors to decorate unrelated sections.
- **Don't** recolor success, warning, error, or information states to match product branding.
- **Don't** hide security consequences inside an unlabeled overflow menu.
- **Don't** use color-only status, icon-only navigation, or placeholder-only labels.
- **Don't** introduce a frontend framework or build pipeline solely to reproduce this design.
- **Don't** change routes, methods, input names, hidden authorization state, autocomplete, permission checks, or WebAuthn behavior during visual work.
