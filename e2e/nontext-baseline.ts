/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, and that is a measured statement, not a hope: the full drive —
 * both themes, both viewports, every state including hover and focus — reports
 * zero non-text findings after the fixes that landed with this gate (the
 * primary buttons' missing dark-theme boundary, and the focused inputs whose
 * `outline-none` + crimson focus border left them at 2.09:1). The shared top
 * bar's ghost buttons, baselined at ~1.49:1 across much of the fleet, were
 * already fixed in this repo one commit earlier by mixing the border from
 * `--cl-ink` instead of `--accent`.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
