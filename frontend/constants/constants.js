export const C = {
  bg:       "#0b0e13",
  surface:  "#111620",
  surface2: "#181e2a",
  border:   "#1d2535",
  amber:    "#f5a623",
  amberDim: "#7a5210",
  green:    "#4ade80",
  red:      "#f87171",
  blue:     "#60a5fa",
  muted:    "#4a5a6e",
  text:     "#c8d6e8",
};

export const STAGE_ICONS = {
  pending:  "○",
  running:  "◉",
  complete: "✓",
  waiting:  "◈",
  error:    "✗",
};

export const STAGE_COLORS = {
  pending:  C.muted,
  running:  C.amber,
  complete: C.green,
  waiting:  C.blue,
  error:    C.red,
};

export const EVENT_COLORS = {
  node_completed:    C.green,
  hitl_pause:        C.blue,
  pipeline_complete: C.amber,
  error:             C.red,
  ping:              C.muted,
};