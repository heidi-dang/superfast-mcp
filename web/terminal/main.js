/**
 * superfast-mcp Terminal UI
 *
 * Follow-tail (tail -f) behavior:
 * Before appending new output, measure whether the user is already near the
 * bottom (within FOLLOW_THRESHOLD_PX). If yes, pin scrollTop to scrollHeight
 * after the append so the viewport tracks the newest lines automatically.
 * If the user has scrolled up to read history, do not force-scroll — preserve
 * their position until they return near the bottom.
 *
 * Same pattern as chatgpt-terminal-plugin packages/terminal-ui (flushOutput).
 */

const FOLLOW_THRESHOLD_PX = 24;
const MAX_OUTPUT_CHARS = 600_000;
const OUTPUT_TRIM_TARGET = 450_000;
const MOBILE_MAX_OUTPUT_CHARS = 220_000;
const MOBILE_OUTPUT_TRIM_TARGET = 160_000;

const TERM_RE =
  /(^.*?[$#>]\s)([\w./:+-]+)?|(^\s*(?:\/\/|#\s)[^\n]*)|\b(ERROR|FAIL|FATAL|EXCEPTION)\b|\b(WARN(?:ING)?)\b|\b(PASS|SUCCESS|DONE|OK)\b|("[^"\n]*"|'[^'\n]*')|(--?[\w-]+)|((?:~|\.{1,2})?\/[^\s"';|&]+)|(\b\d+(?:\.\d+)?\b)|\b(const|let|var|function|class|if|else|for|while|return|import|from|export|async|await|new|true|false|null|undefined)\b/gim;
const TERM_KIND = [
  '',
  'prompt',
  'command',
  'comment',
  'error',
  'warning',
  'success',
  'string',
  'option',
  'path',
  'number',
  'keyword',
];

function normalizeTerminalText(input) {
  let output = '';
  let index = 0;
  while (index < input.length) {
    const code = input.charCodeAt(index);
    if (code === 0x1b) {
      const next = input[index + 1];
      if (next === '[') {
        index += 2;
        while (index < input.length) {
          const control = input.charCodeAt(index++);
          if (control >= 0x40 && control <= 0x7e) break;
        }
        continue;
      }
      if (next === ']') {
        index += 2;
        while (index < input.length) {
          const control = input.charCodeAt(index);
          if (control === 0x07) {
            index += 1;
            break;
          }
          if (control === 0x1b && input[index + 1] === '\\') {
            index += 2;
            break;
          }
          index += 1;
        }
        continue;
      }
      index += Math.min(2, input.length - index);
      continue;
    }
    if (code === 0x08) {
      output = output.slice(0, -1);
      index += 1;
      continue;
    }
    if (code === 0x0d) {
      if (input.charCodeAt(index + 1) === 0x0a) index += 1;
      output += '\n';
      index += 1;
      continue;
    }
    if (code < 0x20 && code !== 0x09 && code !== 0x0a) {
      index += 1;
      continue;
    }
    output += input[index] ?? '';
    index += 1;
  }
  return output;
}

function highlightTerminalText(doc, input) {
  const text = normalizeTerminalText(input);
  const out = doc.createDocumentFragment();
  let end = 0;
  const add = (value, kind) => {
    const span = doc.createElement('span');
    span.className = `term-${TERM_KIND[kind]}`;
    span.textContent = value;
    out.appendChild(span);
  };
  TERM_RE.lastIndex = 0;
  for (const match of text.matchAll(TERM_RE)) {
    const at = match.index ?? 0;
    if (at > end) out.append(text.slice(end, at));
    if (match[1]) {
      add(match[1], 1);
      if (match[2]) add(match[2], 2);
    } else {
      add(match[0], match.slice(1).findIndex(Boolean) + 1);
    }
    end = at + match[0].length;
  }
  if (end < text.length) out.append(text.slice(end));
  return out;
}

function appendRichTerminalText(container, input) {
  const doc = container.ownerDocument;
  const frag = highlightTerminalText(doc, input);
  const renderedChars = (frag.textContent ?? input).length;
  container.appendChild(frag);
  return renderedChars;
}

/**
 * Returns true when the viewport is already pinned near the bottom
 * (within FOLLOW_THRESHOLD_PX of the end). Used to decide whether to
 * auto-scroll after appending new live output — same contract as tail -f.
 */
function isFollowingTail(el, thresholdPx = FOLLOW_THRESHOLD_PX) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < thresholdPx;
}

/** Pin viewport to the newest output (tail -f). */
function followTail(el) {
  el.scrollTop = el.scrollHeight;
}

class TerminalView {
  constructor(doc) {
    this.doc = doc;
    this.shell = doc.getElementById('shell');
    this.output = doc.getElementById('output');
    this.machine = doc.getElementById('machine');
    this.status = doc.getElementById('status');
    this.path = doc.getElementById('path');
    this.footerShell = doc.getElementById('footer-shell');
    this.outputQueue = '';
    this.outputFrame = undefined;
    this.renderedChars = 0;
    this.hasLiveOutput = false;
    this.streamState = 'connecting';
    this.userPinned = false; // true when user scrolled away from bottom

    this.output.addEventListener(
      'scroll',
      () => {
        // If user scrolls up, pause follow-tail until they return near bottom.
        this.userPinned = !isFollowingTail(this.output);
      },
      { passive: true },
    );
  }

  setState(state) {
    this.streamState = state;
    this.shell.dataset.state = state;
    this.status.dataset.state = state;
    const label = this.status.lastElementChild;
    if (label) label.textContent = state.toUpperCase();
  }

  setMeta({ machine, cwd, shell } = {}) {
    if (machine) this.machine.textContent = machine;
    if (cwd !== undefined) {
      this.path.textContent = cwd || 'Waiting for terminal session…';
      this.path.title = cwd || '';
    }
    if (shell) this.footerShell.textContent = shell;
  }

  /** Queue text for rAF-batched append + follow-tail. */
  enqueue(text) {
    if (!text) return;
    this.outputQueue += text;
    this.scheduleFlush();
  }

  scheduleFlush() {
    if (this.outputFrame !== undefined) return;
    this.outputFrame = window.requestAnimationFrame(() => {
      this.outputFrame = undefined;
      this.flushOutput();
    });
  }

  /**
   * Core follow-tail path (mirrors chatgpt-terminal-plugin flushOutput):
   * 1. Measure stickiness BEFORE mutating the DOM.
   * 2. Append new rich text.
   * 3. Trim if over budget.
   * 4. If was following (and user has not pinned), scroll to bottom.
   */
  flushOutput() {
    if (this.outputFrame !== undefined) {
      window.cancelAnimationFrame(this.outputFrame);
      this.outputFrame = undefined;
    }
    if (!this.outputQueue) return;

    const output = this.output;
    if (!this.hasLiveOutput) {
      output.textContent = '';
      this.renderedChars = 0;
      this.hasLiveOutput = true;
    }

    // Decide follow-tail BEFORE append so the measurement is stable.
    const follow = !this.userPinned && isFollowingTail(output);

    this.renderedChars += appendRichTerminalText(output, this.outputQueue);
    this.outputQueue = '';
    this.trimOutput();

    if (follow) followTail(output);
  }

  trimOutput() {
    const narrow =
      this.doc.defaultView?.matchMedia?.('(max-width: 560px)').matches ?? false;
    const maxChars = narrow ? MOBILE_MAX_OUTPUT_CHARS : MAX_OUTPUT_CHARS;
    if (this.renderedChars <= maxChars) return;

    const text = this.output.textContent ?? '';
    const trimTarget = narrow ? MOBILE_OUTPUT_TRIM_TARGET : OUTPUT_TRIM_TARGET;
    let tail = text.slice(-trimTarget);
    const newline = tail.indexOf('\n');
    if (newline >= 0) tail = tail.slice(newline + 1);

    const follow = !this.userPinned && isFollowingTail(this.output);
    this.output.textContent = '';
    this.renderedChars = appendRichTerminalText(
      this.output,
      `[Older terminal output trimmed]\n${tail}`,
    );
    if (follow) followTail(this.output);
  }
}

// --- Demo / host wiring ----------------------------------------------------
// Until Phase 2 SSE is wired, accept postMessage { type: 'terminal_output', text }
// and optional { type: 'terminal_meta', ... } so local preview works.

const view = new TerminalView(document);
view.setState('live');
view.setMeta({ machine: 'superfast-mcp', cwd: '~', shell: 'bash' });

window.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;
  if (data.type === 'terminal_output' && typeof data.text === 'string') {
    view.enqueue(data.text);
  }
  if (data.type === 'terminal_meta') {
    view.setMeta(data);
  }
  if (data.type === 'terminal_state' && typeof data.state === 'string') {
    view.setState(data.state);
  }
});

// Local self-test: stream a few lines if ?demo=1
if (new URLSearchParams(location.search).has('demo')) {
  const lines = [
    '$ go build -o superfast-mcp ./cmd/superfast-mcp\n',
    'superfast-mcp: listening on :8787\n',
    '$ git status --porcelain -b\n',
    '## main...origin/main\n',
    ' M web/terminal/main.js\n',
    '$ ./superfast-mcp --http :8787 --roots .\n',
    'superfast-mcp 0.1.0 listening on :8787  (public http://localhost:8787/mcp)\n',
  ];
  let i = 0;
  const tick = () => {
    if (i >= lines.length) return;
    view.enqueue(lines[i++]);
    setTimeout(tick, 280);
  };
  tick();
}

export { TerminalView, isFollowingTail, followTail, FOLLOW_THRESHOLD_PX };
