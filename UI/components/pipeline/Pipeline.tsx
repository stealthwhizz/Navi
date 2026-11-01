'use client';

import { AnimatePresence, animate, motion, useReducedMotion } from 'motion/react';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { STAGES, stageMetric, stageStates, type StageId, type StageState } from '@/lib/pipeline';
import type { Scan } from '@/lib/types';
import { Icon } from '../Icon';
import s from './pipeline.module.css';

const EASE_OUT = [0.23, 1, 0.32, 1] as const;
const EASE_IN_OUT = [0.77, 0, 0.175, 1] as const;
const EDGES: [StageId, StageId][] = [['sast', 'correlate'], ['dast', 'correlate']];
const MAX_PARTICLES = 5; // per lane; the count shown in the hub is exact, the dots are a visual sample
const converged = new Set<string>(); // scans whose convergence already played in this browser session

type Rect = { left: number; top: number; right: number; bottom: number; width: number; height: number };

// Cubic curve between two nodes, leaving from the side that faces the target.
function edgePath(a: Rect, b: Rect, root: Rect): string {
  const ax = a.left + a.width / 2 - root.left, ay = a.top + a.height / 2 - root.top;
  const bx = b.left + b.width / 2 - root.left, by = b.top + b.height / 2 - root.top;
  if (Math.abs(bx - ax) >= Math.abs(by - ay)) {
    const x1 = a.right - root.left, x2 = b.left - root.left, c = (x2 - x1) / 2;
    return `M${x1} ${ay} C${x1 + c} ${ay} ${x2 - c} ${by} ${x2} ${by}`;
  }
  const y1 = a.bottom - root.top, y2 = b.top - root.top, c = (y2 - y1) / 2;
  return `M${ax} ${y1} C${ax} ${y1 + c} ${bx} ${y2 - c} ${bx} ${y2}`;
}

function StatusIcon({ state }: { state: StageState }) {
  // Icon swaps cross-fade (opacity, 0.25 scale, 4px blur) so a finished stage reads as a change, not a flicker.
  return (
    <span className={s.status} aria-hidden="true">
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={state}
          initial={{ opacity: 0, transform: 'scale(0.25)', filter: 'blur(4px)' }}
          animate={{ opacity: 1, transform: 'scale(1)', filter: 'blur(0px)' }}
          exit={{ opacity: 0, transform: 'scale(0.25)', filter: 'blur(4px)' }}
          transition={{ type: 'spring', duration: 0.3, bounce: 0 }}
          style={{ display: 'grid', placeItems: 'center' }}
        >
          {state === 'done' ? <Icon name="check" /> : state === 'failed' ? <Icon name="x" /> : state === 'active' ? <span className={s.dot} /> : null}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

const STATE_WORD: Record<StageState, string> = { waiting: 'waiting', active: 'running', done: 'done', failed: 'failed' };

export function Pipeline({ scan }: { scan: Scan }) {
  const reduce = useReducedMotion();
  const states = stageStates(scan);
  const root = useRef<HTMLDivElement>(null);
  const nodeEls = useRef<Partial<Record<StageId, HTMLElement | null>>>({});
  const pathEls = useRef<Record<string, SVGPathElement | null>>({});
  const dots = useRef<(SVGCircleElement | null)[]>([]);
  const [paths, setPaths] = useState<Record<string, string>>({});
  const [merged, setMerged] = useState(0); // bumps when findings arrive at the hub, to fire the ripple once

  const n = scan.counts;
  const completed = scan.state === 'completed';
  const proven = completed && n.confirmed > 0;
  const lanes = { sast: Math.min(n.confirmed + n.code_only, MAX_PARTICLES), dast: Math.min(n.confirmed + n.runtime_only, MAX_PARTICLES) };

  // Wires follow the real node boxes, so they stay attached through resizes, font loading, and the mobile layout.
  useLayoutEffect(() => {
    const el = root.current;
    if (!el) return;
    const measure = () => {
      const box = el.getBoundingClientRect();
      const next: Record<string, string> = {};
      for (const [a, b] of EDGES) {
        const ra = nodeEls.current[a]?.getBoundingClientRect();
        const rb = nodeEls.current[b]?.getBoundingClientRect();
        if (ra && rb) next[`${a}-${b}`] = edgePath(ra, rb, box);
      }
      setPaths((current) => {
        if (Object.keys(next).length === Object.keys(current).length &&
          Object.keys(next).every((key) => next[key] === current[key])) return current;
        return next;
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    Object.values(nodeEls.current).forEach((node) => node && observer.observe(node));
    return () => observer.disconnect();
  }, []);

  // Convergence: once per scan per session, real finding counts travel from each scanner lane into correlation.
  useEffect(() => {
    if (!completed || converged.has(scan.id) || !paths['sast-correlate'] || lanes.sast + lanes.dast === 0) return;
    converged.add(scan.id);
    if (reduce) { setMerged((m) => m + 1); return; }
    const runs = [...Array(lanes.sast).fill('sast-correlate'), ...Array(lanes.dast).fill('dast-correlate')].map((key: string, i) => {
      const path = pathEls.current[key];
      const dot = dots.current[i];
      if (!path || !dot) return null;
      const length = path.getTotalLength();
      return animate(0, 1, {
        duration: 0.9, delay: 0.15 + (i % MAX_PARTICLES) * 0.12, ease: EASE_IN_OUT,
        onUpdate: (v) => {
          const p = path.getPointAtLength(v * length);
          dot.setAttribute('cx', String(p.x));
          dot.setAttribute('cy', String(p.y));
          dot.style.opacity = v < 0.08 ? String(v / 0.08) : v > 0.92 ? String((1 - v) / 0.08) : '1';
        },
      });
    }).filter((run) => run !== null);
    Promise.all(runs.map((run) => run.finished)).then(() => setMerged((m) => m + 1));
    return () => runs.forEach((run) => run.stop());
  }, [completed, scan.id, paths, lanes.sast, lanes.dast, reduce]);

  const edgeState = (a: StageId, b: StageId) =>
    states[a] === 'done' && states[b] === 'active' ? 'flow' : states[a] === 'done' && (states[b] === 'done' || states[b] === 'failed') ? 'lit' : 'idle';

  return (
    <div ref={root} className={s.root}>
      <svg className={s.wires} aria-hidden="true">
        {EDGES.map(([a, b], i) => {
          const key = `${a}-${b}`;
          const d = paths[key];
          if (!d) return null;
          const state = edgeState(a, b);
          const proof = proven && b === 'correlate';
          return (
            <g key={key}>
              <path ref={(el) => { pathEls.current[key] = el; }} className={s.wire} d={d} />
              <motion.path
                className={[s.wireLit, proof && s.wireProven, states[b] === 'failed' && s.wireFailed].filter(Boolean).join(' ')}
                d={d}
                initial={false}
                animate={{ pathLength: state === 'idle' ? 0 : 1, opacity: state === 'idle' ? 0 : 1 }}
                transition={{ duration: reduce ? 0 : 0.45, ease: EASE_OUT, delay: reduce ? 0 : i * 0.06 }}
              />
              {state === 'flow' && <path className={s.wireFlow} d={d} />}
            </g>
          );
        })}
        {[...Array(lanes.sast + lanes.dast)].map((_, i) => <circle key={i} ref={(el) => { dots.current[i] = el; }} className={s.particle} r={3.5} cx={0} cy={0} />)}
      </svg>

      <ol className={s.stages} aria-label="Scan pipeline">
        {STAGES.map((stage) => {
          const state = states[stage.id];
          if (stage.id === 'correlate') {
            return (
              <li key={stage.id} className={`${s.correlate} ${s.hub}`} data-state={state} data-proven={proven}>
                <div ref={(el) => { nodeEls.current.correlate = el; }} className={s.orb}>
                  {state === 'active' && <span className={s.orbit} aria-hidden="true" />}
                  <AnimatePresence>
                    {proven && merged > 0 && (
                      <motion.span
                        key={merged}
                        className={s.ripple}
                        aria-hidden="true"
                        initial={{ opacity: 0.8, transform: 'scale(1)' }}
                        animate={{ opacity: 0, transform: reduce ? 'scale(1)' : 'scale(1.45)' }}
                        transition={{ duration: 0.7, ease: EASE_OUT }}
                      />
                    )}
                  </AnimatePresence>
                  <strong>{completed ? n.confirmed : state === 'failed' ? '!' : '…'}</strong>
                  <span>{completed ? 'Confirmed' : state === 'active' ? 'Correlating' : state === 'failed' ? 'Stopped' : 'Waiting'}</span>
                </div>
                <span className={s.hubLabel}>{stage.label}<span className="sr-only">, {STATE_WORD[state]}</span></span>
                <span className={s.metric}>{stageMetric(scan, stage.id, state)}</span>
              </li>
            );
          }
          return (
            <li key={stage.id} ref={(el) => { nodeEls.current[stage.id] = el; }} className={`${s[stage.id]} ${s.node}`} data-state={state} title={stage.detail}>
              <span className={s.head}><StatusIcon state={state} /><span>{stage.label}<span className="sr-only">, {STATE_WORD[state]}</span></span></span>
              <span className={s.metric}>{stageMetric(scan, stage.id, state)}</span>
              {(stage.id === 'sast' || stage.id === 'dast') && <span className={s.lane}>{stage.id.toUpperCase()}</span>}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
