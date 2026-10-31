'use client';

import { useRouter } from 'next/navigation';
import { useRef, useState, type FormEvent } from 'react';
import { ApiError, api } from '@/lib/api';
import type { Scan } from '@/lib/types';
import { Notice, cx, ui } from '../ui';
import s from './scan.module.css';

const FIELDS = {
  source_root: { label: 'Source directory', help: 'Path to the PHP project on the machine running the API.', type: 'text', required: 'Enter the source directory.' },
  target_origin: { label: 'Test app address', help: 'Only the local test app allowed in the server config, for example http://127.0.0.1:8080.', type: 'url', required: 'Enter the test app address.' },
} as const;
type FieldName = keyof typeof FIELDS;

export function ScanForm({ previous, open = !previous }: { previous: Scan | null; open?: boolean }) {
  const router = useRouter();
  const form = useRef<HTMLFormElement>(null);
  const [errors, setErrors] = useState<Partial<Record<FieldName, string>>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const body = { source_root: String(data.get('source_root') ?? '').trim(), target_origin: String(data.get('target_origin') ?? '').trim() };
    const missing = (Object.keys(FIELDS) as FieldName[]).filter((name) => !body[name]);
    setFormError(null);
    setErrors(Object.fromEntries(missing.map((name) => [name, FIELDS[name].required])));
    if (missing.length) { form.current?.querySelector<HTMLInputElement>(`#${missing[0]}`)?.focus(); return; }

    setBusy(true);
    try {
      const created = await api.startScan(body);
      router.push(`/issues/?scan=${encodeURIComponent(created.scan_id)}`);
    } catch (err) {
      setBusy(false);
      const fieldErrors = err instanceof ApiError ? Object.entries(err.fields).filter((entry): entry is [FieldName, string] => entry[0] in FIELDS) : [];
      if (fieldErrors.length) {
        setErrors(Object.fromEntries(fieldErrors));
        form.current?.querySelector<HTMLInputElement>(`#${fieldErrors[0][0]}`)?.focus();
      } else {
        setFormError((err as Error).message);
      }
    }
  }

  return (
    <details className={cx(ui.disclosure, s.section)} open={open}>
      <summary>New scan</summary>
      <form ref={form} className={s.form} noValidate onSubmit={submit}>
        {(Object.keys(FIELDS) as FieldName[]).map((name) => {
          const f = FIELDS[name];
          return (
            <div key={name} className={ui.field}>
              <label htmlFor={name}>{f.label}</label>
              <input
                id={name} name={name} type={f.type} required autoComplete="off" spellCheck={false}
                className={cx(ui.control, 'mono')} defaultValue={previous?.[name] ?? ''}
                aria-invalid={errors[name] ? true : undefined} aria-describedby={`${name}-help ${name}-error`}
              />
              <p id={`${name}-help`} className="meta">{f.help}</p>
              <p id={`${name}-error`} className={ui.fieldError} hidden={!errors[name]}>{errors[name]}</p>
            </div>
          );
        })}
        <button className={cx(ui.btn, s.submit)} type="submit" disabled={busy}>{busy ? 'Starting scan…' : 'Start scan'}</button>
        {formError && <div className={s.formError}><Notice kind="error">{formError}</Notice></div>}
      </form>
    </details>
  );
}
