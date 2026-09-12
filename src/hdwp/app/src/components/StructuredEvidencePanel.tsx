import React, { useState } from 'react'

const SENSITIVE_FIELDS = new Set(['password', 'token', 'api_key', 'secret', 'access_token',
  'refresh_token', 'private_key', 'ssn', 'credit_card'])

const S: Record<string, React.CSSProperties> = {
  section:   { marginBottom: 8 },
  label:     { fontSize: 8, color: '#2a4a2a', letterSpacing: 1, marginBottom: 3 },
  mono:      { fontFamily: 'var(--font-mono)', fontSize: 9 },
  badge:     { display: 'inline-block', padding: '1px 6px', marginRight: 4, marginBottom: 2,
               border: '1px solid currentColor', fontSize: 8, letterSpacing: 1 },
  table:     { width: '100%', borderCollapse: 'collapse', fontSize: 9 },
  td:        { padding: '2px 6px', borderBottom: '1px solid #111', verticalAlign: 'top' },
  tdKey:     { padding: '2px 6px', borderBottom: '1px solid #111', color: '#445566', width: '40%' },
  row:       { display: 'flex', gap: 8, marginBottom: 3, alignItems: 'baseline' },
  key:       { color: '#445566', fontSize: 9, minWidth: 80 },
  val:       { fontFamily: 'var(--font-mono)', fontSize: 9, color: '#00ff88', wordBreak: 'break-all' },
  warn:      { padding: '4px 8px', border: '1px solid #ff0066', color: '#ff0066', fontSize: 9,
               background: '#ff006611', marginBottom: 4 },
  info:      { padding: '4px 8px', border: '1px solid #ffaa00', color: '#ffaa00', fontSize: 9,
               background: '#ffaa0011', marginBottom: 4 },
  collapse:  { cursor: 'pointer', fontSize: 8, color: '#2a4a2a', letterSpacing: 1, marginBottom: 3,
               background: 'none', border: 'none', padding: 0 },
}

// ── Atoms ─────────────────────────────────────────────────────────────────────

function Badge({ text, color = '#00ff88' }: { text: string; color?: string }) {
  return <span style={{ ...S.badge, color }}>{text}</span>
}

function KV({ k, v, highlight = false }: { k: string; v: string; highlight?: boolean }) {
  return (
    <div style={S.row}>
      <span style={S.key}>{k}</span>
      <span style={{ ...S.val, color: highlight ? '#ff4400' : '#00ff88' }}>{v}</span>
    </div>
  )
}

function SectionLabel({ text }: { text: string }) {
  return <div style={S.label}>{text}</div>
}

function CollapsibleRaw({ text }: { text: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div style={S.section}>
      <button style={S.collapse} onClick={() => setOpen(o => !o)}>
        {open ? '▾ RAW OUTPUT' : '▸ RAW OUTPUT'}
      </button>
      {open && (
        <pre style={{
          margin: 0, padding: '6px 8px', background: '#060606',
          border: '1px solid #111', fontSize: 8, color: '#334433',
          fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap',
          wordBreak: 'break-all', maxHeight: 120, overflowY: 'auto',
        }}>
          {text}
        </pre>
      )}
    </div>
  )
}

// ── Blocs spécialisés ─────────────────────────────────────────────────────────

function RootBadge() {
  return (
    <div style={{ ...S.warn, borderColor: '#ff0066', color: '#ff0066', background: '#ff006622' }}>
      ⚠ EXÉCUTION EN TANT QUE ROOT
    </div>
  )
}

function UserInfo({ e }: { e: Record<string, any> }) {
  return (
    <div style={S.section}>
      <SectionLabel text="── IDENTITÉ ──" />
      {e.user    && <KV k="user"  v={String(e.user)}  highlight={e.user === 'root'} />}
      {e.uid     && <KV k="uid"   v={String(e.uid)}   highlight={e.uid === '0'} />}
      {e.primary_group && <KV k="group" v={String(e.primary_group)} />}
      {e.hostname && <KV k="host" v={String(e.hostname)} />}
      {Array.isArray(e.groups) && e.groups.length > 0 && (
        <div style={S.row}>
          <span style={S.key}>groups</span>
          <span>{(e.groups as string[]).map(g =>
            <Badge key={g} text={g} color={g === 'root' || g === 'sudo' ? '#ff4400' : '#445566'} />
          )}</span>
        </div>
      )}
    </div>
  )
}

function PasswdTable({ entries }: { entries: Array<Record<string, string>> }) {
  return (
    <div style={S.section}>
      <SectionLabel text="── /ETC/PASSWD ──" />
      <table style={S.table}>
        <thead>
          <tr>
            {['user', 'uid', 'home', 'shell'].map(h => (
              <td key={h} style={{ ...S.tdKey, fontSize: 8, color: '#2a4a2a' }}>{h}</td>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((row, i) => (
            <tr key={i}>
              <td style={{ ...S.td, color: row.user === 'root' ? '#ff4400' : '#00ff88' }}>{row.user}</td>
              <td style={{ ...S.td, color: '#445566' }}>{row.uid}</td>
              <td style={{ ...S.td, color: '#445566' }}>{row.home}</td>
              <td style={{ ...S.td, color: '#445566', fontSize: 8 }}>{row.shell}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ExposedFields({ fields }: { fields: Record<string, string> }) {
  return (
    <div style={S.section}>
      <SectionLabel text="── CHAMPS EXPOSÉS ──" />
      <table style={S.table}>
        <tbody>
          {Object.entries(fields).map(([k, v]) => (
            <tr key={k}>
              <td style={{ ...S.tdKey }}>{k}</td>
              <td style={{
                ...S.td,
                color: SENSITIVE_FIELDS.has(k) ? '#ff4400' : '#00ff88',
                fontFamily: 'var(--font-mono)',
                wordBreak: 'break-all',
              }}>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EnvVars({ vars, label }: { vars: Record<string, string>; label: string }) {
  return (
    <div style={S.section}>
      <SectionLabel text={label} />
      <table style={S.table}>
        <tbody>
          {Object.entries(vars).map(([k, v]) => (
            <tr key={k}>
              <td style={{ ...S.tdKey, color: '#ff4400' }}>{k}</td>
              <td style={{ ...S.td, color: '#ff8800', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', fontSize: 8 }}>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SqlInfo({ e }: { e: Record<string, any> }) {
  return (
    <div style={S.section}>
      <SectionLabel text="── BASE DE DONNÉES ──" />
      {e.db_type    && <KV k="type"    v={String(e.db_type)} />}
      {e.db_version && <KV k="version" v={String(e.db_version)} />}
      {e.db_user    && <KV k="user"    v={String(e.db_user)} highlight />}
      {e.database   && <KV k="database" v={String(e.database)} highlight />}
      {Array.isArray(e.extracted_values) && e.extracted_values.length > 0 && (
        <div style={S.section}>
          <SectionLabel text="── VALEURS EXTRAITES ──" />
          {(e.extracted_values as string[]).map((v, i) =>
            <div key={i} style={{ ...S.mono, color: '#ff4400', marginBottom: 2 }}>{v}</div>
          )}
        </div>
      )}
      {Array.isArray(e.interesting_tables) && e.interesting_tables.length > 0 && (
        <div style={{ marginTop: 4 }}>
          <SectionLabel text="── TABLES SENSIBLES ──" />
          {(e.interesting_tables as string[]).map(t =>
            <Badge key={t} text={t} color="#ff4400" />
          )}
        </div>
      )}
    </div>
  )
}

function ConfirmedFlags({ flags }: { flags: string[] }) {
  return (
    <div style={S.section}>
      <SectionLabel text="── FLAGS CONFIRMÉS ──" />
      {flags.map(f => <Badge key={f} text={f} color="#00ff88" />)}
    </div>
  )
}

function CloudMetadata({ e }: { e: Record<string, any> }) {
  return (
    <div style={{ ...S.warn, borderColor: '#ffaa00', color: '#ffaa00', background: '#ffaa0011' }}>
      ☁ CLOUD METADATA EXPOSÉ
      {e.instance_id && <div style={{ marginTop: 2 }}><KV k="instance" v={String(e.instance_id)} /></div>}
      {e.ami_id && <KV k="ami" v={String(e.ami_id)} />}
      {e.aws_access_key && <KV k="access_key" v={String(e.aws_access_key)} highlight />}
    </div>
  )
}

function PrivateKeys({ types }: { types: string[] }) {
  return (
    <div style={{ ...S.warn }}>
      🔑 CLÉ PRIVÉE DÉTECTÉE : {types.join(', ')}
    </div>
  )
}

function TokenField({ token }: { token: string }) {
  const [copied, setCopied] = useState(false)
  const display = token.length > 40 ? token.slice(0, 40) + '…' : token
  return (
    <div style={S.section}>
      <SectionLabel text="── TOKEN OBTENU ──" />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ ...S.mono, color: '#ffaa00', wordBreak: 'break-all', flex: 1 }}>{display}</span>
        <button
          onClick={() => navigator.clipboard.writeText(token).then(() => {
            setCopied(true); setTimeout(() => setCopied(false), 1500)
          }).catch(() => {})}
          style={{ ...S.badge, cursor: 'pointer', background: 'none', color: copied ? '#00ff88' : '#2a4a2a' }}
        >{copied ? '✓' : 'COPY'}</button>
      </div>
    </div>
  )
}

// ── Composant principal ───────────────────────────────────────────────────────

interface Props {
  evidence: Record<string, any> | null
  status: string
}

export default function StructuredEvidencePanel({ evidence, status }: Props) {
  if (!evidence || status === 'not_implemented') return null

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e = evidence as Record<string, any>
  const rendered: React.ReactNode[] = []
  const handled = new Set<string>()

  // ROOT
  if (e.is_root === true) { rendered.push(<RootBadge key="root" />); handled.add('is_root') }

  // Identité shell (cmdi, ssti RCE, el_injection, deserialization, file_upload)
  if (e.user || e.uid || e.hostname || e.groups) {
    rendered.push(<UserInfo key="user" e={e} />)
    ;['user', 'uid', 'gid', 'primary_group', 'hostname', 'groups'].forEach(k => handled.add(k))
  }

  // RCE confirmé
  if (e.rce_confirmed || e.webshell_executed) {
    rendered.push(
      <div key="rce" style={{ ...S.info, borderColor: '#ff0066', color: '#ff0066', background: '#ff006611' }}>
        ⚡ {e.rce_confirmed ? 'RCE CONFIRMÉE' : 'WEBSHELL EXÉCUTÉ'}
        {e.rce_output && <div style={{ ...S.mono, marginTop: 2 }}>{String(e.rce_output)}</div>}
        {e.command_output && <div style={{ ...S.mono, marginTop: 2 }}>{String(e.command_output)}</div>}
        {e.upload_url && <div style={{ marginTop: 2 }}><KV k="url" v={String(e.upload_url)} highlight /></div>}
      </div>
    )
    ;['rce_confirmed', 'rce_output', 'webshell_executed', 'webshell_uploaded', 'command_output', 'upload_url'].forEach(k => handled.add(k))
  }

  // Template / EL évaluation
  if (e.template_confirmed || e.el_evaluated) {
    rendered.push(
      <div key="tmpl" style={S.info}>
        ✓ ÉVALUATION D'EXPRESSION CONFIRMÉE
        {e.evaluation_result && <div style={{ ...S.mono, marginTop: 2 }}>{String(e.evaluation_result)}</div>}
        {e.template_engine && <KV k="moteur" v={String(e.template_engine)} />}
        {e.java_class && <KV k="classe" v={String(e.java_class)} />}
      </div>
    )
    ;['template_confirmed', 'el_evaluated', 'evaluation_result', 'template_engine', 'java_class', 'rce_confirmed'].forEach(k => handled.add(k))
  }

  // Bypass auth
  if (e.bypass_successful === true) {
    rendered.push(
      <div key="bypass" style={{ ...S.info, borderColor: '#00ff88', color: '#00ff88', background: '#00ff8811' }}>
        ✓ BYPASS D'AUTHENTIFICATION RÉUSSI
        {e.authenticated_as && <KV k="as" v={String(e.authenticated_as)} highlight />}
      </div>
    )
    ;['bypass_successful', 'authenticated_as', 'first_record_user'].forEach(k => handled.add(k))
  }

  // Token obtenu
  if (typeof e.obtained_token === 'string') {
    rendered.push(<TokenField key="token" token={e.obtained_token} />)
    handled.add('obtained_token')
  }

  // JWT claims
  if (e.claims && typeof e.claims === 'object') {
    rendered.push(
      <div key="claims" style={S.section}>
        <SectionLabel text="── CLAIMS JWT ──" />
        {Object.entries(e.claims as Record<string, string>).map(([k, v]) =>
          <KV key={k} k={k} v={String(v)} highlight={k === 'role' || k === 'admin'} />
        )}
        {e.privilege_escalation && <Badge text="ESCALADE DE PRIVILÈGES" color="#ff0066" />}
      </div>
    )
    ;['claims', 'privilege_escalation', 'auth_bypass'].forEach(k => handled.add(k))
  }

  // /etc/passwd
  if (Array.isArray(e.passwd_entries) && e.passwd_entries.length > 0) {
    rendered.push(<PasswdTable key="passwd" entries={e.passwd_entries as Array<Record<string, string>>} />)
    ;['passwd_entries', 'users_with_shell', 'file_read'].forEach(k => handled.add(k))
  }
  if (Array.isArray(e.users_with_shell) && !handled.has('users_with_shell')) {
    rendered.push(
      <div key="shellus" style={S.section}>
        <SectionLabel text="── USERS AVEC SHELL ──" />
        {(e.users_with_shell as string[]).map(u =>
          <Badge key={u} text={u} color={u === 'root' ? '#ff0066' : '#ffaa00'} />
        )}
      </div>
    )
    handled.add('users_with_shell')
  }

  // Variables d'environnement sensibles
  if (e.sensitive_env_vars && typeof e.sensitive_env_vars === 'object') {
    rendered.push(<EnvVars key="senv" vars={e.sensitive_env_vars as Record<string, string>} label="── ENV SECRETS ──" />)
    handled.add('sensitive_env_vars')
  }
  if (e.env_vars && typeof e.env_vars === 'object' && !handled.has('env_vars')) {
    const keys = Object.keys(e.env_vars as object)
    if (keys.length > 0) {
      rendered.push(<EnvVars key="env" vars={e.env_vars as Record<string, string>} label="── ENV VARS ──" />)
    }
    handled.add('env_vars')
  }

  // Clés privées
  if (Array.isArray(e.private_keys_found)) {
    rendered.push(<PrivateKeys key="privkey" types={e.private_keys_found as string[]} />)
    handled.add('private_keys_found')
  }

  // Champs exposés BOLA/IDOR
  if (e.exposed_fields && typeof e.exposed_fields === 'object') {
    rendered.push(<ExposedFields key="expf" fields={e.exposed_fields as Record<string, string>} />)
    ;['exposed_fields', 'object_id', 'accessible_objects_found'].forEach(k => handled.add(k))
  }

  // Info DB SQLi
  if (e.db_type || e.db_user || e.database || e.interesting_tables || e.extracted_values) {
    rendered.push(<SqlInfo key="sql" e={e} />)
    ;['db_type', 'db_version', 'db_user', 'database', 'interesting_tables', 'extracted_values'].forEach(k => handled.add(k))
  }

  // Cloud metadata SSRF
  if (e.cloud_metadata_exposed) {
    rendered.push(<CloudMetadata key="cloud" e={e} />)
    ;['cloud_metadata_exposed', 'instance_id', 'ami_id', 'aws_access_key'].forEach(k => handled.add(k))
  }
  if (Array.isArray(e.internal_ips_exposed)) {
    rendered.push(
      <div key="ips" style={S.section}>
        <SectionLabel text="── IPs INTERNES EXPOSÉES ──" />
        {(e.internal_ips_exposed as string[]).map(ip => <Badge key={ip} text={ip} color="#ffaa00" />)}
      </div>
    )
    handled.add('internal_ips_exposed')
  }

  // Headers absents (passive findings)
  if (Array.isArray(e.headers_absent) && (e.headers_absent as string[]).length > 0) {
    rendered.push(
      <div key="hdrabsent" style={S.section}>
        <SectionLabel text="── HEADERS DE SÉCURITÉ ABSENTS ──" />
        {(e.headers_absent as string[]).map(h =>
          <Badge key={h} text={h} color="#ff4400" />
        )}
      </div>
    )
    handled.add('headers_absent')
  }
  if (e.security_headers_found && typeof e.security_headers_found === 'object') {
    const hdrs = e.security_headers_found as Record<string, string>
    if (Object.keys(hdrs).length > 0) {
      rendered.push(
        <div key="hdrpresent" style={S.section}>
          <SectionLabel text="── HEADERS PRÉSENTS ──" />
          {Object.entries(hdrs).map(([k, v]) =>
            <KV key={k} k={k} v={String(v).slice(0, 80)} />
          )}
        </div>
      )
    }
    handled.add('security_headers_found')
  }

  // Flags booléens confirmés
  if (Array.isArray(e.confirmed_flags) && (e.confirmed_flags as string[]).length > 0) {
    rendered.push(<ConfirmedFlags key="flags" flags={e.confirmed_flags as string[]} />)
    handled.add('confirmed_flags')
  }

  // GraphQL schema
  if (e.schema_leaked) {
    rendered.push(
      <div key="gql" style={S.info}>
        ⚠ SCHÉMA GRAPHQL EXPOSÉ
        {Array.isArray(e.sensitive_fields) && (e.sensitive_fields as string[]).length > 0 && (
          <div style={{ marginTop: 4 }}>
            <SectionLabel text="Types sensibles :" />
            {(e.sensitive_fields as string[]).map(t => <Badge key={t} text={t} color="#ff4400" />)}
          </div>
        )}
      </div>
    )
    ;['schema_leaked', 'schema_types', 'sensitive_fields'].forEach(k => handled.add(k))
  }

  // XSS reflection
  if (e.payload_reflected) {
    rendered.push(
      <div key="xss" style={S.info}>
        ✓ PAYLOAD XSS RÉFLÉCHI DANS LA RÉPONSE
        {e.cookie_exposure && <div style={{ ...S.mono, color: '#ff4400', marginTop: 2 }}>Cookie: {String(e.cookie_exposure)}</div>}
      </div>
    )
    ;['payload_reflected', 'cookie_exposure', 'waf_blocked'].forEach(k => handled.add(k))
  }

  // Redirect
  if (e.redirect_target) {
    rendered.push(
      <div key="redir" style={S.info}>
        → REDIRECTION EXTERNE : {String(e.redirect_target)}
        {e.bypass_technique && <div style={{ ...S.mono, fontSize: 8, marginTop: 2 }}>bypass: {String(e.bypass_technique)}</div>}
      </div>
    )
    ;['redirect_target', 'external_redirect', 'bypass_technique'].forEach(k => handled.add(k))
  }

  // Gadget désérialisation
  if (e.gadget_triggered) {
    rendered.push(
      <div key="deser" style={{ ...S.warn }}>
        ⚡ GADGET CHAIN DÉCLENCHÉ
        {e.stack_trace_snippet && <div style={{ ...S.mono, fontSize: 8, marginTop: 2, color: '#ff8800' }}>{String(e.stack_trace_snippet)}</div>}
        {e.gadget_library && <KV k="lib" v={String(e.gadget_library)} />}
      </div>
    )
    ;['gadget_triggered', 'stack_trace_snippet', 'gadget_library', 'language'].forEach(k => handled.add(k))
  }

  // Champs restants non gérés → JSON fallback
  const remaining: Record<string, any> = {}
  for (const [k, v] of Object.entries(e)) {
    if (!handled.has(k) && k !== 'raw_output') remaining[k] = v
  }
  if (Object.keys(remaining).length > 0) {
    rendered.push(
      <div key="fallback" style={S.section}>
        <SectionLabel text="── DONNÉES ──" />
        <pre style={{
          margin: 0, padding: '6px 8px', background: '#060606',
          border: '1px solid #111', fontSize: 8, color: '#445566',
          fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap',
          wordBreak: 'break-all', maxHeight: 120, overflowY: 'auto',
        }}>
          {JSON.stringify(remaining, null, 2)}
        </pre>
      </div>
    )
  }

  // Raw output replié
  if (typeof e.raw_output === 'string' && e.raw_output) {
    rendered.push(<CollapsibleRaw key="raw" text={e.raw_output} />)
  }

  if (rendered.length === 0) return null

  return (
    <div style={{ flexShrink: 0 }}>
      <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>── IMPACT ──</div>
      <div style={{ border: '1px solid #1a2a1a', padding: '8px 10px', background: '#040804' }}>
        {rendered}
      </div>
    </div>
  )
}
