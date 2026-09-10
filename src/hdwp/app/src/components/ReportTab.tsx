import { useEffect, useState } from 'react'
import { useLLMStore } from '../stores/llmStore'

type Format = 'markdown' | 'json' | 'har'

const FORMATS: { value: Format; label: string; desc: string }[] = [
  { value: 'markdown', label: 'Markdown', desc: 'Rapport lisible avec résumé IA optionnel' },
  { value: 'json', label: 'JSON', desc: 'findings.json + summary.json — pour intégration' },
  { value: 'har', label: 'HAR', desc: 'Un fichier .har par finding — pour Burp/ZAP' },
]

const API_KEY_LABELS: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  ollama: '— (Ollama, aucune clé requise)',
}

export function ReportTab() {
  const { active: llmActive, provider, model, api_key_valid } = useLLMStore()

  const [format, setFormat] = useState<Format>('json')
  const [aiSummary, setAiSummary] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [result, setResult] = useState<{ path: string; ai_included: boolean } | null>(null)
  const [error, setError] = useState('')
  const [outputDir, setOutputDir] = useState('')
  const [defaultDir, setDefaultDir] = useState('')

  useEffect(() => {
    fetch('/api/report/default-dir')
      .then(r => r.ok ? r.json() : null)
      .then((d: { path: string } | null) => { if (d) setDefaultDir(d.path) })
      .catch(() => {})
  }, [])

  const handleGenerate = async () => {
    setGenerating(true); setResult(null); setError('')
    try {
      const r = await fetch('/api/report/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format, include_ai_summary: aiSummary && llmActive, output_dir: outputDir || null }),
      })
      if (!r.ok) {
        setError(await r.text())
      } else {
        const data = await r.json() as { path: string; ai_summary_included: boolean }
        setResult({ path: data.path, ai_included: data.ai_summary_included })
      }
    } catch { setError('Impossible de contacter le serveur') }
    finally { setGenerating(false) }
  }

  const sectionLabel = (t: string) => (
    <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 8, marginTop: 16 }}>
      {`── ${t} ──`}
    </div>
  )

  const apiKeyLabel = API_KEY_LABELS[provider ?? 'anthropic'] ?? 'CLÉ API'

  return (
    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', overflowY: 'auto' }}>
      <div style={{ width: 520, background: 'var(--bg-panel)', border: '1px solid var(--border-hi)', padding: '24px 28px' }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 12, color: 'var(--green)', letterSpacing: 2, marginBottom: 4 }}>
          ── GÉNÉRER UN RAPPORT ──
        </div>

        {sectionLabel('FORMAT')}
        {FORMATS.map(f => (
          <label key={f.value} style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', marginBottom: 8,
            color: format === f.value ? 'var(--green)' : 'var(--green-dark)',
          }}>
            <input type="radio" checked={format === f.value}
              onChange={() => { setFormat(f.value); setResult(null) }}
              style={{ accentColor: 'var(--green)', marginTop: 2, flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: 11 }}>{f.label}</div>
              <div style={{ fontSize: 9, color: '#445566', marginTop: 1 }}>{f.desc}</div>
            </div>
          </label>
        ))}

        {format === 'markdown' && (
          <>
            {sectionLabel('RÉSUMÉ IA')}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 11, color: aiSummary ? 'var(--green)' : 'var(--green-dark)' }}>
                <input type="checkbox" checked={aiSummary} onChange={e => setAiSummary(e.target.checked)} style={{ accentColor: 'var(--green)' }} />
                Inclure un résumé IA
              </label>
              {aiSummary && !llmActive && (
                <span style={{ fontSize: 9, color: '#ffaa00' }}>LLM non configuré — rapport sans résumé</span>
              )}
              {aiSummary && llmActive && model && (
                <span style={{ fontSize: 9, color: '#445566' }}>({model})</span>
              )}
            </div>

            {sectionLabel('CLÉ API')}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', display: 'inline-block', background: api_key_valid ? 'var(--green)' : '#445566' }} />
              <span style={{ color: api_key_valid ? 'var(--green)' : '#445566' }}>
                {apiKeyLabel} {provider !== 'ollama' ? (api_key_valid ? 'détectée' : 'absente') : ''}
              </span>
            </div>
          </>
        )}

        {sectionLabel('RÉPERTOIRE DE SORTIE')}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input
            type="text"
            value={outputDir}
            onChange={e => setOutputDir(e.target.value)}
            placeholder={defaultDir || '~/.hdwp/workspaces/.../reports/'}
            style={{
              flex: 1, background: 'var(--bg-input)', border: '1px solid var(--border-hi)',
              color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 10,
              padding: '5px 8px',
            }}
          />
          <button
            onClick={() => setOutputDir('')}
            style={{
              padding: '5px 10px', fontFamily: 'var(--font-title)', fontSize: 9,
              letterSpacing: 1, background: 'transparent', border: '1px solid var(--border-hi)',
              color: 'var(--green-dark)', cursor: 'pointer', flexShrink: 0,
            }}
          >
            [ DÉFAUT ]
          </button>
        </div>

        {error && <div style={{ color: 'var(--red)', fontSize: 10, marginTop: 12 }}>{error}</div>}

        {result && (
          <div style={{ marginTop: 12, padding: '8px 10px', background: '#050e07', border: '1px solid #1a3a1a' }}>
            <div style={{ fontSize: 9, color: 'var(--green)', marginBottom: 4 }}>✓ Rapport généré</div>
            <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-hl)', wordBreak: 'break-all' }}>{result.path}</div>
            {!result.ai_included && format === 'markdown' && aiSummary && (
              <div style={{ fontSize: 8, color: '#445566', marginTop: 4 }}>Rapport généré · Résumé IA : non inclus (LLM non configuré)</div>
            )}
          </div>
        )}

        <button onClick={handleGenerate} disabled={generating} style={{
          marginTop: 20, width: '100%', padding: '8px 0',
          background: 'transparent', border: '1px solid var(--green)',
          color: 'var(--green)', fontFamily: 'var(--font-title)', fontSize: 10,
          letterSpacing: 2, cursor: generating ? 'wait' : 'pointer', transition: 'all 0.12s',
        }}
          onMouseEnter={e => { e.currentTarget.style.background = 'var(--green)'; e.currentTarget.style.color = '#020c0a' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--green)' }}
        >
          {generating ? '[ GÉNÉRATION... ]' : result ? '[ REGÉNÉRER ]' : '[ GÉNÉRER ]'}
        </button>
      </div>
    </div>
  )
}
