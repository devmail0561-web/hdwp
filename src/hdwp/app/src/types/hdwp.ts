export interface BusEvent {
  type: string
  source: string
  ts: string
  payload: Record<string, unknown>
}

export interface ConfidenceBreakdown {
  oracle_strength: number
  reproducibility: number
  observation_quality: number
  behavioral_specificity: number
  experiment_coverage: number
  overall: number
  v2_boost: number
  ml_boost: number
}

export interface SignalContribution {
  dimension: string
  raw_value: number
  weight: number
  contribution: number
  label: string
}

export interface FindingExplanation {
  v1_score: number
  v2_score: number
  ml_score: number
  signals: Record<string, number>
  top_contributors: SignalContribution[]
  verdict_rationale: string
}

export interface Finding {
  id: string
  hypothesis_id: string
  property_id: string
  status: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL'
  confidence: number
  owasp_category: string
  cwe_id: string
  affected_endpoints: string[]
  remediation_hint: string
  confidence_breakdown?: ConfidenceBreakdown
  explanation?: FindingExplanation | null
  proof?: Record<string, unknown>
}

export interface StateResponse {
  status: string
  session_id: string
  target_url: string
  phase: string
  model_confidence: number
  endpoint_count: number
  hypothesis_count: number
  findings_count: number
  property_count: number
  experiment_count: number
  proxy_active: boolean
  error_message: string
  tech_stack: string[]
  detected_versions: Record<string, string>
  detected_content_types: string[]
  // V3 intelligence fields
  threat_score_max?: number
  invariant_violation_count?: number
  invariant_count?: number
  waf_detected?: boolean
}

export interface LLMStatus {
  active: boolean
  provider: string | null
  model: string | null
  api_key_valid: boolean
}

export interface Plugin {
  id: string
  name: string
  version: string
  category: string
  enabled: boolean
  source: string
  description: string
  owasp_mapping: string[]
  cwe_mapping: string[]
  data_access: string
}

export interface BehavioralProfile {
  mean: number
  std: number
  sample_count: number
  max_zscore_seen: number | null
}

export interface EndpointNode {
  id: string
  path: string
  methods: string[]
  auth_required: boolean
  roles_observed: string[]
  // Champs enrichis (peuplés après observation)
  behavioral_profile?: BehavioralProfile
  status_by_role?: Record<string, number>
  contains_privilege_field?: boolean
  observed_roles?: string[]
  jwt_field_names?: string[]
  error_tech_signals?: string[]
  detected_waf?: string | null
  returns?: string[]
  response_content_type?: string | null
}

export interface LLMModelsResponse {
  models: string[]
  error: string | null
}

export interface ApiKeyStatus {
  set: boolean
  masked: string | null
  required: boolean
}

export interface SessionMeta {
  session_id: string
  target_url: string
  status: string
  phase: string
  created_at: string
  updated_at: string
  findings_count: number
  mode: string
}

export interface FlowEdge {
  from_endpoint: string
  to_endpoint: string
  trigger: 'link' | 'form' | 'ajax' | 'fsm' | 'redirect'
  params_transferred: string[]
  confidence: number
}

export interface DBColumn {
  name: string
  type_hint: string
  is_pk: boolean
  is_fk_to: string | null
}

export interface DBTable {
  name: string
  columns: DBColumn[]
  evidence_endpoints: string[]
  confidence: number
}

export interface FlowMap {
  edges: FlowEdge[]
  db_tables: DBTable[]
  exfiltration_risks: string[]
  last_updated: string
}

export interface NewSessionRequest {
  target_url: string
  mode: 'auto' | 'yaml' | 'manual'
  yaml_path?: string
  manual_tokens?: ManualToken[]
}

export interface ManualToken {
  role_name: string
  token_type: 'bearer' | 'basic' | 'api_key' | 'cookie'
  token_value: string
}

// ── V3 event payload interfaces ───────────────────────────────────────────────

export interface ThreatModelUpdated {
  scores: Record<string, number>
  classifications: Record<string, string>
}

export interface InvariantViolated {
  endpoint_path: string
  pattern_type: string
  formal_statement: string
  confidence: number
  experiment_id: string
  observed_value: string
}

export interface CrossRoleDiffStructural {
  endpoint_path: string; diff_type: 'STRUCTURAL'; role_a: string; role_b: string; confidence: number
  details: { extra_in_a: string[]; extra_in_b: string[]; sensitive_leaked: string[] }
}
export interface CrossRoleDiffValue {
  endpoint_path: string; diff_type: 'VALUE'; role_a: string; role_b: string; confidence: number
  details: { masked_fields: Record<string, { a: string; b: string }> }
}
export interface CrossRoleDiffIdentity {
  endpoint_path: string; diff_type: 'IDENTITY'; role_a: string; role_b: string; confidence: number
  details: { mismatches: Record<string, { a: string; b: string }> }
}
export type CrossRoleDiff = CrossRoleDiffStructural | CrossRoleDiffValue | CrossRoleDiffIdentity

export interface TemporalAnomaly {
  endpoint_path: string
  timing_ms: number
  baseline_p95: number
  threshold: number
  escalation_level: 0 | 1 | 2
  suggested_delay: number
  hypothesis_id: string
}

export interface WafSignature {
  endpoint: string
  waf_type: 'cloudflare' | 'aws_waf' | 'modsecurity' | 'f5_asm' | 'unknown'
  bypass_strategies: string[]
  hypothesis_id: string
}

export interface GoalReached {
  goal_type: string
  plan_steps: number
  total_cost: number
}

export interface PreconditionMissing {
  finding_id: string
  missing: Record<string, string[]>
  endpoint: string
}
