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
  proof?: Record<string, unknown>
}

export interface PayloadFinding extends Finding {
  has_replay: boolean
  replay_type: 'passive' | 'experiment' | 'none'
  proof: Record<string, unknown>
}

export interface ExploitRelatedFinding {
  id: string
  cwe_id: string
  severity: string
  endpoint: string
}

export interface ExploitResult {
  finding_id: string
  vuln_type: string
  status: 'success' | 'partial' | 'not_implemented' | 'failed'
  impact_evidence: Record<string, unknown> | null
  request_used: Record<string, unknown> | null
  elapsed_ms: number
  note: string
  impact_description?: string
  attack_scenarios?: string[]
  related_findings?: ExploitRelatedFinding[]
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

export interface ChainCandidate {
  chain_type: string
  description: string
  precondition_finding_ids: string[]
  executable: boolean
  missing_preconditions: string[]
}

export interface ChainFinding {
  id: string
  chain_type: string
  trigger_finding_ids: string[]
  severity: string
  confidence: number
  proof: Record<string, unknown>
}

export interface ScriptTemplate {
  name: string
  path: string
  type: 'py' | 'sh' | 'js'
  description: string
}

export interface ScriptResult {
  success: boolean
  stdout: string
  stderr: string
  exit_code: number
  elapsed_ms: number
}

export interface ExploitAction {
  finding_id: string
  action_type: 'demo_page' | 'payload_url' | 'html_form' | 'click_link' | 'copy_payload'
  title: string
  description: string
  payload: string
  demo_url: string | null
  instructions: string[]
  copy_ready: boolean
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

export interface PayloadAdaptedBlocked  { signal_type: 'BLOCKED';          adaptation: 'waf_bypass';          endpoint: string; waf_type: string; strategies: { name: string; transform: string }[]; hypothesis_id: string }
export interface PayloadAdaptedError    { signal_type: 'ERROR';            adaptation: 'error_refinement';    endpoint: string; db_hints: Record<string, string>; hypothesis_id: string }
export interface PayloadAdaptedTiming   { signal_type: 'TIMING_ANOMALY';   adaptation: 'timing_escalation';   endpoint: string; timing_ms: number; baseline_ms: number; hypothesis_id: string }
export interface PayloadAdaptedField    { signal_type: 'UNEXPECTED_FIELD'; adaptation: 'field_investigation'; endpoint: string; hypothesis_id: string }
export type PayloadAdapted = PayloadAdaptedBlocked | PayloadAdaptedError | PayloadAdaptedTiming | PayloadAdaptedField

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
