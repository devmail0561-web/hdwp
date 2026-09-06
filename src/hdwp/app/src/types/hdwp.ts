export interface BusEvent {
  type: string
  source: string
  ts: string
  payload: Record<string, unknown>
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

export interface EndpointNode {
  id: string
  path: string
  methods: string[]
  auth_required: boolean
  roles_observed: string[]
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
