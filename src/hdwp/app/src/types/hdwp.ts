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

export interface ExploitFinding extends Finding {
  has_replay: boolean
  replay_type: 'passive' | 'experiment' | 'none'
  proof: Record<string, unknown>
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
