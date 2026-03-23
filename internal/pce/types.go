package pce

// ScopeActor is one entry in a rule consumer/provider list.
// Exactly one field should be set. Actors="ams" means all managed workloads.
type ScopeActor struct {
	Label          *HrefRef `json:"label,omitempty"`
	LabelGroup     *HrefRef `json:"label_group,omitempty"`
	Actors         string   `json:"actors,omitempty"`
	IPList         *HrefRef `json:"ip_list,omitempty"`
	Workload       *HrefRef `json:"workload,omitempty"`
	VirtualService *HrefRef `json:"virtual_service,omitempty"`
	VirtualServer  *HrefRef `json:"virtual_server,omitempty"`
	Exclusion      bool     `json:"exclusion,omitempty"`
}

// HrefRef is a wrapper used wherever the PCE expects {"href": "..."}.
// Name is display-only and is ignored by the PCE on write.
type HrefRef struct {
	Href string `json:"href"`
	Name string `json:"name,omitempty"`
}
