package detector

import (
	"context"
	"sync"

	"redirx/internal/models"
	"redirx/internal/redirect"
)

// RequestExecutor abstracts HTTP request dispatching with rate limiting,
// metrics tracking, and error recording for decoupled detection techniques.
type RequestExecutor interface {
	Execute(ctx context.Context, targetURL string) (*redirect.ExecutionResult, error)
	Wait(targetURL string)
	RecordRequest()
	RecordFinding(classification models.Classification)
	RecordError(err string)
	IncrementParameters()
}

// Technique represents an independent, pluggable Open Redirect detection method.
type Technique interface {
	// ID returns a unique machine-readable identifier for the technique.
	ID() string
	// Name returns a human-readable title for console and reports.
	Name() string
	// Description explains the testing methodology.
	Description() string
	// IsEnabled checks whether this technique is active under the given configuration.
	IsEnabled(cfg *models.ScanConfig) bool
	// Execute performs the detection logic against the target URL.
	Execute(ctx context.Context, targetURL string, exec RequestExecutor, cfg *models.ScanConfig) ([]models.Finding, error)
}

// Registry manages and coordinates available detection techniques.
type Registry struct {
	mu         sync.RWMutex
	techniques []Technique
}

// NewRegistry initializes an empty technique registry.
func NewRegistry() *Registry {
	return &Registry{
		techniques: make([]Technique, 0),
	}
}

// Register adds a new technique to the registry.
func (r *Registry) Register(t Technique) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.techniques = append(r.techniques, t)
}

// All returns a slice of all registered techniques.
func (r *Registry) All() []Technique {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copied := make([]Technique, len(r.techniques))
	copy(copied, r.techniques)
	return copied
}

// GetEnabled returns only the techniques enabled by the current scan configuration.
func (r *Registry) GetEnabled(cfg *models.ScanConfig) []Technique {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var enabled []Technique
	for _, t := range r.techniques {
		if t.IsEnabled(cfg) {
			enabled = append(enabled, t)
		}
	}
	return enabled
}

// DefaultRegistry constructs a registry populated with all standard detection techniques.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewPathCanonicalizationTechnique())
	r.Register(NewQueryParameterTechnique())
	return r
}

