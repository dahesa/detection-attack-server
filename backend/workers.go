package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// WorkersEngine engine untuk edge computing/workers
type WorkersEngine struct {
	mu         sync.RWMutex
	workers    map[string]*Worker
	executions map[string]*Execution
	stats      *WorkersStats
}

// Worker represents a worker
type Worker struct {
	ID             string
	Name           string
	Script         string
	Runtime        string // javascript, python, go
	Triggers       []string
	IsActive       bool
	CreatedAt      time.Time
	LastModified   time.Time
	ExecutionCount int64
	ErrorCount     int64
}

// Execution represents a worker execution
type Execution struct {
	ID          string
	WorkerID    string
	StartedAt   time.Time
	CompletedAt time.Time
	Duration    time.Duration
	Status      string // success, error, timeout
	Result      interface{}
	Error       string
}

// WorkersStats statistics
type WorkersStats struct {
	TotalWorkers    int64
	ActiveWorkers   int64
	TotalExecutions int64
	SuccessCount    int64
	ErrorCount      int64
	AvgDuration     time.Duration
}

// NewWorkersEngine creates new workers engine
func NewWorkersEngine() *WorkersEngine {
	return &WorkersEngine{
		workers:    make(map[string]*Worker),
		executions: make(map[string]*Execution),
		stats:      &WorkersStats{},
	}
}

// CreateWorker creates a new worker
func (we *WorkersEngine) CreateWorker(name, script, runtime string, triggers []string) (*Worker, error) {
	we.mu.Lock()
	defer we.mu.Unlock()

	worker := &Worker{
		ID:             generateWorkerID(),
		Name:           name,
		Script:         script,
		Runtime:        runtime,
		Triggers:       triggers,
		IsActive:       true,
		CreatedAt:      time.Now(),
		LastModified:   time.Now(),
		ExecutionCount: 0,
		ErrorCount:     0,
	}

	we.workers[worker.ID] = worker
	we.stats.TotalWorkers++
	we.stats.ActiveWorkers++

	log.Printf("✅ Worker created: %s (%s)", name, worker.ID)
	return worker, nil
}

// ExecuteWorker executes a worker
func (we *WorkersEngine) ExecuteWorker(workerID string, request *http.Request, data map[string]interface{}) (*Execution, error) {
	we.mu.RLock()
	worker, exists := we.workers[workerID]
	we.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("worker not found: %s", workerID)
	}

	if !worker.IsActive {
		return nil, fmt.Errorf("worker is not active")
	}

	execution := &Execution{
		ID:        generateExecutionID(),
		WorkerID:  workerID,
		StartedAt: time.Now(),
		Status:    "running",
	}

	we.mu.Lock()
	we.executions[execution.ID] = execution
	we.stats.TotalExecutions++
	we.mu.Unlock()

	// Execute worker script
	result, err := we.runWorker(worker, request, data)

	execution.CompletedAt = time.Now()
	execution.Duration = execution.CompletedAt.Sub(execution.StartedAt)

	if err != nil {
		execution.Status = "error"
		execution.Error = err.Error()
		we.stats.ErrorCount++
		worker.ErrorCount++
	} else {
		execution.Status = "success"
		execution.Result = result
		we.stats.SuccessCount++
	}

	worker.ExecutionCount++

	// Update average duration
	we.updateAvgDuration(execution.Duration)

	return execution, err
}

func (we *WorkersEngine) runWorker(worker *Worker, request *http.Request, data map[string]interface{}) (interface{}, error) {
	// In production, this would execute the actual worker script
	// For now, return a simple result based on runtime

	switch worker.Runtime {
	case "javascript":
		return we.runJavaScriptWorker(worker, request, data)
	case "python":
		return we.runPythonWorker(worker, request, data)
	case "go":
		return we.runGoWorker(worker, request, data)
	default:
		return nil, fmt.Errorf("unsupported runtime: %s", worker.Runtime)
	}
}

func (we *WorkersEngine) runJavaScriptWorker(worker *Worker, request *http.Request, data map[string]interface{}) (interface{}, error) {
	// In production, use JavaScript runtime (like V8)
	log.Printf("🔧 Executing JavaScript worker: %s", worker.Name)
	return map[string]interface{}{
		"message": "Worker executed successfully",
		"worker":  worker.Name,
		"data":    data,
	}, nil
}

func (we *WorkersEngine) runPythonWorker(worker *Worker, request *http.Request, data map[string]interface{}) (interface{}, error) {
	// In production, use Python runtime
	log.Printf("🔧 Executing Python worker: %s", worker.Name)
	return map[string]interface{}{
		"message": "Worker executed successfully",
		"worker":  worker.Name,
		"data":    data,
	}, nil
}

func (we *WorkersEngine) runGoWorker(worker *Worker, request *http.Request, data map[string]interface{}) (interface{}, error) {
	// In production, use Go runtime
	log.Printf("🔧 Executing Go worker: %s", worker.Name)
	return map[string]interface{}{
		"message": "Worker executed successfully",
		"worker":  worker.Name,
		"data":    data,
	}, nil
}

func (we *WorkersEngine) updateAvgDuration(duration time.Duration) {
	we.mu.Lock()
	defer we.mu.Unlock()

	if we.stats.TotalExecutions > 0 {
		avg := we.stats.AvgDuration.Nanoseconds()
		newAvg := (avg*int64(we.stats.TotalExecutions-1) + duration.Nanoseconds()) / int64(we.stats.TotalExecutions)
		we.stats.AvgDuration = time.Duration(newAvg)
	} else {
		we.stats.AvgDuration = duration
	}
}

// TriggerWorkers triggers workers based on event
func (we *WorkersEngine) TriggerWorkers(event string, request *http.Request, data map[string]interface{}) []*Execution {
	we.mu.RLock()
	defer we.mu.RUnlock()

	executions := make([]*Execution, 0)

	for _, worker := range we.workers {
		if !worker.IsActive {
			continue
		}

		// Check if worker should be triggered
		for _, trigger := range worker.Triggers {
			if trigger == event || trigger == "*" {
				exec, err := we.ExecuteWorker(worker.ID, request, data)
				if err == nil {
					executions = append(executions, exec)
				}
			}
		}
	}

	return executions
}

// Middleware untuk workers
func (we *WorkersEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trigger workers before request
		data := map[string]interface{}{
			"method": r.Method,
			"path":   r.URL.Path,
			"ip":     getClientIP(r),
		}
		we.TriggerWorkers("http_request", r, data)

		next.ServeHTTP(w, r)

		// Trigger workers after request
		we.TriggerWorkers("http_response", r, data)
	})
}

// GetStats returns workers statistics
func (we *WorkersEngine) GetStats() *WorkersStats {
	we.mu.RLock()
	defer we.mu.RUnlock()

	return &WorkersStats{
		TotalWorkers:    we.stats.TotalWorkers,
		ActiveWorkers:   we.stats.ActiveWorkers,
		TotalExecutions: we.stats.TotalExecutions,
		SuccessCount:    we.stats.SuccessCount,
		ErrorCount:      we.stats.ErrorCount,
		AvgDuration:     we.stats.AvgDuration,
	}
}

func generateWorkerID() string {
	return fmt.Sprintf("worker_%d", time.Now().UnixNano())
}

func generateExecutionID() string {
	return fmt.Sprintf("exec_%d", time.Now().UnixNano())
}
