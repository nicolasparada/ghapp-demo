package types

import (
	"encoding/json"
	"time"
)

type User struct {
	ID          int64
	DisplayName string
	Login       string
	Email       *string
	AvatarURL   string
	CreatedAt   time.Time
}

type Project struct {
	ID        int64
	CreatedBy *int64
	Role      string
	Name      string
	Slug      string
	CreatedAt time.Time
}

type Installation struct {
	GitHubInstallationID int64
	GitHubAccountID      int64
	TargetType           string
	TargetLogin          string
	RepositorySelection  *string
	CreatedAt            time.Time
	SyncedAt             time.Time
	DeletedAt            *time.Time
}

type Repo struct {
	RepoID      int64
	FullName    string
	Owner       string
	OwnerID     int64
	Visibility  string
	SyncedAt    time.Time
	Bound       bool
	CanBind     bool
	BoundAt     *time.Time
	RevokedAt   *time.Time
	UpdatedFrom string
}

type Run struct {
	ID                int64
	PublicID          string
	RepoID            int64
	RepoFullName      string
	RepoVisibility    string
	ViewerIsMember    bool
	CommitSHA         string
	WorkflowName      string
	WorkflowRef       string
	WorkflowSHA       string
	JobWorkflowRef    string
	JobWorkflowSHA    string
	JobKey            string
	JobName           string
	JobDisplayName    *string
	GitHubRunID       int64
	GitHubJobID       *int64
	RunAttempt        int
	Branch            string
	EventName         string
	Actor             string
	ActorID           *int64
	RunnerEnvironment string
	ExecutionID       string
	RunnerName        string
	RunnerOS          string
	CaptureStartedAt  *time.Time
	CaptureEndedAt    *time.Time
	PayloadSHA256     string
	PRNumber          *int64
	EnrichmentState   string
	EgressJSON        json.RawMessage
	CreatedAt         time.Time
}
