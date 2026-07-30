package types

import (
	"encoding/json"
	"time"
)

type User struct {
	ID        int64
	GitHubID  int64
	Login     string
	AvatarURL string
	CreatedAt time.Time
}

type Project struct {
	ID        int64
	UserID    int64
	Name      string
	Slug      string
	CreatedAt time.Time
}

type Installation struct {
	ID                   int64
	GitHubInstallationID int64
	TargetType           string
	TargetLogin          string
	CreatedAt            time.Time
}

type RepoLink struct {
	ID                   int64
	InstallationID       int64
	GitHubInstallationID int64
	TargetType           string
	TargetLogin          string
	RepoFullName         string
	CreatedAt            time.Time
}

type Run struct {
	ID             int64
	RepoFullName   string
	CommitSHA      string
	WorkflowName   string
	JobWorkflowRef string
	JobName        string
	GitHubRunID    int64
	GitHubJobID    int64
	Branch         string
	EventName      string
	Actor          string
	PRNumber       *int64
	EgressJSON     json.RawMessage
	CreatedAt      time.Time
}
