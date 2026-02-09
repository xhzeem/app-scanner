package nse

// Modify to use the new manifest.json file and sync with the repo and valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	scriptContentPrefix = "nse:script"
)

// SyncManager handles synchronization between local NSE scripts and ValKey store
type SyncManager struct {
	repoManager *RepoManager
	kvStore     store.KVStore
}

// NewSyncManager creates a new SyncManager instance
func NewSyncManager(repoManager *RepoManager, kvStore store.KVStore) *SyncManager {
	return &SyncManager{
		repoManager: repoManager,
		kvStore:     kvStore,
	}
}

// loadRepositories loads the repository list, prioritizing ValKey over local manifest
func (sm *SyncManager) loadRepositories(ctx context.Context) (*RepositoryList, error) {
	// Try to get repository list from ValKey first
	resp, err := sm.kvStore.GetValue(ctx, ValKeyRepoManifestKey)
	if err != nil {
		// Check for key not found errors (valkey nil message or "not found")
		if strings.Contains(err.Error(), "valkey nil message") || strings.Contains(err.Error(), "not found") {
			// Load built-in repository list
			slog.Info("no repository manifest found in ValKey, loading built-in manifest")
			builtInList, err := LoadRepositoryList("internal/nse/manifest.json")
			if err != nil {
				return nil, fmt.Errorf("failed to load built-in repository list: %w", err)
			}

			// Initialize ValKey with built-in list
			manifestJSON, err := json.Marshal(builtInList)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal repository list: %w", err)
			}

			if err := sm.kvStore.SetValue(ctx, ValKeyRepoManifestKey, string(manifestJSON)); err != nil {
				return nil, fmt.Errorf("failed to initialize ValKey repository manifest: %w", err)
			}

			slog.Info("successfully initialized ValKey repository manifest")
			return builtInList, nil
		}
		return nil, fmt.Errorf("failed to get repository manifest from ValKey: %w", err)
	}

	// Parse ValKey response
	var repoList RepositoryList
	if err := json.Unmarshal([]byte(resp.Message.Value), &repoList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal repository manifest from ValKey: %w", err)
	}

	return &repoList, nil
}

// Sync synchronizes the local NSE scripts with the ValKey store
func (sm *SyncManager) Sync(ctx context.Context) error {
	// Load repositories from ValKey or initialize from built-in list
	repoList, err := sm.loadRepositories(ctx)
	if err != nil {
		return fmt.Errorf("failed to load repositories: %w", err)
	}

	// Process each repository
	for _, repo := range repoList.Repositories {
		slog.Info("processing repository", "repo", repo.Name)

		// Create a new repo manager for this repository
		repoPath := filepath.Join(sm.repoManager.BasePath, "..", repo.Name)
		repoManager := NewRepoManager(repoPath, repo.URL)

		// Check if repository already exists and has a manifest (development/volume mount scenario)
		if repoManager.isGitRepo() {
			slog.Debug("repository already exists, using local copy", "repo", repo.Name)
		} else {
			// Ensure repository is cloned (production scenario)
			if err := repoManager.EnsureRepo(); err != nil {
				slog.Warn("failed to ensure repository", "repo", repo.Name, "error", err)
				continue
			}
		}

		// Get local manifest from repository
		localManifest, err := repoManager.GetManifest()
		if err != nil {
			slog.Warn("failed to get manifest from repository", "repo", repo.Name, "error", err)
			continue
		}

		// Get ValKey manifest (global source of truth)
		globalManifest, err := sm.getValKeyManifest(ctx)
		if err != nil {
			// Check for key not found errors
			if strings.Contains(err.Error(), "not found") {
				// If no global manifest exists, initialize it with local manifest
				slog.Info("no manifest found in ValKey, initializing with local manifest", "manifest", localManifest.Name)
				if err := sm.updateValKeyManifest(ctx, localManifest); err != nil {
					slog.Warn("failed to initialize ValKey manifest", "repo", repo.Name, "error", err)
					continue
				}
				slog.Info("successfully initialized ValKey manifest")
				globalManifest = localManifest
			} else {
				slog.Warn("failed to get ValKey manifest", "repo", repo.Name, "error", err)
				continue
			}
		}

		// Merge manifests with global taking precedence
		mergedManifest := sm.mergeManifests(globalManifest, localManifest)

		// Update ValKey with merged manifest
		if err := sm.updateValKeyManifest(ctx, mergedManifest); err != nil {
			slog.Warn("failed to update ValKey manifest", "repo", repo.Name, "error", err)
			continue
		}

		// Sync each script's content
		var synced, failed int
		for id, script := range mergedManifest.Scripts {
			if err := sm.syncScriptContent(id, script); err != nil {
				failed++
				slog.Debug("failed to sync script", "script_id", id, "error", err)
				continue
			}
			synced++
		}
		slog.Info("script sync complete", "repo", repo.Name,
			"synced", synced, "failed", failed, "total", len(mergedManifest.Scripts))
	}

	return nil
}

// mergeManifests merges two manifests with global taking precedence
// But ensures new scripts from local are added to the merged result
func (sm *SyncManager) mergeManifests(global, local *Manifest) *Manifest {
	slog.Debug("merging manifests", "global_scripts", len(global.Scripts), "local_scripts", len(local.Scripts))

	merged := &Manifest{
		Name:        global.Name,        // Use global name
		Version:     global.Version,     // Use global version
		Description: global.Description, // Use global description
		Scripts:     make(map[string]Script),
	}

	// First, add all local scripts
	for id, script := range local.Scripts {
		merged.Scripts[id] = script
		if _, exists := global.Scripts[id]; !exists {
			slog.Debug("found new script in repository", "script_id", id)
		}
	}

	// Then overlay global scripts (taking precedence for existing scripts)
	for id, script := range global.Scripts {
		merged.Scripts[id] = script
	}

	slog.Debug("merged manifest complete", "script_count", len(merged.Scripts))
	return merged
}

// extractScriptContent ensures we're storing proper Lua script content, not JSON
func extractScriptContent(content string) string {
	// Check if content looks like JSON (starts with '{')
	if strings.TrimSpace(content)[0] == '{' {
		// Try to parse as JSON
		var jsonContent struct {
			Content string `json:"content"`
		}
		err := json.Unmarshal([]byte(content), &jsonContent)
		if err == nil && jsonContent.Content != "" {
			// Found valid content field in JSON
			return jsonContent.Content
		}
	}
	// Return as-is if not JSON or couldn't parse
	return content
}

// syncScriptContent synchronizes a single script's content
func (sm *SyncManager) syncScriptContent(id string, script Script) error {
	// Get script content from ValKey first (highest priority)
	globalContent, err := sm.getScriptContent(context.Background(), id)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	// If we have global content, use it
	if globalContent != "" {
		// Extract the actual script content from potentially JSON-wrapped content
		scriptContent := extractScriptContent(globalContent)

		// Write global content to local file
		scriptPath := filepath.Join(sm.repoManager.BasePath, script.Path)
		if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
			return fmt.Errorf("failed to create script directory: %w", err)
		}

		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
			return fmt.Errorf("failed to write script file: %w", err)
		}
		return nil
	}

	// If no global content, read from local file
	scriptPath := filepath.Join(sm.repoManager.BasePath, script.Path)
	localContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read local script: %w", err)
	}

	// Create new script content
	newContent := &ScriptContent{
		Content: string(localContent),
		Metadata: Metadata{
			Author:      "System",
			Tags:        []string{script.Protocol},
			Description: fmt.Sprintf("NSE script for %s protocol", script.Protocol),
		},
		UpdatedAt: time.Now().Unix(),
	}

	// Update ValKey with local content
	if err := sm.updateScriptContent(context.Background(), id, newContent); err != nil {
		return fmt.Errorf("failed to update script content in ValKey: %w", err)
	}

	return nil
}

// getValKeyManifest retrieves the manifest from ValKey store
func (sm *SyncManager) getValKeyManifest(ctx context.Context) (*Manifest, error) {
	resp, err := sm.kvStore.GetValue(ctx, ValKeyManifestKey)
	if err != nil {
		if strings.Contains(err.Error(), "valkey nil message") {
			// Initialize empty manifest if it doesn't exist
			slog.Info("no manifest found in ValKey, initializing empty manifest")
			emptyManifest := &Manifest{
				Scripts: make(map[string]Script),
			}
			err = sm.updateValKeyManifest(ctx, emptyManifest)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize empty manifest: %w", err)
			}
			return emptyManifest, nil
		}
		return nil, fmt.Errorf("failed to get manifest from ValKey: %w", err)
	}

	var manifest Manifest
	err = json.Unmarshal([]byte(resp.Message.Value), &manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if manifest.Scripts == nil {
		manifest.Scripts = make(map[string]Script)
	}

	return &manifest, nil
}

// updateValKeyManifest updates the manifest in ValKey store
func (sm *SyncManager) updateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	// First marshal the manifest to JSON
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Store the JSON string directly
	if err := sm.kvStore.SetValue(ctx, ValKeyManifestKey, string(manifestJSON)); err != nil {
		return fmt.Errorf("failed to update ValKey manifest: %w", err)
	}

	return nil
}

// getScriptContent retrieves a script's content from the KV store
func (sm *SyncManager) getScriptContent(ctx context.Context, scriptName string) (string, error) {
	resp, err := sm.kvStore.GetValue(ctx, fmt.Sprintf("%s:%s", scriptContentPrefix, scriptName))
	if err != nil {
		if strings.Contains(err.Error(), "valkey nil message") {
			// Script content doesn't exist in ValKey yet
			slog.Debug("no content found in ValKey for script", "script_id", scriptName)
			return "", nil
		}
		return "", fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	return resp.Message.Value, nil
}

// updateScriptContent updates a script's content in the KV store
func (sm *SyncManager) updateScriptContent(ctx context.Context, scriptID string, content *ScriptContent) error {
	key := ValKeyScriptPrefix + scriptID

	// First marshal the content to JSON
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal script content: %w", err)
	}

	// Store the JSON string directly
	if err := sm.kvStore.SetValue(ctx, key, string(contentJSON)); err != nil {
		return fmt.Errorf("failed to set script content in ValKey: %w", err)
	}

	return nil
}

// UpdateScriptFromUI updates a script's content and metadata from the UI
func (sm *SyncManager) UpdateScriptFromUI(ctx context.Context, scriptID string, content *ScriptContent) error {
	// Validate that the script exists in the manifest
	manifest, err := sm.repoManager.GetManifest()
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	script, exists := manifest.Scripts[scriptID]
	if !exists {
		return fmt.Errorf("script %s not found in manifest", scriptID)
	}

	// Update the script content in ValKey
	if err := sm.updateScriptContent(ctx, scriptID, content); err != nil {
		return fmt.Errorf("failed to update script content: %w", err)
	}

	// Create script directory and write the updated content to the local file
	scriptPath := filepath.Join(NSEBasePath, script.Path)
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		return fmt.Errorf("failed to create script directory: %w", err)
	}

	if err := os.WriteFile(scriptPath, []byte(content.Content), 0644); err != nil {
		return fmt.Errorf("failed to write script file: %w", err)
	}

	return nil
}

func (sm *SyncManager) syncScript(ctx context.Context, scriptName string, script Script) error {
	// Get script content from ValKey
	globalContent, err := sm.getScriptContent(ctx, scriptName)
	if err != nil {
		return fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	// If script doesn't exist in ValKey, read from local and update ValKey
	if globalContent == "" {
		localContent, err := os.ReadFile(filepath.Join(sm.repoManager.BasePath, script.Path))
		if err != nil {
			return fmt.Errorf("failed to read local script: %w", err)
		}

		err = sm.updateScriptContent(ctx, scriptName, &ScriptContent{Content: string(localContent)})
		if err != nil {
			return fmt.Errorf("failed to update script content in ValKey: %w", err)
		}
		return nil
	}

	// Update local script with ValKey content
	err = os.WriteFile(filepath.Join(sm.repoManager.BasePath, script.Path), []byte(globalContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write script content: %w", err)
	}

	return nil
}

// SyncScriptContent synchronizes a single script's content
func (sm *SyncManager) SyncScriptContent(id string, script Script) error {
	return sm.syncScriptContent(id, script)
}

// UpdateValKeyManifest updates the manifest in ValKey store
func (sm *SyncManager) UpdateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	return sm.updateValKeyManifest(ctx, manifest)
}
