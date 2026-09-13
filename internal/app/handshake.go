package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

const (
	fingerprintPath = "/alpha/fingerprint/record"
	lifecyclePath   = "/alpha/lifecycle-events"
)

// DetectionStore returns the configured detection store, or nil.
func (c *CCClient) DetectionStore() *DetectionStore {
	return c.detection
}

// SetDetection wires the detection store. It also becomes the per-key session
// source for request metadata fallback.
func (c *CCClient) SetDetection(store *DetectionStore) {
	c.detection = store
	if store != nil {
		c.sessions = store
	}
}

// prepareDetection makes sure the key's fingerprint/lifecycle handshake has
// run before a completion is sent. It is best-effort: only a 401/403 from the
// handshake disables the account and fails over.
func (c *CCClient) prepareDetection(ctx context.Context, acct *Account) error {
	if c.detection == nil {
		return nil
	}
	base := c.BaseURLValue()
	if _, need := c.detection.Ensure(acct.ID, base); !need {
		return nil
	}

	// Per-account lock: concurrent first requests must not double-fire, and
	// the second waits for the first rather than racing ahead.
	lock := c.accountHandshakeLock(acct.ID)
	lock.Lock()
	defer lock.Unlock()
	if _, need := c.detection.Ensure(acct.ID, base); !need {
		return nil
	}

	err := c.runHandshake(ctx, acct, base)
	// The reference advances the refresh deadline after every attempt, so a
	// failed handshake is not retried on the next completion.
	c.detection.MarkHandshake(acct.ID, base)
	if isHandshakeAuthError(err) {
		acct.Enabled = false
		acct.RecordFailure(err)
		return err
	}
	// err is nil or a non-auth failure that runHandshake already logged;
	// neither may block the completion.
	return nil
}

func (c *CCClient) accountHandshakeLock(id string) *sync.Mutex {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeLocks == nil {
		c.handshakeLocks = map[string]*sync.Mutex{}
	}
	lock, ok := c.handshakeLocks[id]
	if !ok {
		lock = &sync.Mutex{}
		c.handshakeLocks[id] = lock
	}
	return lock
}

// runHandshake fires fingerprint and lifecycle concurrently, matching the
// reference's Promise.all.
func (c *CCClient) runHandshake(ctx context.Context, acct *Account, base string) error {
	state, _ := c.detection.State(acct.ID)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results <- c.sendFingerprint(ctx, acct, state)
	}()
	go func() {
		defer wg.Done()
		results <- c.sendLifecycle(ctx, acct, state)
	}()
	wg.Wait()
	close(results)

	var authErr error
	for err := range results {
		if err == nil {
			continue
		}
		if isHandshakeAuthError(err) {
			if authErr == nil {
				authErr = err
			}
			continue
		}
		log.Printf("[WARN] handshake request for account %s failed: %s", acct.Name, redactError(err))
	}
	return authErr
}

func (c *CCClient) sendFingerprint(ctx context.Context, acct *Account, state DetectionState) error {
	return c.doHandshakeRequest(ctx, fingerprintPath, fingerprintPayloadFrom(state), acct.APIKey)
}

func (c *CCClient) sendLifecycle(ctx context.Context, acct *Account, state DetectionState) error {
	return c.doHandshakeRequest(ctx, lifecyclePath, lifecyclePayloadFrom(state, c.cliVersion()), acct.APIKey)
}

// RecordFingerprint performs a single fingerprint/record call, used by the
// WebUI's "re-record" action.
func (c *CCClient) RecordFingerprint(ctx context.Context, acct *Account) error {
	if c.detection == nil {
		return fmt.Errorf("detection store is not configured")
	}
	state, _ := c.detection.Ensure(acct.ID, c.BaseURLValue())
	if err := c.sendFingerprint(ctx, acct, state); err != nil {
		return err
	}
	c.detection.MarkRecorded(acct.ID, c.BaseURLValue())
	return nil
}

// RecordLifecycle performs a single lifecycle-events call, used by the WebUI's
// "new session" action.
func (c *CCClient) RecordLifecycle(ctx context.Context, acct *Account) error {
	if c.detection == nil {
		return fmt.Errorf("detection store is not configured")
	}
	state, _ := c.detection.Ensure(acct.ID, c.BaseURLValue())
	if err := c.sendLifecycle(ctx, acct, state); err != nil {
		return err
	}
	c.detection.MarkRecorded(acct.ID, c.BaseURLValue())
	return nil
}

func (c *CCClient) doHandshakeRequest(ctx context.Context, path string, payload any, apiKey string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURLValue()+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request: %w", path, err)
	}
	meta := CLIRequestMetadata{
		Version:     c.cliVersion(),
		Environment: cliEnvironmentHeader,
		ZDREnabled:  zdrEnabled(nil),
	}
	meta.ApplyHandshake(req)
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return &upstreamAPIError{
			Status:  resp.StatusCode,
			Type:    "handshake_error",
			Code:    "handshake_failed",
			Message: fmt.Sprintf("handshake %s returned %d", path, resp.StatusCode),
		}
	}
	return nil
}

func isHandshakeAuthError(err error) bool {
	var upstreamErr *upstreamAPIError
	if !errors.As(err, &upstreamErr) {
		return false
	}
	return upstreamErr.Status == http.StatusUnauthorized || upstreamErr.Status == http.StatusForbidden
}
