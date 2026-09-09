package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cpa-usage-keeper/internal/repository"
	"cpa-usage-keeper/internal/service"
	"github.com/gin-gonic/gin"
)

const identityMappingUpdateBodyLimit = 4096

type identityMappingUpdateRequest struct {
	SourceUserCatalogID string `json:"source_user_catalog_id"`
}

type identityMappingResponse struct {
	ID                  string `json:"id"`
	Label               string `json:"label"`
	SourceUserCatalogID string `json:"source_user_catalog_id,omitempty"`
	SourceUserLabel     string `json:"source_user_label,omitempty"`
	MatchMethod         string `json:"match_method,omitempty"`
	Confirmed           bool   `json:"confirmed"`
}

type identityMappingsResponse struct {
	SourceSystem string                    `json:"source_system"`
	SyncedAt     time.Time                 `json:"synced_at"`
	Stale        bool                      `json:"stale"`
	Mappings     []identityMappingResponse `json:"mappings"`
}

func registerIdentityMappingRoutes(router gin.IRoutes, access service.UsageAccessProvider, catalogState CatalogStateProvider) {
	router.GET("/admin/identity-mappings", func(c *gin.Context) {
		principal, ok := embeddedAccessPrincipalFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		records, err := access.ListIdentityMappings(c.Request.Context(), principal)
		if err != nil {
			writeUsageScopeError(c, err)
			return
		}
		users, err := access.ListScopeUsers(c.Request.Context(), principal)
		if err != nil {
			writeUsageScopeError(c, err)
			return
		}
		metadata, ok := loadUsageScopeSyncMetadata(c, catalogState, principal.SourceSystem)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, identityMappingsResponse{
			SourceSystem: metadata.SourceSystem,
			SyncedAt:     metadata.SyncedAt,
			Stale:        metadata.Stale,
			Mappings:     buildIdentityMappingResponses(records, buildUsageScopeUserOptions(users)),
		})
	})

	router.PUT("/admin/identity-mappings/:id", func(c *gin.Context) {
		principal, ok := embeddedAccessPrincipalFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		request, err := decodeIdentityMappingUpdate(c.Request)
		if err != nil || strings.TrimSpace(c.Param("id")) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mapping update"})
			return
		}
		if err := access.ReplaceIdentityMapping(c.Request.Context(), principal, c.Param("id"), request.SourceUserCatalogID); err != nil {
			writeUsageScopeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	})
}

func decodeIdentityMappingUpdate(request *http.Request) (identityMappingUpdateRequest, error) {
	if request == nil || request.Body == nil {
		return identityMappingUpdateRequest{}, errors.New("missing request body")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, identityMappingUpdateBodyLimit+1))
	decoder.DisallowUnknownFields()
	var payload identityMappingUpdateRequest
	if err := decoder.Decode(&payload); err != nil {
		return identityMappingUpdateRequest{}, err
	}
	if strings.TrimSpace(payload.SourceUserCatalogID) == "" {
		return identityMappingUpdateRequest{}, errors.New("source user catalog ID is required")
	}
	payload.SourceUserCatalogID = strings.TrimSpace(payload.SourceUserCatalogID)
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return identityMappingUpdateRequest{}, fmt.Errorf("multiple JSON values are not allowed")
		}
		return identityMappingUpdateRequest{}, err
	}
	return payload, nil
}

func buildIdentityMappingResponses(records []repository.IdentityMappingRecord, users []usageScopeOption) []identityMappingResponse {
	labelsByID := make(map[string]string, len(users))
	for _, user := range users {
		labelsByID[user.ID] = user.Label
	}
	responses := make([]identityMappingResponse, 0, len(records))
	for _, record := range records {
		responses = append(responses, identityMappingResponse{
			ID:                  record.ExternalIdentityID,
			Label:               safeUsageScopeLabel(record.ExternalLabel, "External identity"),
			SourceUserCatalogID: record.SourceUserID,
			SourceUserLabel:     labelsByID[record.SourceUserID],
			MatchMethod:         record.MatchMethod,
			Confirmed:           record.Confirmed,
		})
	}
	return responses
}
