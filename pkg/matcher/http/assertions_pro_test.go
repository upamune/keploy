package http

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

func TestAssertionMatchAdvancedBodyAndJSONPath(t *testing.T) {
	tc := &models.TestCase{
		HTTPResp: models.HTTPResp{StatusCode: 200, Body: `{"user":{"id":"u-1","role":"admin"}}`},
		Assertions: map[models.AssertionType]interface{}{
			models.StatusCodeClass: "2xx",
			models.BodyContains:    `"role":"admin"`,
			models.BodyMatches:     `"id":"u-[0-9]+"`,
			models.JsonPathExists:  []interface{}{"user.id", "user.role"},
			models.JsonPathEqual: map[string]interface{}{
				"user.role": "admin",
			},
		},
	}
	actual := &models.HTTPResp{StatusCode: 201, Body: `{"user":{"id":"u-1","role":"admin"}}`}

	pass, _ := AssertionMatch(tc, actual, zap.NewNop())
	require.True(t, pass)
}

func TestAssertionMatchAdvancedFailure(t *testing.T) {
	tc := &models.TestCase{
		HTTPResp: models.HTTPResp{StatusCode: 200},
		Assertions: map[models.AssertionType]interface{}{
			models.StatusCodeClass: "2xx",
			models.JsonPathEqual: map[string]interface{}{
				"user.role": "admin",
			},
		},
	}
	actual := &models.HTTPResp{StatusCode: 500, Body: `{"user":{"role":"viewer"}}`}

	pass, _ := AssertionMatch(tc, actual, zap.NewNop())
	require.False(t, pass)
}
