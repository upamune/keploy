// Package redis records and replays Redis RESP dependency calls.
package redis

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"go.keploy.io/server/v3/pkg"
	"go.keploy.io/server/v3/pkg/agent/proxy/integrations"
	ioutil "go.keploy.io/server/v3/pkg/agent/proxy/integrations/util"
	syncMock "go.keploy.io/server/v3/pkg/agent/proxy/syncMock"
	"go.keploy.io/server/v3/pkg/agent/proxy/util"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

func init() {
	integrations.Register(integrations.REDIS, &integrations.Parsers{
		Initializer: New,
		Priority:    90,
	})
}

// Redis is a RESP parser for Redis traffic.
type Redis struct {
	logger *zap.Logger
}

// New creates a Redis parser.
func New(logger *zap.Logger) integrations.Integrations {
	return &Redis{logger: logger}
}

// MatchType detects RESP array commands used by Redis clients.
func (r *Redis) MatchType(_ context.Context, reqBuf []byte) bool {
	cmd, ok := parseRESPCommand(reqBuf)
	if !ok {
		return false
	}
	switch strings.ToUpper(cmd) {
	case "AUTH", "HELLO", "PING", "SELECT", "CLIENT", "INFO", "CONFIG", "COMMAND", "GET", "SET", "DEL", "EXISTS", "EXPIRE", "TTL", "HGET", "HSET", "HDEL", "HGETALL", "LPUSH", "RPUSH", "LPOP", "RPOP", "SADD", "SREM", "SMEMBERS", "ZADD", "ZREM", "ZRANGE", "INCR", "DECR", "MGET", "MSET", "EVAL", "EVALSHA", "SUBSCRIBE", "PSUBSCRIBE", "UNSUBSCRIBE", "RESET", "QUIT":
		return true
	default:
		return false
	}
}

// RecordOutgoing records request/response RESP frames while forwarding them.
func (r *Redis) RecordOutgoing(ctx context.Context, session *integrations.RecordSession) error {
	reqBuf, err := util.ReadInitialBuf(ctx, session.Logger, session.Ingress)
	if err != nil {
		return fmt.Errorf("failed to read redis request: %w", err)
	}

	req, err := readRESPFrame(ctx, session.Ingress, reqBuf)
	if err != nil {
		return fmt.Errorf("failed to read redis request frame: %w", err)
	}
	reqAt := models.CapturedReqTime(ctx)

	if _, err := session.Egress.Write(req); err != nil {
		return fmt.Errorf("failed to forward redis request: %w", err)
	}

	resp, err := readRESPFrame(ctx, session.Egress, nil)
	if err != nil {
		return fmt.Errorf("failed to read redis response frame: %w", err)
	}
	respAt := models.CapturedRespTime(ctx)

	if _, err := session.Ingress.Write(resp); err != nil {
		return fmt.Errorf("failed to forward redis response: %w", err)
	}

	r.recordMock(ctx, req, resp, reqAt, respAt)
	return forwardRESP(ctx, session.Ingress, session.Egress, func(req, resp []byte, reqAt, respAt time.Time) {
		r.recordMock(ctx, req, resp, reqAt, respAt)
	})
}

// MockOutgoing replays recorded RESP responses by exact request match.
func (r *Redis) MockOutgoing(ctx context.Context, src net.Conn, _ *models.ConditionalDstCfg, mockDb integrations.MockMemDb, _ models.OutgoingOptions) error {
	reqBuf, err := util.ReadInitialBuf(ctx, r.logger, src)
	if err != nil {
		return fmt.Errorf("failed to read redis request: %w", err)
	}
	req, err := readRESPFrame(ctx, src, reqBuf)
	if err != nil {
		return fmt.Errorf("failed to read redis request frame: %w", err)
	}
	for {
		resp, ok, err := r.match(ctx, req, mockDb)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("redis mock not found for command %q", commandName(req))
		}
		if _, err := src.Write(resp); err != nil {
			return fmt.Errorf("failed to write redis response: %w", err)
		}

		req, err = readRESPFrame(ctx, src, nil)
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to read redis request frame: %w", err)
		}
	}
}

func (r *Redis) recordMock(ctx context.Context, req, resp []byte, reqAt, respAt time.Time) {
	metadata := map[string]string{
		"type":    redisMockType(req),
		"command": commandName(req),
	}
	if connID, ok := ctx.Value(models.ClientConnectionIDKey).(string); ok {
		metadata["connID"] = connID
	}
	mock := &models.Mock{
		Version: models.GetVersion(),
		Name:    "mocks",
		Kind:    models.REDIS,
		Spec: models.MockSpec{
			Metadata:         metadata,
			GenericRequests:  []models.Payload{encodePayload(req, models.FromClient)},
			GenericResponses: []models.Payload{encodePayload(resp, models.FromServer)},
			ReqTimestampMock: reqAt,
			ResTimestampMock: respAt,
		},
	}
	mock.DeriveLifetime()
	if mgr := syncMock.Get(); mgr != nil {
		mgr.AddMock(mock)
	}
}

func (r *Redis) match(ctx context.Context, req []byte, mockDb integrations.MockMemDb) ([]byte, bool, error) {
	perTest, err := mockDb.GetPerTestMocksInWindow()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get redis per-test mocks: %w", err)
	}
	session, err := mockDb.GetSessionMocks()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get redis session mocks: %w", err)
	}
	pool := append([]*models.Mock{}, perTest...)
	pool = append(pool, session...)
	for _, mock := range pool {
		if mock == nil || mock.Kind != models.REDIS || len(mock.Spec.GenericRequests) == 0 || len(mock.Spec.GenericResponses) == 0 {
			continue
		}
		got, ok := decodePayload(mock.Spec.GenericRequests[0])
		if !ok || !bytes.Equal(got, req) {
			continue
		}
		resp, ok := decodePayload(mock.Spec.GenericResponses[0])
		if !ok {
			continue
		}
		if mock.TestModeInfo.Lifetime == models.LifetimePerTest {
			mockDb.DeleteFilteredMock(*mock)
		} else {
			updated := *mock
			updated.TestModeInfo.SortOrder = pkg.GetNextSortNum()
			mockDb.UpdateUnFilteredMock(mock, &updated)
		}
		return resp, true, nil
	}
	return nil, false, nil
}

func forwardRESP(ctx context.Context, client, server net.Conn, record func(req, resp []byte, reqAt, respAt time.Time)) error {
	for {
		reqAt := models.CapturedReqTime(ctx)
		req, err := readRESPFrame(ctx, client, nil)
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if _, err := server.Write(req); err != nil {
			return err
		}
		resp, err := readRESPFrame(ctx, server, nil)
		if err != nil {
			return err
		}
		respAt := models.CapturedRespTime(ctx)
		if _, err := client.Write(resp); err != nil {
			return err
		}
		record(req, resp, reqAt, respAt)
	}
}

func readRESPFrame(ctx context.Context, conn net.Conn, initial []byte) ([]byte, error) {
	buf := append([]byte(nil), initial...)
	tmp := make([]byte, 4096)
	for {
		if n, ok := respFrameLen(buf); ok {
			return buf[:n], nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if len(buf) > 0 {
				if n, ok := respFrameLen(buf); ok {
					return buf[:n], nil
				}
			}
			return nil, err
		}
	}
}

func respFrameLen(buf []byte) (int, bool) {
	if len(buf) == 0 {
		return 0, false
	}
	return respValueLen(buf, 0)
}

func respValueLen(buf []byte, pos int) (int, bool) {
	if pos >= len(buf) {
		return 0, false
	}
	switch buf[pos] {
	case '+', '-', ':':
		end := bytes.Index(buf[pos:], []byte("\r\n"))
		if end < 0 {
			return 0, false
		}
		return pos + end + 2, true
	case '$':
		lineEnd := bytes.Index(buf[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			return 0, false
		}
		n, err := strconv.Atoi(string(buf[pos+1 : pos+lineEnd]))
		if err != nil {
			return 0, false
		}
		if n < 0 {
			return pos + lineEnd + 2, true
		}
		end := pos + lineEnd + 2 + n + 2
		return end, len(buf) >= end
	case '*':
		lineEnd := bytes.Index(buf[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			return 0, false
		}
		count, err := strconv.Atoi(string(buf[pos+1 : pos+lineEnd]))
		if err != nil {
			return 0, false
		}
		next := pos + lineEnd + 2
		for i := 0; i < count; i++ {
			n, ok := respValueLen(buf, next)
			if !ok {
				return 0, false
			}
			next = n
		}
		return next, true
	default:
		end := bytes.Index(buf[pos:], []byte("\r\n"))
		if end < 0 {
			return 0, false
		}
		return pos + end + 2, true
	}
}

func parseRESPCommand(buf []byte) (string, bool) {
	if len(buf) == 0 {
		return "", false
	}
	if buf[0] != '*' {
		line := string(buf)
		if i := strings.IndexAny(line, " \r\n"); i > 0 {
			return line[:i], true
		}
		return "", false
	}
	firstBulk := bytes.Index(buf, []byte("\r\n$"))
	if firstBulk < 0 {
		return "", false
	}
	lenStart := firstBulk + 3
	lenEnd := bytes.Index(buf[lenStart:], []byte("\r\n"))
	if lenEnd < 0 {
		return "", false
	}
	n, err := strconv.Atoi(string(buf[lenStart : lenStart+lenEnd]))
	if err != nil || n < 0 {
		return "", false
	}
	start := lenStart + lenEnd + 2
	if len(buf) < start+n {
		return "", false
	}
	return string(buf[start : start+n]), true
}

func commandName(req []byte) string {
	cmd, _ := parseRESPCommand(req)
	return strings.ToUpper(cmd)
}

func redisMockType(req []byte) string {
	switch commandName(req) {
	case "AUTH", "HELLO", "SELECT", "CLIENT", "INFO", "CONFIG", "COMMAND", "SUBSCRIBE", "PSUBSCRIBE", "UNSUBSCRIBE", "RESET":
		return "config"
	default:
		return "mocks"
	}
}

func encodePayload(buf []byte, origin models.OriginType) models.Payload {
	data := string(buf)
	typ := models.String
	if !ioutil.IsASCII(data) {
		data = ioutil.EncodeBase64(buf)
		typ = "binary"
	}
	return models.Payload{Origin: origin, Message: []models.OutputBinary{{Type: typ, Data: data}}}
}

func decodePayload(p models.Payload) ([]byte, bool) {
	if len(p.Message) == 0 {
		return nil, false
	}
	msg := p.Message[0]
	if msg.Type == "binary" {
		b, err := ioutil.DecodeBase64(msg.Data)
		return b, err == nil
	}
	return []byte(msg.Data), true
}
