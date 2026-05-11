package redis

import "testing"

func TestRESPFrameLenArrayCommand(t *testing.T) {
	frame := []byte("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\nextra")
	n, ok := respFrameLen(frame)
	if !ok {
		t.Fatal("expected complete RESP frame")
	}
	if got, want := string(frame[:n]), "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"; got != want {
		t.Fatalf("frame = %q, want %q", got, want)
	}
}

func TestParseRESPCommand(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "array", in: "*2\r\n$3\r\nSET\r\n$1\r\nk\r\n", want: "SET", ok: true},
		{name: "inline", in: "PING\r\n", want: "PING", ok: true},
		{name: "partial", in: "*1\r\n$4\r\nPIN", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRESPCommand([]byte(tc.in))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("command = %q, want %q", got, tc.want)
			}
		})
	}
}
