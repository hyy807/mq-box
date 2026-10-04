package aha

import "testing"

func TestPersistentTokenPolicy(t *testing.T) {
	cases := []struct {
		value map[string]any
		want  string
	}{
		{map[string]any{"token": "session"}, ""},
		{map[string]any{"token": map[string]any{"token": "persistent"}}, "persistent"},
		{map[string]any{"access": map[string]any{"token": "persistent"}}, "persistent"},
		{map[string]any{"data": map[string]any{"access_token": "persistent"}}, "persistent"},
	}
	for _, c := range cases {
		if got := accessToken(c.value); got != c.want {
			t.Fatalf("got %q want %q", got, c.want)
		}
	}
}
