package trojan

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// FastUP nodes are provisioned as "<uuid>" plus a salt; the user deliberately
// does not use the vendor's "#fastup" suffix. This locks the resulting key to
// the vendor formula hex(md5(password + salt)) so a later refactor cannot
// silently change what the servers expect.
func TestDerivePasswordFastupWithoutSuffix(t *testing.T) {
	const (
		uuid = "3ab9e5b8-3d07-4e0d-98e2-adfa99f2259f"
		salt = "nya20241209"
	)
	got := DerivePassword(uuid, salt)
	sum := md5.Sum([]byte(uuid + salt))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("DerivePassword(%q, %q) = %q, want %q", uuid, salt, got, want)
	}
	if len(got) != 32 {
		t.Fatalf("derived password must be 32 hex characters, got %d", len(got))
	}
}

// The vendor suffix must never reach this implementation: it would be hashed
// together with the salt and produce a key no server accepts. Keeping the
// assertion makes that mistake impossible to reintroduce silently.
func TestDerivePasswordSuffixInPasswordChangesTheKey(t *testing.T) {
	const (
		uuid = "3ab9e5b8-3d07-4e0d-98e2-adfa99f2259f"
		salt = "nya20241209"
	)
	bare := DerivePassword(uuid, salt)
	suffixed := DerivePassword(uuid+"#fastup", salt)
	if bare == suffixed {
		t.Fatal(`a "#fastup" suffix inside the password must change the derived key`)
	}
	if suffixed == DerivePassword(uuid+"#fastup", "") {
		t.Fatal("a suffixed password must not be treated as an ordinary Trojan password")
	}
}

// No salt means ordinary Trojan: the password passes through untouched, so
// non-FastUP nodes keep working with this build.
func TestDerivePasswordWithoutSaltIsPassThrough(t *testing.T) {
	const ordinary = "ordinary-trojan-password"
	if got := DerivePassword(ordinary, ""); got != ordinary {
		t.Fatalf("DerivePassword(%q, \"\") = %q, want the password unchanged", ordinary, got)
	}
}
