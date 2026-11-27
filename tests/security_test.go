package tests

import (
	"strings"
	"testing"
)

// os/user under winemu (testdata/src/go/security_user): user.Current,
// user.LookupId and user.LookupGroupId must succeed and agree with each other,
// with GetUserNameW and with USERPROFILE.
func TestSecurityGoUser(t *testing.T) {
	r := runGuest(t, "security_user.exe", guestOpts{})
	if r.Code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
	kv := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		k, v, _ := strings.Cut(strings.TrimRight(l, "\r"), "=")
		kv[k] = v
	}
	name := kv["GetUserNameW"]
	if name == "" || strings.HasPrefix(name, "ERR:") {
		t.Fatalf("GetUserNameW = %q", name)
	}
	if got := kv["current.Username"]; !strings.HasSuffix(got, `\`+name) || strings.Count(got, `\`) != 1 {
		t.Fatalf("current.Username = %q, want DOMAIN\\%s", got, name)
	}
	if uid := kv["current.Uid"]; !strings.HasPrefix(uid, "S-1-5-21-") {
		t.Fatalf("current.Uid = %q, want a machine account SID", uid)
	}
	if gid := kv["current.Gid"]; !strings.HasPrefix(gid, "S-1-5-") || gid == kv["current.Uid"] {
		t.Fatalf("current.Gid = %q", gid)
	}
	if home := kv["current.HomeDir"]; home == "" || !strings.EqualFold(home, kv["USERPROFILE"]) {
		t.Fatalf("current.HomeDir = %q, USERPROFILE = %q", home, kv["USERPROFILE"])
	}
	if kv["current.Name"] == "" {
		t.Fatal("current.Name is empty")
	}
	for _, f := range []string{"Username", "Uid", "Gid", "HomeDir", "Name"} {
		if kv["lookup."+f] != kv["current."+f] {
			t.Fatalf("LookupId(%s).%s = %q, Current().%s = %q", kv["current.Uid"], f, kv["lookup."+f], f, kv["current."+f])
		}
	}
	if kv["group.Name"] == "" {
		t.Fatalf("LookupGroupId(%s) name is empty", kv["current.Gid"])
	}
}
