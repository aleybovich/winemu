package win

import (
	"testing"
)

func TestGetUserName(t *testing.T) {
	h := newTestEmu(t)
	user := h.E.fs.user
	n := h.alloc(4)
	secExpectFail(t, h, "GetUserNameW probe", h.call(dAdv, "GetUserNameW", 0, n), errInsufficientBuf)
	if h.r32(n) != uint32(len(user)+1) {
		t.Fatalf("probe size %d, want %d", h.r32(n), len(user)+1)
	}
	buf := h.alloc(2 * len(user))
	h.w32(n, uint32(len(user))) // no room for the NUL
	secExpectFail(t, h, "GetUserNameW exact", h.call(dAdv, "GetUserNameW", buf, n), errInsufficientBuf)
	buf = h.alloc(2*len(user) + 2)
	if h.call(dAdv, "GetUserNameW", buf, n) != 1 || h.readWStr(buf) != user || h.r32(n) != uint32(len(user)+1) {
		t.Fatalf("GetUserNameW = %q size %d", h.readWStr(buf), h.r32(n))
	}
	h.w32(n, 64)
	if h.call(dAdv, "GetUserNameA", buf, n) != 1 || h.readAStr(buf) != user {
		t.Fatalf("GetUserNameA = %q", h.readAStr(buf))
	}
	secExpectFail(t, h, "GetUserNameW(size NULL)", h.call(dAdv, "GetUserNameW", buf, 0), errInvalidParameter)
}

func TestGetUserNameEx(t *testing.T) {
	h := newTestEmu(t)
	sam := secComputerName + `\` + h.E.fs.user
	n, buf := h.alloc(4), h.alloc(256)
	secExpectFail(t, h, "GetUserNameExW probe", h.call("secur32.dll", "GetUserNameExW", nameSamCompatible, 0, n), errMoreData)
	if h.r32(n) != uint32(len(sam)+1) {
		t.Fatalf("probe size %d", h.r32(n))
	}
	if h.call("secur32.dll", "GetUserNameExW", nameSamCompatible, buf, n) != 1 || h.readWStr(buf) != sam || h.r32(n) != uint32(len(sam)) {
		t.Fatalf("GetUserNameExW = %q size %d", h.readWStr(buf), h.r32(n))
	}
	h.w32(n, 128)
	if h.call("secur32.dll", "GetUserNameExA", nameDisplay, buf, n) != 1 || h.readAStr(buf) != h.E.fs.user {
		t.Fatalf("GetUserNameExA(NameDisplay) = %q", h.readAStr(buf))
	}
	h.w32(n, 128)
	secExpectFail(t, h, "NameUserPrincipal", h.call("secur32.dll", "GetUserNameExW", 8, buf, n), errNoneMapped)
	secExpectFail(t, h, "NameUnknown", h.call("secur32.dll", "GetUserNameExW", 0, buf, n), errInvalidParameter)
}

func TestTranslateName(t *testing.T) {
	h := newTestEmu(t)
	sam := h.wstr(secComputerName + `\` + h.E.fs.user)
	n, buf := h.alloc(4), h.alloc(256)
	secExpectFail(t, h, "TranslateNameW probe", h.call("secur32.dll", "TranslateNameW", sam, nameSamCompatible, nameDisplay, 0, n), errInsufficientBuf)
	if h.r32(n) != uint32(len(h.E.fs.user)+1) {
		t.Fatalf("probe size %d", h.r32(n))
	}
	if h.call("secur32.dll", "TranslateNameW", sam, nameSamCompatible, nameDisplay, buf, n) != 1 || h.readWStr(buf) != h.E.fs.user {
		t.Fatalf("TranslateNameW = %q", h.readWStr(buf))
	}
	h.w32(n, 128)
	if h.call("secur32.dll", "TranslateNameA", h.astr(`.\`+h.E.fs.user), nameSamCompatible, nameSamCompatible, buf, n) != 1 ||
		h.readAStr(buf) != secComputerName+`\`+h.E.fs.user {
		t.Fatalf("TranslateNameA = %q", h.readAStr(buf))
	}
	secExpectFail(t, h, "TranslateNameW(unknown)", h.call("secur32.dll", "TranslateNameW", h.wstr(`WINEMU\nobody`), nameSamCompatible, nameDisplay, buf, n), errNoneMapped)
	secExpectFail(t, h, "TranslateNameW(NULL)", h.call("secur32.dll", "TranslateNameW", 0, nameSamCompatible, nameDisplay, buf, n), errInvalidParameter)
}

func TestLookupAccountSid(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	tu, _ := secTokenInfo(t, h, tok, secTokenUserCls)
	usid := h.r64(tu)
	cn, cd, use := h.alloc(4), h.alloc(4), h.alloc(4)
	secExpectFail(t, h, "LookupAccountSidW probe", h.call(dAdv, "LookupAccountSidW", 0, usid, 0, cn, 0, cd, use), errInsufficientBuf)
	user := h.E.fs.user
	if h.r32(cn) != uint32(len(user)+1) || h.r32(cd) != uint32(len(secComputerName)+1) {
		t.Fatalf("probe sizes %d/%d", h.r32(cn), h.r32(cd))
	}
	name, dom := h.alloc(2*int(h.r32(cn))), h.alloc(2*int(h.r32(cd)))
	if h.call(dAdv, "LookupAccountSidW", 0, usid, name, cn, dom, cd, use) != 1 {
		t.Fatalf("LookupAccountSidW failed, lastError %d", h.lastError())
	}
	if h.readWStr(name) != user || h.readWStr(dom) != secComputerName || h.r32(use) != sidTypeUser || h.r32(cn) != uint32(len(user)) {
		t.Fatalf("LookupAccountSidW = %q %q use %d", h.readWStr(name), h.readWStr(dom), h.r32(use))
	}
	// primary group (from the token) and a well-known group with an empty domain
	pg, _ := secTokenInfo(t, h, tok, 5)
	h.w32(cn, 64)
	h.w32(cd, 64)
	name, dom = h.alloc(128), h.alloc(128)
	if h.call(dAdv, "LookupAccountSidA", h.astr(secComputerName), h.r64(pg), name, cn, dom, cd, use) != 1 || h.readAStr(name) != "None" || h.r32(use) != sidTypeGroup {
		t.Fatalf("LookupAccountSidA(primary group) = %q use %d", h.readAStr(name), h.r32(use))
	}
	h.w32(cn, 64)
	h.w32(cd, 64)
	if h.call(dAdv, "LookupAccountSidW", 0, secSid(t, h, "S-1-1-0"), name, cn, dom, cd, use) != 1 || h.readWStr(name) != "Everyone" || h.readWStr(dom) != "" || h.r32(use) != sidTypeWellKnownGroup {
		t.Fatalf("Everyone = %q %q %d", h.readWStr(name), h.readWStr(dom), h.r32(use))
	}
	secExpectFail(t, h, "unknown SID", h.call(dAdv, "LookupAccountSidW", 0, secSid(t, h, "S-1-5-21-1-2-3-4"), name, cn, dom, cd, use), errNoneMapped)
	secExpectFail(t, h, "invalid SID", h.call(dAdv, "LookupAccountSidW", 0, 0, name, cn, dom, cd, use), errInvalidSid)
}

func TestLookupAccountName(t *testing.T) {
	h := newTestEmu(t)
	user := h.E.fs.user
	cb, cd, use := h.alloc(4), h.alloc(4), h.alloc(4)
	secExpectFail(t, h, "LookupAccountNameW probe", h.call(dAdv, "LookupAccountNameW", 0, h.wstr(user), 0, cb, 0, cd, use), errInsufficientBuf)
	if h.r32(cb) != 28 || h.r32(cd) != uint32(len(secComputerName)+1) {
		t.Fatalf("probe sizes %d/%d", h.r32(cb), h.r32(cd))
	}
	sidBuf, dom := h.alloc(64), h.alloc(128)
	for _, c := range []struct {
		name, sid string
		use       uint32
	}{
		{user, sidUserAccount.String(), sidTypeUser},
		{secComputerName + `\` + user, sidUserAccount.String(), sidTypeUser},
		{`.\` + user, sidUserAccount.String(), sidTypeUser},
		{"winemu", sidMachineDomain.String(), sidTypeDomain},
		{`BUILTIN\Administrators`, "S-1-5-32-544", sidTypeAlias},
		{"everyone", "S-1-1-0", sidTypeWellKnownGroup},
	} {
		h.w32(cb, 64)
		h.w32(cd, 64)
		if h.call(dAdv, "LookupAccountNameW", 0, h.wstr(c.name), sidBuf, cb, dom, cd, use) != 1 || secSidStr(h, sidBuf) != c.sid || h.r32(use) != c.use {
			t.Fatalf("LookupAccountNameW(%q) = %q use %d, lastError %d", c.name, secSidStr(h, sidBuf), h.r32(use), h.lastError())
		}
	}
	h.w32(cb, 64)
	h.w32(cd, 64)
	if h.call(dAdv, "LookupAccountNameA", 0, h.astr(user), sidBuf, cb, dom, cd, use) != 1 || h.readAStr(dom) != secComputerName || h.r32(cd) != uint32(len(secComputerName)) {
		t.Fatalf("LookupAccountNameA domain %q size %d", h.readAStr(dom), h.r32(cd))
	}
	secExpectFail(t, h, "unknown name", h.call(dAdv, "LookupAccountNameW", 0, h.wstr("nobody-here"), sidBuf, cb, dom, cd, use), errNoneMapped)
	secExpectFail(t, h, "wrong domain", h.call(dAdv, "LookupAccountNameW", 0, h.wstr(`OTHER\`+user), sidBuf, cb, dom, cd, use), errNoneMapped)
	h.w32(cb, 27)
	secExpectFail(t, h, "SID buffer 27", h.call(dAdv, "LookupAccountNameW", 0, h.wstr(user), sidBuf, cb, dom, cd, use), errInsufficientBuf)
}

func TestNetUserGetInfo(t *testing.T) {
	h := newTestEmu(t)
	const netapi = "netapi32.dll"
	user := h.wstr(h.E.fs.user)
	out := h.alloc(8)
	// USER_INFO_4 (x64): full_name @64, user_sid @152, primary_group_id @160
	if r := h.call(netapi, "NetUserGetInfo", 0, user, 4, out); r != 0 {
		t.Fatalf("NetUserGetInfo(4) = %d", r)
	}
	b := h.r64(out)
	if h.readWStr(h.r64(b)) != h.E.fs.user || h.readWStr(h.r64(b+64)) != h.E.fs.user ||
		secSidStr(h, h.r64(b+152)) != sidUserAccount.String() || h.r32(b+160) != ridNone || h.r64(b+8) != 0 {
		t.Fatalf("USER_INFO_4 name %q full %q sid %q pgid %d", h.readWStr(h.r64(b)), h.readWStr(h.r64(b+64)), secSidStr(h, h.r64(b+152)), h.r32(b+160))
	}
	if h.call(netapi, "NetApiBufferFree", b) != 0 {
		t.Fatal("NetApiBufferFree")
	}
	// USER_INFO_10: name, comment, usr_comment, full_name @24; server given as \\COMPUTER
	if r := h.call(netapi, "NetUserGetInfo", h.wstr(`\\`+secComputerName), user, 10, out); r != 0 || h.readWStr(h.r64(h.r64(out)+24)) != h.E.fs.user {
		t.Fatalf("NetUserGetInfo(10) = %d", r)
	}
	// USER_INFO_20: flags @24, user_id @28
	if r := h.call(netapi, "NetUserGetInfo", 0, user, 20, out); r != 0 || h.r32(h.r64(out)+28) != ridUser {
		t.Fatalf("NetUserGetInfo(20) = %d rid %d", r, h.r32(h.r64(out)+28))
	}
	for _, lvl := range []uint64{0, 1, 23} {
		if r := h.call(netapi, "NetUserGetInfo", 0, user, lvl, out); r != 0 || h.readWStr(h.r64(h.r64(out))) != h.E.fs.user {
			t.Fatalf("NetUserGetInfo(%d) = %d", lvl, r)
		}
	}
	if r := h.call(netapi, "NetUserGetInfo", 0, h.wstr("nobody-here"), 10, out); r != nerrUserNotFound {
		t.Fatalf("unknown user = %d, want %d", r, nerrUserNotFound)
	}
	if r := h.call(netapi, "NetUserGetInfo", 0, h.wstr("Everyone"), 10, out); r != nerrUserNotFound {
		t.Fatalf("group as user = %d", r)
	}
	if r := h.call(netapi, "NetUserGetInfo", 0, user, 5, out); r != errInvalidLevel {
		t.Fatalf("level 5 = %d, want %d", r, errInvalidLevel)
	}
	if r := h.call(netapi, "NetUserGetInfo", h.wstr(`\\OTHERHOST`), user, 10, out); r != errBadNetPath {
		t.Fatalf("remote server = %d", r)
	}
	if r := h.call(netapi, "NetApiBufferFree", 0); r != 0 {
		t.Fatalf("NetApiBufferFree(NULL) = %d", r)
	}
}

func TestNetGetJoinInformation(t *testing.T) {
	h := newTestEmu(t)
	name, status := h.alloc(8), h.alloc(4)
	if r := h.call("netapi32.dll", "NetGetJoinInformation", 0, name, status); r != 0 || h.readWStr(h.r64(name)) != workgroupName || h.r32(status) != 2 {
		t.Fatalf("NetGetJoinInformation = %d %q status %d", r, h.readWStr(h.r64(name)), h.r32(status))
	}
	if r := h.call("netapi32.dll", "NetGetJoinInformation", 0, 0, status); r != errInvalidParameter {
		t.Fatalf("NULL out = %d", r)
	}
}

func TestProfileDirectories(t *testing.T) {
	h := newTestEmu(t)
	env := h.alloc(512)
	if h.call(dK32, "GetEnvironmentVariableW", h.wstr("USERPROFILE"), env, 256) == 0 {
		t.Fatal("USERPROFILE not set")
	}
	tok := secOpenProcessToken(t, h)
	n := h.alloc(4)
	secExpectFail(t, h, "GetUserProfileDirectoryW probe", h.call("userenv.dll", "GetUserProfileDirectoryW", tok, 0, n), errInsufficientBuf)
	want := h.readWStr(env)
	if h.r32(n) != uint32(len(want)+1) {
		t.Fatalf("probe size %d, want %d", h.r32(n), len(want)+1)
	}
	buf := h.alloc(2 * int(h.r32(n)))
	if h.call("userenv.dll", "GetUserProfileDirectoryW", tok, buf, n) != 1 || h.readWStr(buf) != want {
		t.Fatalf("GetUserProfileDirectoryW = %q, USERPROFILE %q", h.readWStr(buf), want)
	}
	h.w32(n, 256)
	if h.call("userenv.dll", "GetUserProfileDirectoryA", secProcessToken, buf, n) != 1 || h.readAStr(buf) != want {
		t.Fatalf("GetUserProfileDirectoryA = %q", h.readAStr(buf))
	}
	secExpectFail(t, h, "GetUserProfileDirectoryW(bad token)", h.call("userenv.dll", "GetUserProfileDirectoryW", 0x7777, buf, n), errInvalidHandle)
	h.w32(n, 3)
	secExpectFail(t, h, "GetProfilesDirectoryW small", h.call("userenv.dll", "GetProfilesDirectoryW", buf, n), errInsufficientBuf)
	if h.call("userenv.dll", "GetProfilesDirectoryW", buf, n) != 1 || h.readWStr(buf)+`\`+h.E.fs.user != want {
		t.Fatalf("GetProfilesDirectoryW = %q", h.readWStr(buf))
	}
}
