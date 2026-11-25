package dnsx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newFake(t *testing.T, cidr, upstream string) *Fake {
	t.Helper()
	f, err := NewFake(cidr, upstream)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNewFake(t *testing.T) {
	for _, cidr := range []string{"", "198.18.0.0", "x/8", "fd00::/8", "198.18.0.0/31", "10.0.0.0/7"} {
		if _, err := NewFake(cidr, "127.0.0.1:53"); err == nil {
			t.Errorf("range %q was accepted", cidr)
		}
	}
	if _, err := NewFake("198.18.0.0/15", "127.0.0.1"); err == nil {
		t.Error("an upstream without a port was accepted")
	}
	f := newFake(t, "198.18.5.7/16", "127.0.0.1:53")
	if f.Range() != netip.MustParsePrefix("198.18.0.0/16") {
		t.Errorf("Range() = %v, want the masked network", f.Range())
	}
	if f.Addr() != nil {
		t.Error("Addr() is set although the server is not listening")
	}
	if f.Upstream() != "127.0.0.1:53" {
		t.Errorf("Upstream() = %q", f.Upstream())
	}
}

func TestAssignAndLookup(t *testing.T) {
	f := newFake(t, "198.18.0.0/15", "127.0.0.1:53")
	a := f.Assign("www.example.com")
	if a != netip.MustParseAddr("198.18.0.1") {
		t.Errorf("first placeholder = %v, want the first host address", a)
	}
	if again := f.Assign("WWW.Example.COM."); again != a {
		t.Errorf("the same name got a second placeholder: %v and %v", a, again)
	}
	b := f.Assign("api.example.com")
	if b == a {
		t.Error("two names share one placeholder")
	}
	if name, ok := f.Lookup(a); !ok || name != "www.example.com" {
		t.Errorf("Lookup(%v) = %q, %v", a, name, ok)
	}
	if name, ok := f.Lookup(netip.MustParseAddr("::ffff:198.18.0.2")); !ok || name != "api.example.com" {
		t.Errorf("Lookup of the IPv4-mapped form = %q, %v", name, ok)
	}
	if _, ok := f.Lookup(netip.MustParseAddr("198.18.9.9")); ok {
		t.Error("Lookup knows an address nobody was given")
	}
	for addr, want := range map[string]bool{
		"198.18.0.1": true, "198.19.255.255": true, "::ffff:198.18.0.1": true,
		"198.20.0.0": false, "198.17.255.255": false, "2001:db8::1": false,
	} {
		if got := f.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestPoolRecycles(t *testing.T) {
	f := newFake(t, "198.18.0.0/30", "127.0.0.1:53") // two usable addresses
	one, two := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	if a, b := f.Assign("a.example"), f.Assign("b.example"); a != one || b != two {
		t.Fatalf("got %v and %v", a, b)
	}
	// The pool is full: the oldest mapping makes room.
	if c := f.Assign("c.example"); c != one {
		t.Fatalf("third name got %v, want the recycled %v", c, one)
	}
	if name, _ := f.Lookup(one); name != "c.example" {
		t.Errorf("Lookup(%v) = %q after recycling", one, name)
	}
	// "a.example" lost its address and gets a new one, never the old mapping.
	if a := f.Assign("a.example"); a != two {
		t.Errorf("a.example got %v, want %v", a, two)
	}
	if name, _ := f.Lookup(two); name != "a.example" {
		t.Errorf("Lookup(%v) = %q", two, name)
	}
	// Network and broadcast address are never handed out.
	for i := 0; i < 20; i++ {
		if ip := f.Assign(strings.Repeat("x", i+1) + ".example"); ip != one && ip != two {
			t.Fatalf("placeholder %v is outside the usable range", ip)
		}
	}
	if n := len(f.byName); n != 2 {
		t.Errorf("%d names are remembered for 2 addresses", n)
	}
}

// query builds a standard DNS query with one question.
func query(id uint16, name string, qtype uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func exchange(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return buf[:n]
}

func listen(t *testing.T, f *Fake) string {
	t.Helper()
	if err := f.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f.Addr().String()
}

func TestServeAnswersWithPlaceholders(t *testing.T) {
	f := newFake(t, "198.18.0.0/15", "127.0.0.1:9")
	f.Dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("a query the server can answer itself went upstream")
		return nil, errors.New("no upstream in this test")
	}
	addr := listen(t, f)

	q := query(0xBEEF, "Shop.Example.com", typeA)
	r := exchange(t, addr, q)
	if len(r) != len(q)+16 {
		t.Fatalf("reply is %d bytes, want %d", len(r), len(q)+16)
	}
	if id := binary.BigEndian.Uint16(r); id != 0xBEEF {
		t.Errorf("reply id %#x", id)
	}
	if r[2]&0x80 == 0 || r[2]&0x01 == 0 || r[3] != 0x80 {
		t.Errorf("flags %#02x %#02x: want a response with RD and RA and no error", r[2], r[3])
	}
	if qd, an := binary.BigEndian.Uint16(r[4:]), binary.BigEndian.Uint16(r[6:]); qd != 1 || an != 1 {
		t.Errorf("%d questions and %d answers", qd, an)
	}
	if !bytes.Equal(r[12:len(q)], q[12:]) {
		t.Error("the question is not echoed")
	}
	ans := r[len(q):]
	if !bytes.Equal(ans[:12], []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4}) {
		t.Errorf("answer record header % x", ans[:12])
	}
	ip := netip.AddrFrom4([4]byte(ans[12:16]))
	if name, ok := f.Lookup(ip); !ok || name != "shop.example.com" {
		t.Errorf("the answer %v maps back to %q, %v", ip, name, ok)
	}

	// No AAAA and no HTTPS records, so that clients stay on the placeholder.
	for _, qtype := range []uint16{typeAAAA, typeHTTPS} {
		q := query(7, "shop.example.com", qtype)
		r := exchange(t, addr, q)
		if len(r) != len(q) || r[3]&0x0F != 0 || binary.BigEndian.Uint16(r[6:]) != 0 {
			t.Errorf("type %d: want an empty NOERROR reply, got % x", qtype, r)
		}
	}
}

func TestServeForwardsTheRest(t *testing.T) {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	seen := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			name, _, _, _ := parseQuestion(buf[:n])
			seen <- name
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			reply[3] = 0x83 // NXDOMAIN: easy to tell from our own answers
			_, _ = up.WriteTo(reply, from)
		}
	}()

	f := newFake(t, "198.18.0.0/15", up.LocalAddr().String())
	var dials atomic.Int32
	f.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	addr := listen(t, f)

	cases := []struct {
		name  string
		qtype uint16
	}{
		{"printer.local", typeA},       // local names keep resolving for real
		{"nas.lan", typeA},             //
		{"router", typeA},              // single-label name
		{"1.0.0.127.in-addr.arpa", 12}, // PTR
		{"mail.example.com", 15},       // MX
		{"example.com", 16},            // TXT
		{"db.corp.internal", typeAAAA}, //
	}
	for i, c := range cases {
		r := exchange(t, addr, query(uint16(i+1), c.name, c.qtype))
		if r[3]&0x0F != 3 {
			t.Errorf("%s type %d: the upstream reply was not passed on: % x", c.name, c.qtype, r)
		}
		select {
		case got := <-seen:
			if got != c.name {
				t.Errorf("upstream saw %q, want %q", got, c.name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing reached the upstream server", c.name)
		}
	}
	if int(dials.Load()) != len(cases) {
		t.Errorf("the Dial hook was used %d times for %d queries", dials.Load(), len(cases))
	}
	if n := len(f.byName); n != 0 {
		t.Errorf("%d placeholders were handed out for forwarded names", n)
	}
}

func TestParseQuestionRejectsGarbage(t *testing.T) {
	good := query(1, "www.example.com", typeA)
	if name, qtype, end, ok := parseQuestion(good); !ok || name != "www.example.com" || qtype != typeA || end != len(good) {
		t.Fatalf("parseQuestion(good) = %q, %d, %d, %v", name, qtype, end, ok)
	}
	bad := map[string][]byte{
		"empty":         nil,
		"short header":  good[:11],
		"cut in a name": good[:20],
		"no type":       good[:len(good)-4],
	}
	response := append([]byte(nil), good...)
	response[2] |= 0x80
	bad["a response"] = response
	twoQuestions := append([]byte(nil), good...)
	twoQuestions[5] = 2
	bad["two questions"] = twoQuestions
	chaos := append([]byte(nil), good...)
	chaos[len(chaos)-1] = 3 // class CH
	bad["class CHAOS"] = chaos
	longLabel := append([]byte(nil), good...)
	longLabel[12] = 0xC0 // compression pointer where a label is expected
	bad["compression pointer"] = longLabel
	for name, q := range bad {
		if _, _, _, ok := parseQuestion(q); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	// Every truncation of a valid query is handled without a panic.
	for n := range good {
		parseQuestion(good[:n])
	}
}

// The real client side: Go's own resolver must be happy with the answers.
func TestWithGoResolver(t *testing.T) {
	f := newFake(t, "198.18.0.0/15", "127.0.0.1:9")
	f.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no upstream in this test")
	}
	addr := listen(t, f)
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ips, err := r.LookupNetIP(ctx, "ip", "media.oddly-test.example.com")
	if err != nil {
		t.Fatalf("lookup through the fake server: %v", err)
	}
	if len(ips) != 1 || !f.Contains(ips[0]) {
		t.Fatalf("got %v, want exactly one placeholder address", ips)
	}
	if name, _ := f.Lookup(ips[0]); name != "media.oddly-test.example.com" {
		t.Errorf("%v maps back to %q", ips[0], name)
	}
}

// Names the Real hook claims are resolved by the upstream server and get no
// placeholder.
func TestRealNamesGoUpstream(t *testing.T) {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			reply[3] = 0x83
			_, _ = up.WriteTo(reply, from)
		}
	}()
	f := newFake(t, "198.18.0.0/15", up.LocalAddr().String())
	f.Real = func(name string) bool { return strings.HasSuffix(name, ".corp.example") }
	addr := listen(t, f)

	if r := exchange(t, addr, query(1, "git.corp.example", typeA)); r[3]&0x0F != 3 {
		t.Errorf("a real name was answered here: % x", r)
	}
	if r := exchange(t, addr, query(2, "www.example.com", typeA)); r[3]&0x0F != 0 || binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Errorf("another name got no placeholder: % x", r)
	}
	if _, ok := f.byName["git.corp.example"]; ok || len(f.byName) != 1 {
		t.Errorf("placeholders: %v", f.byName)
	}
}
