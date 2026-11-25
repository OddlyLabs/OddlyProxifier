package intercept

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func TestSplitFamilies(t *testing.T) {
	in := prefixes(
		"192.168.1.7/24", // host bits are masked off
		"10.1.0.0/16",    // inside 10.0.0.0/8
		"10.0.0.0/8",
		"10.0.0.0/8",            // twice
		"::ffff:172.16.0.0/108", // IPv4 in IPv6 clothing
		"::ffff:0.0.0.0/64",     // wider than the IPv4 space: means nothing
		"fe80::1/128",           // inside fe80::/10
		"fe80::/10",
		"2001:db8::/32",
	)
	in = append(in, netip.Prefix{})
	v4, v6 := splitFamilies(in)
	if want := prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"); !reflect.DeepEqual(v4, want) {
		t.Errorf("IPv4: %v, want %v", v4, want)
	}
	if want := prefixes("fe80::/10", "2001:db8::/32"); !reflect.DeepEqual(v6, want) {
		t.Errorf("IPv6: %v, want %v", v6, want)
	}
	if v4, v6 := splitFamilies(nil); len(v4)+len(v6) != 0 {
		t.Errorf("nothing in, %v and %v out", v4, v6)
	}
}

// No two entries of a family may overlap: nftables rejects such a set.
func TestSplitFamiliesNeverOverlap(t *testing.T) {
	in := append(append([]netip.Prefix{}, alwaysBypass...), prefixes(
		"127.0.0.1/32", "0.0.0.0/0", "224.0.0.0/3", "169.254.0.0/16", "::/0", "fe80::/10", "100.64.0.0/10",
	)...)
	v4, v6 := splitFamilies(in)
	for _, list := range [][]netip.Prefix{v4, v6} {
		for i, a := range list {
			for j, b := range list {
				if i != j && a.Overlaps(b) {
					t.Errorf("%v and %v overlap", a, b)
				}
			}
		}
	}
	if len(v4) != 1 || len(v6) != 1 {
		t.Errorf("a default route covers everything: %v, %v", v4, v6)
	}
}

type wrapped struct{ net.Conn }

func (w wrapped) NetConn() net.Conn { return w.Conn }

func TestTCPConnUnwraps(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := tcpConn(wrapped{wrapped{c}})
	if err != nil || got != c.(*net.TCPConn) {
		t.Errorf("tcpConn(wrapped) = %v, %v", got, err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := tcpConn(wrapped{a}); err == nil {
		t.Error("a pipe passed for a TCP connection")
	}
}

func TestTCPAddrPort(t *testing.T) {
	ap, ok := tcpAddrPort(&net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 8080})
	if !ok || ap != netip.MustParseAddrPort("10.0.0.1:8080") {
		t.Errorf("IPv4-mapped address: %v, %v", ap, ok)
	}
	if _, ok := tcpAddrPort(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}); ok {
		t.Error("a UDP address passed for a TCP one")
	}
}
