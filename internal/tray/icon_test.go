package tray

import (
	"encoding/binary"
	"testing"
)

func TestDraw(t *testing.T) {
	for _, size := range []int{16, 20, 24, 32, 48} {
		px := draw(size, true)
		if len(px) != size*size*4 {
			t.Fatalf("size %d: %d bytes", size, len(px))
		}
		at := func(x, y int) [4]byte { return [4]byte(px[(y*size+x)*4:]) }
		// The corners are outside the rounded square.
		if c := at(0, 0); c[3] != 0 {
			t.Errorf("size %d: corner %v is not transparent", size, c)
		}
		// The left node is white, the area above it has the background colour.
		node := at(12*size/32, 10*size/32)
		if node != [4]byte{255, 255, 255, 255} {
			t.Errorf("size %d: node %v", size, node)
		}
		if bg := at(size/2, size/10); bg != [4]byte{0x0B, 0x6E, 0x70, 255} {
			t.Errorf("size %d: background %v", size, bg)
		}
		if off := draw(size, false); off[(size/10*size+size/2)*4] == 0x0B {
			t.Errorf("size %d: the inactive icon has the active colour", size)
		}
	}
}

func TestIconResource(t *testing.T) {
	const size = 20
	res := iconResource(size, true)
	maskRow := 4 // 20 bits, padded to 32
	if want := 40 + size*size*4 + maskRow*size; len(res) != want {
		t.Fatalf("%d bytes, want %d", len(res), want)
	}
	if binary.LittleEndian.Uint32(res[4:]) != size || binary.LittleEndian.Uint32(res[8:]) != size*2 ||
		binary.LittleEndian.Uint16(res[14:]) != 32 {
		t.Errorf("header % x", res[:40])
	}
	// Rows are stored bottom-up and as BGRA: the first stored pixel is the
	// bottom-left corner (transparent), and the background is B=0x70.
	if res[40+3] != 0 {
		t.Error("the bottom-left corner is not transparent")
	}
	px := draw(size, true)
	x, y := size/2, size/10
	stored := res[40+((size-1-y)*size+x)*4:]
	if stored[0] != px[(y*size+x)*4+2] || stored[2] != px[(y*size+x)*4] || stored[0] != 0x70 {
		t.Errorf("stored pixel % x", stored[:4])
	}
}
