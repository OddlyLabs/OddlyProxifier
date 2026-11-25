// The icon is drawn at run time, at whatever size the system asks for, so
// that no binary resource has to be linked in. It is the same mark as the web
// interface's: two nodes joined by a route on a rounded square.
package tray

import (
	"encoding/binary"
	"math"
)

// draw returns size*size pixels, 4 bytes each (R, G, B, A, straight alpha),
// top row first.
func draw(size int, active bool) []byte {
	const ss = 4 // samples per pixel and axis
	bg := [3]float64{0x0B, 0x6E, 0x70}
	if !active {
		bg = [3]float64{0x6E, 0x74, 0x7B}
	}
	out := make([]byte, size*size*4)
	scale := 32 / float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var cover, white float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) * scale
					py := (float64(y) + (float64(sy)+0.5)/ss) * scale
					if !inRoundRect(px, py, 32, 32, 7) {
						continue
					}
					cover++
					if onMark(px, py) {
						white++
					}
				}
			}
			i := (y*size + x) * 4
			if cover == 0 {
				continue
			}
			w := white / cover
			for c := 0; c < 3; c++ {
				out[i+c] = byte(math.Round(bg[c]*(1-w) + 255*w))
			}
			out[i+3] = byte(math.Round(255 * cover / (ss * ss)))
		}
	}
	return out
}

func inRoundRect(x, y, w, h, r float64) bool {
	if x < 0 || y < 0 || x > w || y > h {
		return false
	}
	cx := math.Max(r, math.Min(w-r, x))
	cy := math.Max(r, math.Min(h-r, y))
	return math.Hypot(x-cx, y-cy) <= r
}

// onMark reports whether a point of the 32x32 design is part of the white mark.
func onMark(x, y float64) bool {
	if math.Hypot(x-12, y-10) <= 3.4 || math.Hypot(x-20, y-22) <= 3.4 {
		return true
	}
	path := [][2]float64{{4, 10}, {12, 10}, {20, 22}, {28, 22}}
	for i := 0; i+1 < len(path); i++ {
		if segDist(x, y, path[i], path[i+1]) <= 1.5 {
			return true
		}
	}
	return false
}

func segDist(x, y float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := ((x-a[0])*dx + (y-a[1])*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(x-(a[0]+t*dx), y-(a[1]+t*dy))
}

// iconResource packs the drawing the way icon resources store images: a
// BITMAPINFOHEADER of twice the height, the colour rows bottom-up as BGRA,
// and a 1-bit mask (unused with an alpha channel, but required).
func iconResource(size int, active bool) []byte {
	px := draw(size, active)
	maskRow := (size + 31) / 32 * 4
	buf := make([]byte, 0, 40+size*size*4+maskRow*size)
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint32(hdr[0:], 40)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(size))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(size*2))
	binary.LittleEndian.PutUint16(hdr[12:], 1)
	binary.LittleEndian.PutUint16(hdr[14:], 32)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(size*size*4))
	buf = append(buf, hdr...)
	for y := size - 1; y >= 0; y-- {
		for x := 0; x < size; x++ {
			i := (y*size + x) * 4
			buf = append(buf, px[i+2], px[i+1], px[i], px[i+3])
		}
	}
	return append(buf, make([]byte, maskRow*size)...)
}
