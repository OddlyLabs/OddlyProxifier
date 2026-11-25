// Command release builds OddlyProxifier for every supported platform and
// packs each build with the documents a user needs.
//
//	go run ./tools/release            all targets into dist/
//	go run ./tools/release -out d     another output directory
//	go run ./tools/release -only linux/arm64,windows/amd64
//
// Windows archives are .zip, the others .tar.gz. The Windows archive also
// holds the driver (driver/OddlyDrv.sys and .inf) when it has been built.
// -no-driver leaves it out. A SHA256SUMS file lists the archives.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type target struct{ os, arch string }

// noDriver leaves the driver out: a test-signed build loads only on machines
// that trust the certificate it was signed with.
var noDriver bool

var targets = []target{
	{"windows", "amd64"},
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// file is one entry of an archive.
type file struct {
	src  string // path on disk
	name string // path inside the archive, below the top directory
	mode os.FileMode
}

func main() {
	out := flag.String("out", "dist", "output `directory`")
	only := flag.String("only", "", "comma-separated `targets` such as linux/amd64 (default: all)")
	flag.BoolVar(&noDriver, "no-driver", false, "leave the Windows driver out of the archive")
	flag.Parse()
	if err := run(*out, *only); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(out, only string) error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("run this from the root of the repository")
	}
	version, err := readVersion()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range strings.Split(only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}
	for s := range want {
		known := false
		for _, t := range targets {
			known = known || t.os+"/"+t.arch == s
		}
		if !known {
			return fmt.Errorf("unknown target %q", s)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "oddly-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	var archives []string
	for _, t := range targets {
		if len(want) > 0 && !want[t.os+"/"+t.arch] {
			continue
		}
		name, err := build(t, version, work, out)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", t.os, t.arch, err)
		}
		archives = append(archives, name)
	}
	return writeSums(out, archives)
}

// readVersion takes the version from the engine package, so that the archive
// names can never disagree with what the program reports.
func readVersion() (string, error) {
	src, err := os.ReadFile(filepath.Join("internal", "engine", "engine.go"))
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?m)^\s*(?:const\s+|var\s+)?Version\s*=\s*"([^"]+)"`).FindSubmatch(src)
	if m == nil {
		return "", fmt.Errorf("no Version declaration in internal/engine/engine.go")
	}
	return string(m[1]), nil
}

func build(t target, version, work, out string) (string, error) {
	exe := "oddlyproxifier"
	if t.os == "windows" {
		exe += ".exe"
	}
	bin := filepath.Join(work, t.os+"-"+t.arch, exe)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, "./cmd/oddlyproxifier")
	cmd.Env = append(os.Environ(), "GOOS="+t.os, "GOARCH="+t.arch, "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	files := []file{{bin, exe, 0o755}}
	for _, doc := range []string{"README.md", "LICENSE", filepath.Join("docs", "ARCHITECTURE.md")} {
		if _, err := os.Stat(doc); err == nil {
			files = append(files, file{doc, filepath.ToSlash(doc), 0o644})
		}
	}
	note := ""
	if t.os == "windows" && !noDriver {
		sys := filepath.Join("driver", "OddlyDrv.sys")
		if _, err := os.Stat(sys); err == nil {
			files = append(files, file{sys, "driver/OddlyDrv.sys", 0o644})
			if inf := filepath.Join("driver", "OddlyDrv.inf"); exists(inf) {
				files = append(files, file{inf, "driver/OddlyDrv.inf", 0o644})
			}
		} else {
			note = " (no driver: driver/OddlyDrv.sys has not been built)"
		}
	}

	top := fmt.Sprintf("oddlyproxifier-%s-%s-%s", version, t.os, t.arch)
	var name string
	var err error
	if t.os == "windows" {
		name = top + ".zip"
		err = writeZip(filepath.Join(out, name), top, files)
	} else {
		name = top + ".tar.gz"
		err = writeTarGz(filepath.Join(out, name), top, files)
	}
	if err != nil {
		return "", err
	}
	st, _ := os.Stat(filepath.Join(out, name))
	fmt.Printf("%-48s %5.1f MB%s\n", name, float64(st.Size())/(1<<20), note)
	return name, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func writeZip(path, top string, files []file) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	zw := zip.NewWriter(f)
	for _, e := range files {
		st, err := os.Stat(e.src)
		if err != nil {
			return err
		}
		h := &zip.FileHeader{Name: top + "/" + e.name, Method: zip.Deflate, Modified: st.ModTime()}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if err := copyFile(w, e.src); err != nil {
			return err
		}
	}
	return zw.Close()
}

func writeTarGz(path, top string, files []file) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	now := time.Now()
	dirs := map[string]bool{}
	addDir := func(name string) error {
		if dirs[name] {
			return nil
		}
		dirs[name] = true
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755, ModTime: now})
	}
	if err := addDir(top); err != nil {
		return err
	}
	for _, e := range files {
		st, err := os.Stat(e.src)
		if err != nil {
			return err
		}
		if i := strings.LastIndex(e.name, "/"); i > 0 {
			if err := addDir(top + "/" + e.name[:i]); err != nil {
				return err
			}
		}
		h := &tar.Header{Typeflag: tar.TypeReg, Name: top + "/" + e.name, Mode: int64(e.mode), Size: st.Size(), ModTime: st.ModTime()}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if err := copyFile(tw, e.src); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func copyFile(w io.Writer, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func writeSums(out string, names []string) error {
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		f, err := os.Open(filepath.Join(out, n))
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), n)
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(b.String()), 0o644)
}
