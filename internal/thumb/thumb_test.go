package thumb

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureJPEG = "../../fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg"

func TestContentTypeCoversKnownAndUnknownExtensions(t *testing.T) {
	for path, want := range map[string]string{
		"a/b.jpg":     "image/jpeg",
		"a/b.JPEG":    "image/jpeg",
		"a/b.png":     "image/png",
		"a/b.gif":     "image/gif",
		"a/b.webp":    "image/webp",
		"a/b.avif":    "image/avif",
		"a/b.txt":     "application/octet-stream",
		"noextension": "application/octet-stream",
	} {
		if got := ContentTypeFromPath(path); got != want {
			t.Errorf("ContentTypeFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestSizePxAllowlist(t *testing.T) {
	for name, want := range map[string]int{"sm": 120, "md": 400} {
		if got, ok := SizePx(name); !ok || got != want {
			t.Errorf("SizePx(%q) = %d, %v", name, got, ok)
		}
	}
	for _, name := range []string{"lg", "", "SM", "../md"} {
		if _, ok := SizePx(name); ok {
			t.Errorf("SizePx(%q) is allowed", name)
		}
	}
}

func decodeJPEG(t *testing.T, data []byte) image.Config {
	t.Helper()
	if !bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		t.Fatalf("not JPEG: % x", data[:min(8, len(data))])
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || format != "jpeg" {
		t.Fatalf("decode config: %v %q", err, format)
	}
	return cfg
}

func TestGenerateFitsAFixtureInsideTheLimit(t *testing.T) {
	for _, limit := range []int{120, 400} {
		data, err := Generate(fixtureJPEG, limit)
		if err != nil {
			t.Fatal(err)
		}
		cfg := decodeJPEG(t, data)
		// The fixture is 1200x1660, so the height is the long edge.
		if cfg.Height != limit || cfg.Width >= limit || cfg.Width < 1 {
			t.Errorf("limit %d gave %dx%d", limit, cfg.Width, cfg.Height)
		}
	}
}

func writeImage(t *testing.T, name string, encode func(*os.File) error) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := encode(file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	// Close reports a delayed write error; ignoring it would leave a truncated
	// fixture that fails later with a confusing decode error.
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGenerateSniffsContentNotExtension(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 300, 100))
	src.Set(0, 0, color.NRGBA{R: 200, A: 255})
	// A PNG named .jpg, and a GIF named .png.
	pngPath := writeImage(t, "a.jpg", func(f *os.File) error { return png.Encode(f, src) })
	gifPath := writeImage(t, "b.png", func(f *os.File) error { return gif.Encode(f, src, nil) })
	for _, path := range []string{pngPath, gifPath} {
		data, err := Generate(path, 120)
		if err != nil {
			t.Fatal(err)
		}
		cfg := decodeJPEG(t, data)
		if cfg.Width != 120 || cfg.Height != 40 {
			t.Errorf("%s gave %dx%d", path, cfg.Width, cfg.Height)
		}
	}
}

func TestGenerateRejectsWhatIsNotAnImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jpg")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(path, 120); err == nil {
		t.Fatal("garbage decoded")
	}
	if _, err := Generate(path+".missing", 120); err == nil {
		t.Fatal("a missing file decoded")
	}
}

func pngChunk(kind string, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	out = append(out, kind...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(append([]byte(kind), data...)))
}

func TestGenerateRefusesAHeaderDeclaringHugeDimensions(t *testing.T) {
	header := binary.BigEndian.AppendUint32(nil, 30000)
	header = binary.BigEndian.AppendUint32(header, 30000)
	header = append(header, 8, 6, 0, 0, 0) // 8-bit RGBA
	data := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", header)...)
	path := filepath.Join(t.TempDir(), "huge.png")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(path, 120); err == nil {
		t.Fatal("a 30000x30000 image was decoded")
	}
}

func TestContentTypeOfADotfileNamedAfterAnExtension(t *testing.T) {
	// A leading dot is still the extension separator.
	if got := ContentTypeFromPath(".png"); got != "image/png" {
		t.Errorf("ContentTypeFromPath(%q) = %q, want image/png", ".png", got)
	}
}

func TestDecodeLimitIsInclusiveAtExactlyMaxDecodeBytes(t *testing.T) {
	const atLimitWidth = 16384 // 16384 x 8192 x 4 bytes == maxDecodeBytes
	for name, c := range map[string]struct {
		width, height uint32
		wantRefused   bool
	}{
		"exactly at the limit": {atLimitWidth, 8192, false},
		"one row over":         {atLimitWidth, 8193, true},
		"far over":             {30000, 30000, true},
	} {
		t.Run(name, func(t *testing.T) {
			header := binary.BigEndian.AppendUint32(nil, c.width)
			header = binary.BigEndian.AppendUint32(header, c.height)
			header = append(header, 8, 6, 0, 0, 0) // 8-bit RGBA
			data := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", header)...)
			path := filepath.Join(t.TempDir(), "header-only.png")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := decode(path)
			if err == nil {
				t.Fatal("a header-only PNG decoded")
			}
			refused := strings.Contains(err.Error(), "decode limit")
			if refused != c.wantRefused {
				t.Fatalf("refused by the size limit = %v, want %v (error: %v)", refused, c.wantRefused, err)
			}
		})
	}
}

func TestFitIgnoresAlphaLikeToRGB8(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	src.SetNRGBA(0, 0, color.NRGBA{R: 200, G: 40, B: 40, A: 128})
	c := fit(src, 1).RGBAAt(0, 0)
	if c.A != 0xff || c.R != 200 || c.G != 40 || c.B != 40 {
		t.Errorf("pixel = %+v, want stored RGB 200,40,40 opaque", c)
	}
}

func TestScaledSizeKeepsTheAspectRatioAndNeverCollapses(t *testing.T) {
	for _, c := range []struct{ w, h, limit, wantW, wantH int }{
		{1200, 1660, 400, 289, 400},
		{1000, 667, 400, 400, 267},
		{300, 100, 120, 120, 40},
		{100, 100, 120, 120, 120},
		{10000, 1, 120, 120, 1},
		{1, 10000, 120, 1, 120},
	} {
		w, h := scaledSize(c.w, c.h, c.limit)
		if w != c.wantW || h != c.wantH {
			t.Errorf("scaledSize(%d,%d,%d) = %dx%d, want %dx%d", c.w, c.h, c.limit, w, h, c.wantW, c.wantH)
		}
	}
}
