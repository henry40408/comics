// Package thumb turns page images into small JPEG thumbnails.
package thumb

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/gif" // registers the GIF decoder with image.Decode
	"image/jpeg"
	_ "image/png" // registers the PNG decoder with image.Decode
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // registers the WebP decoder with image.Decode
)

// quality is the JPEG quality of every generated thumbnail.
const quality = 72

// SizePx maps a size keyword to the maximum edge length in pixels. Any other
// keyword is not allowed.
func SizePx(name string) (int, bool) {
	switch name {
	case "sm":
		return 120, true // reader thumbnail rail
	case "md":
		return 400, true // library covers
	default:
		return 0, false
	}
}

// ContentTypeFromPath names the image type by file extension, ignoring case.
func ContentTypeFromPath(filePath string) string {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	default:
		return "application/octet-stream"
	}
}

// Generate decodes the image at filePath by sniffing its content, scales it to
// fit inside limit x limit with the aspect ratio kept, and encodes it as JPEG.
func Generate(filePath string, limit int) ([]byte, error) {
	src, err := decode(filePath)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, fit(src, limit), &jpeg.Options{Quality: quality}); err != nil {
		return nil, fmt.Errorf("encode thumbnail: %w", err)
	}
	return buf.Bytes(), nil
}

// maxDecodeBytes bounds the RGBA buffer a decode may allocate. A header can
// declare far more pixels than the file holds, so the size is checked before
// decoding.
const maxDecodeBytes = 512 << 20

func decode(filePath string) (image.Image, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	config, _, err := image.DecodeConfig(file)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", filePath, err)
	}
	if int64(config.Width)*int64(config.Height)*4 > maxDecodeBytes {
		return nil, fmt.Errorf("decode %s: %dx%d exceeds the %d byte decode limit",
			filePath, config.Width, config.Height, maxDecodeBytes)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", filePath, err)
	}
	return img, nil
}

// fit scales img to the largest size inside limit x limit. JPEG has no alpha
// channel, so alpha is dropped and a transparent pixel shows whatever RGB the
// file stored for it.
func fit(img image.Image, limit int) *image.RGBA {
	opaque := dropAlpha(img)
	width, height := scaledSize(opaque.Bounds().Dx(), opaque.Bounds().Dy(), limit)
	out := image.NewRGBA(image.Rect(0, 0, width, height))
	xdraw.CatmullRom.Scale(out, out.Bounds(), opaque, opaque.Bounds(), xdraw.Src, nil)
	return out
}

// dropAlpha keeps each pixel's non-premultiplied RGB and makes it opaque.
func dropAlpha(img image.Image) *image.RGBA {
	bounds := img.Bounds()
	out := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			out.SetRGBA(x, y, color.RGBA{R: c.R, G: c.G, B: c.B, A: 0xff})
		}
	}
	return out
}

// scaledSize keeps the aspect ratio, never returns a zero edge, rounds to the
// nearest pixel and also enlarges an image smaller than limit.
func scaledSize(width, height, limit int) (int, int) {
	if width >= height {
		return limit, scaledEdge(height, limit, width)
	}
	return scaledEdge(width, limit, height), limit
}

func scaledEdge(short, limit, long int) int {
	ratio := float64(limit) / float64(long)
	return max(1, int(math.Round(float64(short)*ratio)))
}
