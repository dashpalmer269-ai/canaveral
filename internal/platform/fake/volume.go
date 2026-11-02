package fake

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.VolumeInspector = (*Volumes)(nil)

// Volumes maps directory prefixes to volumes. A path belongs to the volume
// with the longest matching Root. It is safe for concurrent use, so a test
// can unmount or swap a volume while a writer is using it.
type Volumes struct {
	mu   sync.Mutex
	vols map[string]models.VolumeInfo
}

// NewVolumes returns an inspector holding vols. Each Root is normalized to
// end with a separator.
func NewVolumes(vols ...models.VolumeInfo) *Volumes {
	v := &Volumes{vols: map[string]models.VolumeInfo{}}
	for _, vi := range vols {
		v.Mount(vi)
	}
	return v
}

// Mount adds or replaces a volume.
func (v *Volumes) Mount(vi models.VolumeInfo) {
	v.mu.Lock()
	defer v.mu.Unlock()
	vi.Root = withSep(vi.Root)
	v.vols[vi.Root] = vi
}

// Unmount removes the volume at root, as if the device were unplugged.
func (v *Volumes) Unmount(root string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.vols, withSep(root))
}

// Volume returns the volume holding path.
func (v *Volumes) Volume(ctx context.Context, path string) (models.VolumeInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.VolumeInfo{}, err
	}
	p := withSep(filepath.Clean(path))
	v.mu.Lock()
	defer v.mu.Unlock()
	var best models.VolumeInfo
	found := false
	for root, vi := range v.vols {
		if strings.HasPrefix(p, root) && len(root) > len(best.Root) {
			best, found = vi, true
		}
	}
	if !found {
		return models.VolumeInfo{}, fmt.Errorf("fake: no volume holds %s: %w", path, platform.ErrNotFound)
	}
	return best, nil
}

func withSep(p string) string {
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return p
	}
	return p + string(filepath.Separator)
}
