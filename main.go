package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cespare/xxhash/v2"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:           "fsdiff",
		Short:         "Filesystem Diff",
		Args:          cobra.ExactArgs(1),
		Run:           run,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.Flags().IntP("depth", "d", 0, "depth of directory hierarchy")
	cmd.Flags().StringArrayP("exclude", "e", nil, "exclude files or directories")
	cmd.Flags().StringP("output", "o", "", "output file name")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := cmd.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	basePath, err := filepath.Abs(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error abs path:", err)
		return
	}

	exclude, err := cmd.Flags().GetStringArray("exclude")
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error reading flags:", err)
		return
	}

	depth, err := cmd.Flags().GetInt("depth")
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error reading flags:", err)
		return
	}

	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error reading flags:", err)
		return
	}

	info, err := os.Lstat(basePath)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error:", err)
		return
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Path %s is not a regular file or directory\n", basePath)
		return
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Building fsdiff for %s\n", basePath)

	ctx := cmd.Context()
	fh := newFSHasher(ctx, exclude)

	start := time.Now()
	eh, err := fh.hashPath(basePath, depth)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error:", err)
		return
	}
	duration := time.Since(start)

	out := cmd.OutOrStdout()
	if outputPath != "" {
		var outFile *os.File
		outFile, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error:", err)
			return
		}
		defer func() { _ = outFile.Close() }()
		out = outFile
	}

	printEntry(out, eh, 0)

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Built fsdiff in %s, %d files checked\n", duration, fh.files.Load())
	if fh.readErrors.Load() > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Encountered %d read errors\n", fh.readErrors.Load())
	}
	if fh.permissionErrors.Load() > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Encountered %d permission errors\n", fh.permissionErrors.Load())
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "FS Diff hash %016x\n", eh.hash)
}

type entryHash struct {
	path    string
	hash    uint64
	entries []entryHash
}

func printEntry(out io.Writer, e entryHash, depth int) {
	path := e.path
	if depth > 0 {
		path = filepath.Base(path)
	}
	_, _ = fmt.Fprintln(out, strings.Repeat("\t", depth)+fmt.Sprintf("%016x", e.hash), path)
	for _, entry := range e.entries {
		printEntry(out, entry, depth+1)
	}
}

type fsHasher struct {
	ctx     context.Context
	exclude []string

	files            *atomic.Int32
	readErrors       *atomic.Int32
	permissionErrors *atomic.Int32
}

func newFSHasher(ctx context.Context, exclude []string) *fsHasher {
	return &fsHasher{
		ctx:              ctx,
		exclude:          exclude,
		files:            &atomic.Int32{},
		readErrors:       &atomic.Int32{},
		permissionErrors: &atomic.Int32{},
	}
}

func (f *fsHasher) done() error {
	select {
	case <-f.ctx.Done():
		return f.ctx.Err()
	default:
		return nil
	}
}

func (f *fsHasher) skip(path string) (bool, error) {
	for _, pattern := range f.exclude {
		if match, err := doublestar.Match(pattern, path); err != nil {
			return false, err
		} else if match {
			return true, nil
		}
	}
	return false, nil
}

func (f *fsHasher) hashPath(path string, depth int) (entryHash, error) {
	if err := f.done(); err != nil {
		return entryHash{}, err
	}

	if skip, err := f.skip(path); err != nil {
		return entryHash{}, fmt.Errorf("skip: %w", err)
	} else if skip {
		return entryHash{}, errors.New("all files are skipped")
	}

	info, err := os.Lstat(path)
	if err != nil {
		return entryHash{}, fmt.Errorf("file info: %w", err)
	}

	if info.IsDir() {
		if depth > 0 {
			return f.hashDirWithDepth(path, depth)
		}

		var eh uint64
		eh, err = f.hashDir(path)
		if err != nil {
			return entryHash{}, err
		}

		return entryHash{path: path, hash: eh}, nil
	}

	eh, err := f.hashFile(path, fs.FileInfoToDirEntry(info))
	if err != nil {
		return entryHash{}, err
	}

	return entryHash{path: path, hash: eh}, nil
}

func (f *fsHasher) hashDirWithDepth(path string, depth int) (entryHash, error) {
	if err := f.done(); err != nil {
		return entryHash{}, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsPermission(err) {
			f.permissionErrors.Add(1)
			return entryHash{path: path}, nil
		}
		return entryHash{}, fmt.Errorf("read dir: %w", err)
	}

	depth--
	h := xxhash.New()

	hashes := make([]entryHash, 0, len(entries))
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())

		var skip bool
		if skip, err = f.skip(entryPath); err != nil {
			return entryHash{}, fmt.Errorf("skip: %w", err)
		} else if skip {
			continue
		}

		var eh uint64
		if entry.IsDir() {
			if depth > 0 {
				var e entryHash
				e, err = f.hashDirWithDepth(entryPath, depth)
				if err != nil {
					return entryHash{}, err
				}

				eh = e.hash
				hashes = append(hashes, e)
			} else {
				eh, err = f.hashDir(entryPath)
				if err != nil {
					return entryHash{}, err
				}

				hashes = append(hashes, entryHash{path: entryPath, hash: eh})
			}
		} else {
			eh, err = f.hashFile(entryPath, entry)
			if err != nil {
				return entryHash{}, err
			}

			hashes = append(hashes, entryHash{path: entryPath, hash: eh})
		}

		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, eh)
		if _, err = h.Write(buf); err != nil {
			return entryHash{}, fmt.Errorf("hash entry: %w", err)
		}
	}
	return entryHash{path: path, hash: h.Sum64(), entries: hashes}, nil
}

func (f *fsHasher) hashDir(path string) (uint64, error) {
	if err := f.done(); err != nil {
		return 0, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsPermission(err) {
			f.permissionErrors.Add(1)
			return 0, nil
		}
		return 0, fmt.Errorf("read dir: %w", err)
	}

	wg := sync.WaitGroup{}
	errs := make(chan error)
	results := make(chan entryHash)
	for _, entry := range entries {
		wg.Go(func() {
			entryPath := filepath.Join(path, entry.Name())

			var skip bool
			if skip, err = f.skip(entryPath); err != nil {
				select {
				case errs <- fmt.Errorf("skip: %w", err):
				case <-f.ctx.Done():
				}
				return
			} else if skip {
				return
			}

			var eh uint64
			if entry.IsDir() {
				eh, err = f.hashDir(entryPath)
			} else {
				eh, err = f.hashFile(entryPath, entry)
			}
			if err != nil {
				select {
				case errs <- err:
				case <-f.ctx.Done():
				}
				return
			}

			select {
			case results <- entryHash{path: entryPath, hash: eh}:
			case <-f.ctx.Done():
			}
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var ok bool
	var result entryHash
	hashResults := make([]entryHash, 0, len(results))
loop:
	for {
		select {
		case err, ok = <-errs:
			if !ok {
				return 0, errors.New("errors channel closed")
			}
			return 0, err
		case result, ok = <-results:
			if !ok {
				break loop
			}
			hashResults = append(hashResults, result)
		case <-f.ctx.Done():
			return 0, f.ctx.Err()
		}
	}
	close(errs)

	slices.SortFunc(hashResults, func(a, b entryHash) int {
		return cmp.Compare(a.path, b.path)
	})

	h := xxhash.New()
	for _, eh := range hashResults {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, eh.hash)
		if _, err = h.Write(buf); err != nil {
			return 0, fmt.Errorf("hash entry: %w", err)
		}
	}
	return h.Sum64(), nil
}

func (f *fsHasher) hashFile(path string, info fs.DirEntry) (uint64, error) {
	if err := f.done(); err != nil {
		return 0, err
	}

	f.files.Add(1)
	h := xxhash.New()

	if _, err := h.WriteString(path); err != nil {
		return 0, fmt.Errorf("hash path: %w", err)
	}

	ft := info.Type()
	fth := make([]byte, 4)
	binary.LittleEndian.PutUint32(fth, uint32(ft))
	if _, err := h.Write(fth); err != nil {
		return 0, fmt.Errorf("hash file type: %w", err)
	}

	if !ft.IsRegular() {
		return h.Sum64(), nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			f.permissionErrors.Add(1)
			return h.Sum64(), nil
		}
		return 0, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	if _, err = io.Copy(h, file); err != nil {
		if errors.Is(err, syscall.EIO) {
			f.readErrors.Add(1)
			return h.Sum64(), nil
		}
		return 0, fmt.Errorf("hash file: %w", err)
	}

	return h.Sum64(), nil
}
