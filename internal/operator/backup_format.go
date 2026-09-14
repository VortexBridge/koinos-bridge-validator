package operator

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/dgraph-io/badger/v3/pb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

// The pinned Badger Load allocates from a uint64 frame length before reading its
// payload. Validate the entire private export first, including object counts,
// so an authenticated but malicious backup cannot supply an unbounded length.
// These limits also apply at creation: we never emit an archive we cannot load.
func validateDatabaseExport(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > backupFileLimit {
		return errors.New("invalid database export file")
	}
	remaining := uint64(info.Size())
	for remaining > 0 {
		if remaining < 8 {
			return errors.New("truncated database frame header")
		}
		var size uint64
		if err := binary.Read(f, binary.LittleEndian, &size); err != nil {
			return err
		}
		remaining -= 8
		if size > 128<<20 || size > remaining {
			return errors.New("database frame exceeds bounded export")
		}
		raw := make([]byte, int(size))
		if _, err := io.ReadFull(f, raw); err != nil {
			return err
		}
		remaining -= size
		count := 0
		for wire := raw; len(wire) > 0; {
			number, kind, n := protowire.ConsumeTag(wire)
			if n < 0 || number != 1 || kind != protowire.BytesType {
				return errors.New("unsupported database list field")
			}
			wire = wire[n:]
			value, n := protowire.ConsumeBytes(wire)
			if n < 0 || len(value) > 5<<20 {
				return errors.New("invalid or oversized database record")
			}
			wire = wire[n:]
			count++
			if count > 100000 {
				return errors.New("database frame has too many records")
			}
		}
		var list pb.KVList
		if err := proto.Unmarshal(raw, &list); err != nil {
			return errors.New("invalid database protobuf")
		}
		for _, kv := range list.Kv {
			if kv == nil || len(kv.Key) == 0 || len(kv.Key) > 64<<10 || len(kv.Value) > 4<<20 || len(kv.Meta) > 1 || len(kv.UserMeta) > 1 || kv.Version == ^uint64(0) || kv.StreamDone {
				return errors.New("unsupported database record limits or version")
			}
		}
	}
	return nil
}
