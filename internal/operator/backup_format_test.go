package operator

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v3/pb"
	"github.com/golang/protobuf/proto"
)

func TestBackupDatabaseFrameLimits(t *testing.T) {
	frame := func(raw []byte) []byte {
		b := new(bytes.Buffer)
		binary.Write(b, binary.LittleEndian, uint64(len(raw)))
		b.Write(raw)
		return b.Bytes()
	}
	valid, _ := proto.Marshal(&pb.KVList{Kv: []*pb.KV{{Key: []byte("key"), Value: []byte("value"), Version: 1, Meta: []byte{0}}}})
	overflow, _ := proto.Marshal(&pb.KVList{Kv: []*pb.KV{{Key: []byte("key"), Version: ^uint64(0)}}})
	emptyKey, _ := proto.Marshal(&pb.KVList{Kv: []*pb.KV{{Value: []byte("value"), Version: 1}}})
	countBomb := bytes.Repeat([]byte{0x0a, 0}, 100001)
	cases := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"empty database", nil, true}, {"valid frame", frame(valid), true},
		{"huge length", bytes.Repeat([]byte{0xff}, 8), false}, {"short header", []byte{1}, false},
		{"short payload", frame(valid)[:len(frame(valid))-1], false}, {"too many protobuf objects", frame(countBomb), false},
		{"transaction timestamp overflow", frame(overflow), false}, {"empty key", frame(emptyKey), false},
		{"malformed protobuf", frame([]byte{0xff}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db.backup")
			mustBackupWrite(t, path, c.raw)
			err := validateDatabaseExport(path)
			if (err == nil) != c.ok {
				t.Fatalf("expected accepted=%v, got %v", c.ok, err)
			}
		})
	}
}
