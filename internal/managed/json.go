package managed

import "encoding/json"

func jsonBytes(v interface{}) ([]byte, error) { return json.Marshal(v) }
func clone(j Journal) Journal {
	b, _ := json.Marshal(j)
	var out Journal
	_ = json.Unmarshal(b, &out)
	return out
}
