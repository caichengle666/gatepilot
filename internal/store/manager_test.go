package store

import "testing"

func TestRetainActiveNodeMissingFromRefresh(t *testing.T) {
	active := Node{ID: "JP_active", Country: "日本", Active: true, ProbeStatus: "available"}
	nodes := retainActiveNode(
		[]Node{{ID: "US_new"}},
		map[string]Node{active.ID: active},
		active.ID,
	)
	if len(nodes) != 2 || nodes[1].ID != active.ID || !nodes[1].Active {
		t.Fatalf("active node was not retained: %+v", nodes)
	}
}

func TestRetainActiveNodeAvoidsDuplicate(t *testing.T) {
	nodes := retainActiveNode(
		[]Node{{ID: "JP_active", Active: true}},
		map[string]Node{"JP_active": {ID: "JP_active"}},
		"JP_active",
	)
	if len(nodes) != 1 {
		t.Fatalf("active node was duplicated: %+v", nodes)
	}
}
