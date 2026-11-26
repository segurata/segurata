package docref

import (
	"reflect"
	"testing"
)

func TestAnchorsFollowGitHub(t *testing.T) {
	md := "# Title\n\n## 1. Google accounts and Workspace administration\n" +
		"## Google Workspace administration (`workspace`)\n" +
		"```bash\n# not a heading\n```\n" +
		"## Notes\n### Notes\n#hashtag\n"
	want := map[string]bool{
		"title": true, "1-google-accounts-and-workspace-administration": true,
		"google-workspace-administration-workspace": true, "notes": true, "notes-1": true,
	}
	if got := Anchors(md); !reflect.DeepEqual(got, want) {
		t.Errorf("anchors %v, want %v", got, want)
	}
}
