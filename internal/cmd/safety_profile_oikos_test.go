package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The oikos profile allows everything except sending, deleting, sharing, and
// signing in. It is deny-only, so a command added upstream is allowed by
// default. This test fails when a new command looks like one of those four
// and the profile has not decided on it, so an upstream sync stops for review.
var oikosRiskyLeaf = regexp.MustCompile(`(send|delete|trash|clear|share|forward|reply|publish|watch|import|export|remove|rekey|keyring|dedupe|vacation|delegates|sendas|update-role|autoforward|tokens|credentials|unset|^set$|-set$)`)

// Reviewed and allowed: drafts, edits inside one document that its version
// history can undo, exports to a local file, and local configuration.
var oikosReviewedAllow = map[string]bool{
	"calendar.alias.set":              true,
	"calendar.alias.unset":            true,
	"contacts.export":                 true,
	"docs.comments.reply":             true,
	"docs.delete":                     true,
	"docs.export":                     true,
	"docs.footer.delete":              true,
	"docs.header.delete":              true,
	"docs.named-range.delete":         true,
	"docs.table-column.delete":        true,
	"docs.table-row.delete":           true,
	"drive.comments.reply":            true,
	"drive.labels.file.remove":        true,
	"forms.watch.delete":              true,
	"gmail.drafts.forward":            true,
	"gmail.drafts.reply":              true,
	"gmail.drafts.reply-all":          true,
	"gmail.import":                    true,
	"gmail.settings.filters.export":   true,
	"sheets.banding.clear":            true,
	"sheets.banding.set":              true,
	"sheets.chart.delete":             true,
	"sheets.conditional-format.clear": true,
	"sheets.datasource.delete":        true,
	"sheets.delete-dimension":         true,
	"sheets.export":                   true,
	"sheets.filter.set":               true,
	"sheets.links.set":                true,
	"sheets.named-ranges.delete":      true,
	"sheets.table.clear":              true,
	"sheets.table.delete":             true,
	"sheets.validation.clear":         true,
	"sheets.validation.set":           true,
	"slides.element.delete":           true,
	"slides.export":                   true,
	"slides.table.column.delete":      true,
	"slides.table.row.delete":         true,
}

var oikosMustAllow = [][]string{
	{"calendar", "create"},
	{"calendar", "update"},
	{"calendar", "respond"},
	{"tasks", "add"},
	{"tasks", "done"},
	{"gmail", "drafts", "create"},
	{"gmail", "archive"},
	{"drive", "upload"},
	{"sheets", "update"},
}

func stockCommandTree(t *testing.T) map[string]*schemaNode {
	t.Helper()
	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"schema"}); err != nil {
				t.Fatalf("Execute(schema): %v", err)
			}
		})
	})
	var doc schemaDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	tree := map[string]*schemaNode{}
	var walk func(prefix []string, node *schemaNode)
	walk = func(prefix []string, node *schemaNode) {
		for _, sub := range node.Subcommands {
			path := append(append([]string{}, prefix...), sub.Name)
			tree[strings.Join(path, ".")] = sub
			walk(path, sub)
		}
	}
	walk(nil, doc.Command)
	return tree
}

func loadOikosProfile(t *testing.T) (bakedSafetyProfile, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "safety-profiles", "oikos.yaml"))
	if err != nil {
		t.Fatalf("read oikos profile: %v", err)
	}
	withBakedSafetyProfile(t, string(raw))
	profile, err := loadBakedSafetyProfile()
	if err != nil {
		t.Fatalf("loadBakedSafetyProfile: %v", err)
	}
	var denies []string
	for _, line := range strings.Split(string(raw), "\n") {
		if rule, ok := strings.CutPrefix(strings.TrimSpace(line), "- "); ok {
			denies = append(denies, rule)
		}
	}
	return profile, denies
}

func TestOikosProfileDecidesEveryRiskyCommand(t *testing.T) {
	setTestConfigHome(t)
	tree := stockCommandTree(t)
	profile, denies := loadOikosProfile(t)

	for _, rule := range denies {
		if tree[rule] == nil {
			t.Errorf("deny rule %q names no command; upstream renamed or removed it", rule)
		}
	}
	for path, node := range tree {
		root := strings.SplitN(path, ".", 2)[0]
		switch root {
		case "gmail", "calendar", "drive", "docs", "sheets", "slides", "contacts", "tasks", "people", "auth", "config", "chat", "forms":
		default:
			continue
		}
		parts := strings.Split(path, ".")
		if len(node.Subcommands) > 0 || !oikosRiskyLeaf.MatchString(parts[len(parts)-1]) {
			continue
		}
		if !profile.allowsCommandPath(parts) || oikosReviewedAllow[path] {
			continue
		}
		t.Errorf("%s looks like it sends, deletes, shares, or signs in; deny it in safety-profiles/oikos.yaml or add it to oikosReviewedAllow", path)
	}
	for path := range oikosReviewedAllow {
		if tree[path] == nil {
			t.Errorf("reviewed command %q no longer exists", path)
		}
	}
}

func TestOikosProfileBlocksSendDeleteShareAndSignIn(t *testing.T) {
	setTestConfigHome(t)
	_, _ = loadOikosProfile(t)

	tests := [][]string{
		{"gmail", "send", "--to", "a@example.com", "--subject", "s", "--body", "b"},
		{"gmail", "drafts", "send", "draft-1"},
		{"gmail", "trash", "msg-1"},
		{"calendar", "delete", "primary", "event-1"},
		{"drive", "share", "file-1", "--email", "a@example.com"},
		{"auth", "tokens", "export", "a@example.com"},
		{"--enable-commands", "gmail.send", "gmail", "send", "--to", "a@example.com", "--subject", "s", "--body", "b"},
	}
	for _, args := range tests {
		err := Execute(args)
		if err == nil || !strings.Contains(err.Error(), `baked safety profile "oikos"`) {
			t.Errorf("expected oikos profile block for %v, got %v", args, err)
		}
	}
}

func TestOikosProfileAllowsEverydayWrites(t *testing.T) {
	setTestConfigHome(t)
	profile, _ := loadOikosProfile(t)
	for _, path := range oikosMustAllow {
		if !profile.allowsCommandPath(path) {
			t.Errorf("oikos profile blocks %s", strings.Join(path, " "))
		}
	}
}
