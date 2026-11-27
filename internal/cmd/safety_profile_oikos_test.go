package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The oikos profile allows eight Google apps except sending, deleting,
// sharing, and signing in. A command added upstream inside one of those apps
// is allowed by default. This test fails when a new command looks like one of those four
// and the profile has not decided on it, so an upstream sync stops for review.
var oikosRiskyLeaf = regexp.MustCompile(`(send|delete|trash|clear|share|forward|reply|publish|watch|import|export|remove|rekey|keyring|dedupe|vacation|delegates|sendas|update-role|autoforward|tokens|credentials|unset|^set$|-set$|modify|move|copy|serve|renew|run|push|login|logout|react|return|suspend|^end$|unsubscribe|resolve|reopen|out-of-office|focus-time|propose-time|respond|upload|sync)`)

// Reviewed and allowed: drafts, edits inside one document that its version
// history can undo, exports to a local file, local configuration, label
// changes (TRASH and SPAM are refused in code), and moves, copies, and
// uploads, which become visible when the target folder is shared.
var oikosReviewedAllow = map[string]bool{
	"gmail.settings.filters.export":   true,
	"calendar.move":                   true,
	"calendar.respond":                true,
	"calendar.unsubscribe":            true,
	"docs.copy":                       true,
	"drive.copy":                      true,
	"drive.move":                      true,
	"drive.sync.push":                 true,
	"drive.upload":                    true,
	"gmail.batch.modify":              true,
	"gmail.labels.modify":             true,
	"gmail.messages.modify":           true,
	"gmail.thread.modify":             true,
	"sheets.copy":                     true,
	"sheets.copy-paste":               true,
	"slides.copy":                     true,
	"slides.move-slide":               true,
	"contacts.export":                 true,
	"docs.delete":                     true,
	"docs.export":                     true,
	"docs.footer.delete":              true,
	"docs.header.delete":              true,
	"docs.named-range.delete":         true,
	"docs.table-column.delete":        true,
	"docs.table-row.delete":           true,
	"drive.labels.file.remove":        true,
	"gmail.drafts.forward":            true,
	"gmail.drafts.reply":              true,
	"gmail.drafts.reply-all":          true,
	"gmail.import":                    true,
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
			if err := Execute([]string{"schema", "--include-hidden"}); err != nil {
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
	inDeny := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			inDeny = line == "deny:"
			continue
		}
		if rule, ok := strings.CutPrefix(strings.TrimSpace(line), "- "); ok && inDeny {
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
		{"--dry-run", "send", "--to", "a@example.com", "--subject", "s", "--body", "b"},
		{"login", "a@example.com"},
		{"logout", "a@example.com", "-y"},
		{"--dry-run", "keep", "delete", "note-1"},
		{"backup", "push"},
		{"appscript", "run", "script-1", "fn"},
		{"drive", "changes", "serve", "--webhook-url", "https://example.com/hook", "--state-file", "/tmp/x"},
		{"--dry-run", "drive", "comments", "create", "file-1", "hi"},
		{"--dry-run", "calendar", "out-of-office", "primary", "--from", "today", "--to", "tomorrow"},
		{"zoom", "auth", "setup"},
		{"youtube", "playlists", "delete", "p1"},
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

func TestOikosProfileRefusesTrashThroughLabels(t *testing.T) {
	setTestConfigHome(t)
	_, _ = loadOikosProfile(t)

	refused := [][]string{
		{"--dry-run", "gmail", "batch", "modify", "m1", "--add", "TRASH"},
		{"--dry-run", "gmail", "messages", "modify", "m1", "--add", "trash"},
		{"--dry-run", "gmail", "thread", "modify", "t1", "--add", "SPAM"},
		{"--dry-run", "gmail", "labels", "modify", "t1", "--add", "Work,TRASH"},
		{"--dry-run", "gmail", "batch", "modify", "m1", "--add-label", "TRASH"},
	}
	for _, args := range refused {
		err := Execute(args)
		if err == nil || !strings.Contains(err.Error(), "baked safety profile") {
			t.Errorf("expected label-trash refusal for %v, got %v", args, err)
		}
	}
	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"--dry-run", "gmail", "batch", "modify", "m1", "--add", "Work", "--remove", "INBOX"}); err != nil {
				t.Errorf("ordinary label change refused: %v", err)
			}
		})
	})
}

func TestOikosProfileRefusesAutoDecliningEvents(t *testing.T) {
	setTestConfigHome(t)
	_, _ = loadOikosProfile(t)

	refused := [][]string{
		{"--dry-run", "calendar", "create", "primary", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z", "--event-type", "out-of-office"},
		{"--dry-run", "calendar", "create", "primary", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z", "--event-type", "ooo", "--ooo-auto-decline", "none"},
		{"--dry-run", "calendar", "create", "primary", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z", "--event-type", "focus-time"},
		{"--dry-run", "calendar", "create", "primary", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z", "--focus-auto-decline", "all"},
		{"--dry-run", "calendar", "update", "primary", "e1", "--ooo-auto-decline", "all"},
		{"--dry-run", "calendar", "update", "primary", "e1", "--focus-decline-message", "busy"},
		{"--dry-run", "calendar", "create", "primary", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z", "--focus-chat-status", "doNotDisturb"},
	}
	for _, args := range refused {
		err := Execute(args)
		if err == nil || !strings.Contains(err.Error(), "baked safety profile") {
			t.Errorf("expected auto-decline refusal for %v, got %v", args, err)
		}
	}
	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"--dry-run", "calendar", "create", "primary", "--summary", "gym", "--from", "2026-12-01T10:00:00Z", "--to", "2026-12-01T11:00:00Z"}); err != nil {
				t.Errorf("ordinary event refused: %v", err)
			}
		})
	})
}

func TestOikosProfileRefusesTemporaryPublicImages(t *testing.T) {
	setTestConfigHome(t)
	_, _ = loadOikosProfile(t)
	err := refusePublicShareUnderProfile("image.png")
	if err == nil || !strings.Contains(err.Error(), "baked safety profile") {
		t.Fatalf("expected public-share refusal, got %v", err)
	}
}

// A command group mounted twice must get the same decision under both paths.
func TestOikosProfileTreatsGmailSettingsMountsAlike(t *testing.T) {
	setTestConfigHome(t)
	tree := stockCommandTree(t)
	profile, _ := loadOikosProfile(t)
	for path := range tree {
		rest, ok := strings.CutPrefix(path, "gmail.settings.")
		if !ok {
			continue
		}
		mirror := "gmail." + rest
		if tree[mirror] == nil {
			continue
		}
		settings := profile.allowsCommandPath(strings.Split(path, "."))
		hidden := profile.allowsCommandPath(strings.Split(mirror, "."))
		if hidden && !settings {
			t.Errorf("%s is blocked but its hidden mount %s is allowed", path, mirror)
		}
	}
}
