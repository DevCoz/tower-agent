package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Run the actual shell installer against fake downloads, never touching /opt.
func TestBootstrap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX bootstrap runs in Linux CI")
	}
	if !exists("dist/install.sh") {
		t.Skip("run scripts/build.mjs first")
	}
	template := read(t, "scripts/install.sh.in")
	for _, scenario := range []string{"success", "bad-checksum", "download-failure", "unsupported-arch", "wrong-version"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			requireNoError(t, os.MkdirAll(bin, 0700))
			installed := filepath.Join(root, "installed")
			download := filepath.Join(root, "download")
			stageBase := filepath.Join(root, "opt", "tower-agent")
			payload := "#!/bin/sh\nif [ \"$1\" = version ]; then printf '%s\\n' 'Tower Agent v1.0.0 (protocol 2)'; else printf '%s\\n' \"$@\" > '" + installed + "'; fi\n"
			if scenario == "wrong-version" {
				payload = strings.ReplaceAll(payload, "v1.0.0", "v0.0.0")
			}
			requireNoError(t, os.WriteFile(download, []byte(payload), 0700))
			checksum := digest(payload)
			if scenario == "bad-checksum" {
				checksum = strings.Repeat("0", 64)
			}
			installer := strings.NewReplacer("__VERSION__", "v1.0.0", "__AMD64_SHA256__", checksum, "__ARM64_SHA256__", checksum, "/opt/tower-agent", stageBase).Replace(template)
			path := filepath.Join(root, "install.sh")
			requireNoError(t, os.WriteFile(path, []byte(installer), 0700))
			arch := "x86_64"
			if scenario == "unsupported-arch" {
				arch = "mips"
			}
			mocks := map[string]string{"id": "#!/bin/sh\necho 0\n", "uname": "#!/bin/sh\nif [ \"$1\" = -s ]; then echo Linux; else echo " + arch + "; fi\n", "curl": "#!/bin/sh\nfor last; do :; done\ncp '" + download + "' \"$last\"\n"}
			if scenario == "download-failure" {
				mocks["curl"] = "#!/bin/sh\nexit 22\n"
			}
			for name, content := range mocks {
				requireNoError(t, os.WriteFile(filepath.Join(bin, name), []byte(content), 0700))
			}
			cmd := exec.Command("sh", path, "install", "--url", "https://panel.test", "--id", "11223344-5566-4788-99aa-bbccddeeff00")
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if scenario == "success" {
				requireNoError(t, err)
				if !strings.Contains(read(t, installed), "--url\nhttps://panel.test") {
					t.Fatal("arguments not forwarded")
				}
			} else {
				if err == nil || exists(installed) {
					t.Fatalf("unverified program executed: %s", output)
				}
			}
			matches, err := filepath.Glob(filepath.Join(stageBase, ".bootstrap.*"))
			requireNoError(t, err)
			if len(matches) != 0 {
				t.Fatal("bootstrap temporary files remain")
			}
		})
	}
}
