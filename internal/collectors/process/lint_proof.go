package process

import (
	"os"
	"os/exec"
)

// LintProof deliberately violates CLAUDE.md 1.2. This branch must fail CI.
func LintProof() {
	_ = exec.Command("powershell", "-NoProfile").Run()
	_ = os.WriteFile(`C:\Windows\Temp\canaveral.txt`, nil, 0o600)
}
