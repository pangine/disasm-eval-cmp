package utils

import (
	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
)

//InsnRow is gt sqlite row in go format
type InsnRow struct {
	Offset        int
	Supplementary gtutils.InsnSupplementary
}
