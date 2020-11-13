package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"

	cmputils "github.com/pangine/disasm-eval-cmp/cmputils"
	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	rstapi "github.com/pangine/pangineDSM-import/rstAPI"
	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"
	genutils "github.com/pangine/pangineDSM-utils/general"
	objectapi "github.com/pangine/pangineDSM-utils/objectAPI"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

func main() {
	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	fileFlag := flag.String("f", "", "Input file")
	entryFlag := flag.String("e", "", "Input file for print")
	typeFlag := flag.String("t", "pangine-all", "I/O type, can be: capnp, gt, ls")
	rvlISAFlag := flag.String("ra", "", "specify a ISA to start llvmmc-resolver (by default it will be auto detected according to input llvm triple)")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")
	flag.Parse()
	llvmTriple := *ltFlag
	file := *fileFlag
	entryFile := *entryFlag
	t := *typeFlag
	rvlISA := *rvlISAFlag
	printLLVM := *printFlag

	if printLLVM {
		genutils.PrintSupportLlvmTriple(gtutils.LLVMTriples)
		return
	}
	llvmTripleStruct := genutils.ParseLlvmTriple(genutils.CheckLlvmTriple(llvmTriple, cmputils.LLVMTriples))
	osEnvObj := llvmTripleStruct.OS + "-" + llvmTripleStruct.Env + "-" + llvmTripleStruct.Obj

	if rvlISA == "" {
		rvlISA = llvmTripleStruct.Arch
	}

	fmt.Println("Start llvmmc-resolver...")
	resolver := exec.Command("resolver", "-p", rvlISA)
	resolver.Start()
	time.Sleep(time.Second)

	var object objectapi.Object
	switch osEnvObj {
	case "Linux-GNU-ELF":
		object = objx86elf.ObjectElf{}
	case "Win32-MSVC-COFF":
		object = objx86coff.ObjectCoff{}
	}

	bi := object.ParseObj(file)
	lowbound := pstruct.P2VConv(bi.ProgramHeaders, 0)
	upbound := pstruct.P2VConv(bi.ProgramHeaders, len(bi.Sections.Data))
	instList := make(map[int]pstruct.InstFlags)

	var insn, fs []int
	switch t {
	case "capnp":
		insn, fs = rstapi.ReadRst(entryFile)
	case "gt":
		insn = make([]int, 0)
		fs = make([]int, 0)
		InsnMap, FsMap := gtutils.ReadSqliteGt(entryFile)
		for i := range InsnMap {
			insn = append(insn, i)
		}
		for f := range FsMap {
			fs = append(fs, f.Start)
		}
	case "ls":
		// Pangine output sqlite type
		sqlInsn := genutils.ReadSqliteRstInsnAll(entryFile)
		fs = genutils.ReadSqliteRstFunc(entryFile)
		sqlBT := genutils.ReadSqliteRstBT(entryFile)
		for _, r := range sqlInsn {
			if _, ok := sqlBT[r.ID]; ok {
				insn = append(insn, r.Offset)
			}
		}
	default:
		fmt.Println("unsupported input type")
		return
	}
	sort.Ints(insn)
	sort.Ints(fs)
	objectapi.ListAdd2Inst(bi, insn, instList, object)
	rstapi.WriteRst(true, instList, fs, os.Stdout, lowbound, upbound)
	resolver.Process.Kill()
}
