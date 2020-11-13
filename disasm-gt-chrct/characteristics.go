package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	cmputils "github.com/pangine/disasm-eval-cmp/cmputils"
	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"
	genutils "github.com/pangine/pangineDSM-utils/general"
	"github.com/pangine/pangineDSM-utils/mcclient"
	objectapi "github.com/pangine/pangineDSM-utils/objectAPI"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

func sizeDir(path string) (dirSize int) {
	var intSize int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			intSize += info.Size()
		}
		return err
	})
	dirSize = int(intSize)
	return
}

func main() {
	argNum := len(os.Args)
	inputDir := os.Args[argNum-1]

	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	singleTargetFlag := flag.String("sf", "", "only operate on a single file")
	singleDirFlag := flag.String("sd", "", "only operate on a single dir")
	rvlISAFlag := flag.String("ra", "", "specify a ISA to start llvmmc-resolver (by default it will be auto detected according to input llvm triple)")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")

	flag.Parse()
	llvmTriple := *ltFlag
	singleDir := *singleDirFlag
	singleTarget := *singleTargetFlag
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
	defer resolver.Process.Kill()

	var object objectapi.Object
	switch osEnvObj {
	case "Linux-GNU-ELF":
		object = objx86elf.ObjectElf{}
	case "Win32-MSVC-COFF":
		object = objx86coff.ObjectCoff{}
	}

	gtRoot := filepath.Join(inputDir, "gt")
	binRoot := filepath.Join(inputDir, "bin")

	var dirList []string
	if singleDir != "" {
		dirList = []string{singleDir}
	} else {
		dirList = genutils.GetDirs(binRoot)
	}

	var totalInsn, totalFunc, totalIndJ, maxBinSize, minBinSize, totalBinSize, totalGTSize, totalSize int
	minBinSize = int(^uint(0) >> 1)

	insnSet := make(map[string]bool)

	for _, dir := range dirList {
		gtDir := filepath.Join(gtRoot, dir)
		binDir := filepath.Join(binRoot, dir)

		var fileList []string
		if singleTarget != "" && singleDir != "" {
			fileList = []string{singleTarget}
		} else {
			fileList = genutils.GetFiles(binDir, "")
		}

		fmt.Printf("Characteristic of %s:\n", dir)
		fmt.Println("-----------------------")

		gtDirSize := sizeDir(gtDir)
		fmt.Printf("GT dir size: %d\n", gtDirSize)
		totalGTSize += gtDirSize
		totalSize += gtDirSize

		for _, file := range fileList {
			refFile := filepath.Join(gtDir, file+".sqlite")
			binFile := filepath.Join(binDir, file)
			bi := object.ParseObj(binFile)

			var fileSize int
			if fi, err := os.Stat(binFile); os.IsNotExist(err) {
				continue
			} else {
				fileSize = int(fi.Size())
			}
			fmt.Printf("%s file size: %d\n", file, fileSize)
			if fileSize > maxBinSize {
				maxBinSize = fileSize
			}
			if fileSize < minBinSize {
				minBinSize = fileSize
			}
			totalBinSize += fileSize
			totalSize += fileSize

			insnMap, funcMap := gtutils.ReadSqliteGt(refFile)
			var sizeInsn, numIndJ int
			for offset, supplementary := range insnMap {
				if !supplementary.Optional {
					sizeInsn++
					res := mcclient.SendResolve(
						pstruct.V2PConv(
							bi.ProgramHeaders, offset),
						bi.Sections.Data)
					if !res.IsInst() || res.TakeBytes() == 0 {
						continue
					}
					instStr, _ := res.Inst()
					typeInst := object.TypeInst(instStr, int(res.TakeBytes()))
					if typeInst.IsIndJmp {
						numIndJ++
					}
					// Count instruction mnemonic
					insnFields := strings.Fields(instStr)
					if len(insnFields) > len(typeInst.Prefixes) {
						insnMne := insnFields[len(typeInst.Prefixes)]
						insnSet[insnMne] = true
					}
					for _, p := range typeInst.Prefixes {
						insnSet[p] = true
					}
				}
			}
			sizeFunc := len(funcMap)
			fmt.Printf("%s Func num: %d\n", file, sizeFunc)
			fmt.Printf("%s Insn num: %d\n", file, sizeInsn)
			fmt.Printf("%s IndJ num: %d\n", file, numIndJ)
			totalFunc += sizeFunc
			totalInsn += sizeInsn
			totalIndJ += numIndJ
		}
		fmt.Println("-----------------------")
	}
	fmt.Println("Complete info:")
	fmt.Printf("Total size: %d\n", totalSize)
	fmt.Printf("Total bin size: %d\n", totalBinSize)
	fmt.Printf("Total gt size: %d\n", totalGTSize)
	fmt.Printf("Max bin size: %d\n", maxBinSize)
	fmt.Printf("Min bin size: %d\n", minBinSize)
	fmt.Printf("Total Func num: %d\n", totalFunc)
	fmt.Printf("Total Insn num: %d\n", totalInsn)
	fmt.Printf("Total IndJ num: %d\n", totalIndJ)
	fmt.Printf("Totol Insn mnemonic set:")
	for insn := range insnSet {
		fmt.Printf(" %s", insn)
	}
	fmt.Println()
}
