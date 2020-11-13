package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	cmputils "github.com/pangine/disasm-eval-cmp/cmputils"
	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	rstapi "github.com/pangine/pangineDSM-import/rstAPI"
	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"
	genutils "github.com/pangine/pangineDSM-utils/general"
	mcclient "github.com/pangine/pangineDSM-utils/mcclient"
	objectapi "github.com/pangine/pangineDSM-utils/objectAPI"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

type funcRange struct {
	start int
	end   int
}

func printHeader() {
	fmt.Print("file, ")
	fmt.Print("insts, ")

	fmt.Print("ls_tp, ")
	fmt.Print("ls_fp, ")
	fmt.Print("ls_fn, ")

	fmt.Print("bap_tp, ")
	fmt.Print("bap_fp, ")
	fmt.Print("bap_fn, ")

	fmt.Print("ghi_tp, ")
	fmt.Print("ghi_fp, ")
	fmt.Print("ghi_fn, ")

	fmt.Print("r2_tp, ")
	fmt.Print("r2_fp, ")
	fmt.Print("r2_fn, ")

	fmt.Print("rse_tp, ")
	fmt.Print("rse_fp, ")
	fmt.Print("rse_fn, ")

	fmt.Print("ddm_tp, ")
	fmt.Print("ddm_fp, ")
	fmt.Print("ddm_fn\n")
}

func runLS(cmd string, fin string, fout string) {
	var dsa *exec.Cmd
	dsa = exec.Command(cmd, "-f", fin, "-o", fout)
	errin := dsa.Start()
	if errin != nil {
		fmt.Println(dsa.Args)
		panic(errin)
	}
	dsa.Wait()
}

func matchRef(
	ref []cmputils.InsnRow,
	dsm []int,
	fses []gtutils.FuncRow,
	ioff int,
	errorMode bool,
	bi pstruct.BinaryInfo,
) (
	tp int,
	fp int,
	fn int,
) {
	lref := len(ref)
	ldsm := len(dsm)
	pr, pd := 0, 0
	i := 0
	for pr < lref && pd < ldsm {
		dsmoff := dsm[pd] - ioff
		for ; i < len(fses) && dsmoff >= fses[i].End; i++ {
		}
		if i >= len(fses) {
			break
		}
		if dsmoff < fses[i].Start {
			pd++
		} else if ref[pr].Offset == dsmoff {
			if !ref[pr].Supplementary.Optional {
				tp++
			}
			pr++
			pd++
		} else if ref[pr].Offset < dsmoff {
			if !ref[pr].Supplementary.Optional {
				fn++
				if errorMode {
					res := mcclient.SendResolve(
						pstruct.V2PConv(bi.ProgramHeaders, ref[pr].Offset),
						bi.Sections.Data)
					inst, _ := res.Inst()
					fmt.Printf("%d\t(0x%x):%s\t|false negative\n", ref[pr].Offset, ref[pr].Offset, inst)
				}
			}
			pr++
		} else {
			fp++
			if errorMode {
				res := mcclient.SendResolve(
					pstruct.V2PConv(bi.ProgramHeaders, dsm[pd]),
					bi.Sections.Data)
				inst, _ := res.Inst()
				fmt.Printf("%d\t(0x%x):%s\t|false positive\n", dsm[pd], dsm[pd], inst)
			}
			pd++
		}
	}
	for i := pr; i < lref; i++ {
		if !ref[i].Supplementary.Optional {
			fn++
		}
	}
	return
}

func calCorrectness(
	ref []cmputils.InsnRow,
	fses []gtutils.FuncRow,
	ioff int,
	out []int,
	ending string,
	errorMode bool,
	bi pstruct.BinaryInfo,
	title string,
) {
	if errorMode {
		fmt.Printf("++++++++++%s errors++++++++++\n", title)
	}
	tp, fp, fn := matchRef(ref, out, fses, ioff, errorMode, bi)
	if !errorMode {
		fmt.Printf("%d, %d, %d%s", tp, fp, fn, ending)
	}
}

func main() {
	argNum := len(os.Args)
	inputDir := os.Args[argNum-1]

	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	errorFlag := flag.Bool("e", false, "run in error checking mode")
	singleTargetFlag := flag.String("sf", "", "only operate on a single file")
	singleDirFlag := flag.String("sd", "", "only operate on a single dir")
	rvlISAFlag := flag.String("ra", "", "specify a ISA to start llvmmc-resolver (by default it will be auto detected according to input llvm triple)")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")
	flag.Parse()
	llvmTriple := *ltFlag
	errorMode := *errorFlag
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

	var object objectapi.Object
	switch osEnvObj {
	case "Linux-GNU-ELF":
		object = objx86elf.ObjectElf{}
	case "Win32-MSVC-COFF":
		object = objx86coff.ObjectCoff{}
	}

	gtRoot := filepath.Join(inputDir, "gt")
	bapRoot := filepath.Join(inputDir, "bap")
	ghiRoot := filepath.Join(inputDir, "ghidra")
	ddmRoot := filepath.Join(inputDir, "ddisasm")
	r2Root := filepath.Join(inputDir, "radare2")
	rseRoot := filepath.Join(inputDir, "rose")
	binRoot := filepath.Join(inputDir, "bin")
	lsRoot := filepath.Join(inputDir, "ls")

	if !errorMode {
		printHeader()
	}

	var dirList []string
	if singleDir != "" {
		dirList = []string{singleDir}
	} else {
		dirList = genutils.GetDirs(binRoot)
	}

	for _, dir := range dirList {
		gtDir := filepath.Join(gtRoot, dir)
		bapDir := filepath.Join(bapRoot, dir)
		ghiDir := filepath.Join(ghiRoot, dir)
		ddmDir := filepath.Join(ddmRoot, dir)
		r2Dir := filepath.Join(r2Root, dir)
		rseDir := filepath.Join(rseRoot, dir)
		binDir := filepath.Join(binRoot, dir)
		lsDir := filepath.Join(lsRoot, dir)

		var fileList []string
		if singleTarget != "" && singleDir != "" {
			fileList = []string{singleTarget}
		} else {
			fileList = genutils.GetFiles(binDir, "")
		}
		fmt.Println(dir)

		for _, file := range fileList {
			refFile := filepath.Join(gtDir, file+".sqlite")

			if _, err := os.Stat(refFile); os.IsNotExist(err) {
				continue
			}

			fmt.Printf("%s, ", file)

			binFile := filepath.Join(binDir, file)

			insnMap, funcMap := gtutils.ReadSqliteGt(refFile)
			refAry := make([]cmputils.InsnRow, 0)
			var MandatoryCount int
			for offset, supplementary := range insnMap {
				refAry = append(refAry, cmputils.InsnRow{
					Offset:        offset,
					Supplementary: supplementary})
				if !supplementary.Optional {
					MandatoryCount++
				}
			}
			sort.SliceStable(refAry, func(i, j int) bool {
				return refAry[i].Offset < refAry[j].Offset
			})
			fses := make([]gtutils.FuncRow, 0)
			for f := range funcMap {
				fses = append(fses, f)
			}
			sort.SliceStable(fses, func(i, j int) bool {
				return fses[i].Start < fses[j].Start
			})

			fmt.Printf("%d, ", MandatoryCount)
			if errorMode {
				fmt.Println()
			}
			bi := object.ParseObj(binFile)

			lsoutFile := filepath.Join(lsDir, file+".sqlite3")
			lsAry := make([]int, 0)

			var lsRst []genutils.InsnRst
			if _, err := os.Stat(lsoutFile); err == nil {
				lsRst = genutils.ReadSqliteRstInsnAll(lsoutFile)
			}
			for _, r := range lsRst {
				lsAry = append(lsAry, r.Offset)
			}
			sort.Ints(lsAry)

			calCorrectness(refAry, fses, 0, lsAry, ", ", errorMode, bi, "ls")

			bapLog := filepath.Join(bapDir, file+"_bap.out")
			bapAry, _ := rstapi.ReadRst(bapLog)
			sort.Ints(bapAry)
			calCorrectness(refAry, fses, 0, bapAry, ", ", errorMode, bi, "bap")

			ghiLog := filepath.Join(ghiDir, file+"_ghidra.out")
			ghAry, _ := rstapi.ReadRst(ghiLog)
			sort.Ints(ghAry)
			calCorrectness(refAry, fses, 0, ghAry, ", ", errorMode, bi, "ghidra")

			r2Log := filepath.Join(r2Dir, file+"_r2.out")
			r2Ary, _ := rstapi.ReadRst(r2Log)
			sort.Ints(r2Ary)
			calCorrectness(refAry, fses, 0, r2Ary, ", ", errorMode, bi, "r2")

			rseLog := filepath.Join(rseDir, file+"_rose.out")
			rseAry, _ := rstapi.ReadRst(rseLog)
			sort.Ints(rseAry)
			calCorrectness(refAry, fses, 0, rseAry, ", ", errorMode, bi, "rose")

			ddmLog := filepath.Join(ddmDir, file+"_ddisasm.out")
			ddmAry, _ := rstapi.ReadRst(ddmLog)
			sort.Ints(ddmAry)
			calCorrectness(refAry, fses, 0, ddmAry, "\n", errorMode, bi, "ddisasm")

			if errorMode {
				fmt.Printf("----------%s end----------\n", file)
			}
		}
	}
	resolver.Process.Kill()
}
