# Disassembler Evaluation - Comparison Toolkit

The toolkit to compare, print, and summarize statistical characteristics on disassembler results and ground truth

This packages includes 3 executables:
 - disasm-eval-cmp: compare disassembler results with ground truth
 - disasm-eval-print: print the disassembler results or ground truth to human-reader-friendly text files
 - disasm-gt-chrct: summarize statistical characteristics on disassembly ground truth

This repo is just for research experimental usage, and may not be well-maintained.

The data needs to be given in the format of the output of [disasm-eval-sources](https://github.com/pangine/disasm-eval-sources), [disasm-gt-generator](https://github.com/pangine/disasm-gt-generator), and [disasm-eval-disasms](https://github.com/pangine/disasm-eval-disasms).

It is highly recommend to use docker images for execution.

------------------------------
To build the Docker image:

You need to install the docker image [llvmmc-resolver](https://github.com/pangine/llvmmc-resolver) before running this.

```bash
docker build -t pangine/cmp .
```

------------------------------
To use the toolkit inside the container:

Assume that you have a compiled projects folder at */path_to_test_cases/x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3*, and the project you want to operate on is **openssh-7.1p2** (there should be a *bin/openssh-7.1p2* subdirectory inside the compiled projects folder).

The llvm triple for this test case should be **x86_64-pc-linux-gnu-elf**

Make sure you have already run the ground truth generator and the disassemblers on the binary.

### disasm-eval-cmp
To compare disassembler results with the ground truth:
```bash
OUTPUTDIR="/path_to_test_cases"
TESTCASE="x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3"
LLVMTRIPLE="x86_64-pc-linux-gnu-elf"
PROJECTNAME="openssh-7.1p2"

docker run --rm -it -v ${OUTPUTDIR}:/output \
-e LLVMTRIPLE="${LLVMTRIPLE}" \
-e TESTCASE="${TESTCASE}" \
-e PROJECTNAME="${PROJECTNAME}" \
pangine/cmp /bin/bash -c \
'disasm-eval-cmp -l ${LLVMTRIPLE} -sd "${PROJECTNAME}" /output/"${TESTCASE}"' |& tee ${PROJECTNAME}_result.csv
```

You can choose not to use the **-sd** argument, and the tool will compare all the test cases in projects folder.

### disasm-eval-print
To print the Ghidra disassembler result on the `sshd` binary into human readable text file:
```bash
OUTPUTDIR="/path_to_test_cases"
TESTCASE="x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3"
LLVMTRIPLE="x86_64-pc-linux-gnu-elf"
PROJECTNAME="openssh-7.1p2"
BINARY="sshd"
DISASM="ghidra"

docker run --rm -it -v ${OUTPUTDIR}:/output \
-e LLVMTRIPLE="${LLVMTRIPLE}" \
-e TESTCASE="${TESTCASE}" \
-e PROJECTNAME="${PROJECTNAME}" \
-e BINARY="${BINARY}" \
-e DISASM="${DISASM}" \
pangine/cmp /bin/bash -c \
'disasm-eval-print -l ${LLVMTRIPLE} -f /output/"${TESTCASE}"/bin/"${PROJECTNAME}"/"${BINARY}" -e /output/"${TESTCASE}"/"${DISASM}"/"${PROJECTNAME}"/"${BINARY}"_"${DISASM}".out -t capnp' | tee ${DISASM}_result.out
```

The `-t` argument should should be set to `capnp` for disassembler results, `gt` for ground truth, `ls` for pangine linear sweep (a toy linear sweep implementation only for experimental purpose, may not be public at this moment).

### disasm-gt-chrct
To get the characteristics for the project:
```bash
OUTPUTDIR="/path_to_test_cases"
TESTCASE="x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3"
LLVMTRIPLE="x86_64-pc-linux-gnu-elf"
PROJECTNAME="openssh-7.1p2"

docker run --rm -it -v ${OUTPUTDIR}:/output \
-e LLVMTRIPLE="${LLVMTRIPLE}" \
-e TESTCASE="${TESTCASE}" \
-e PROJECTNAME="${PROJECTNAME}" \
pangine/cmp /bin/bash -c \
'disasm-gt-chrct -l ${LLVMTRIPLE} -sd "${PROJECTNAME}" /output/"${TESTCASE}"' |& tee ${PROJECTNAME}_chrct.out
```

You can choose not to use the **-sd** argument, and the tool will run on all the test cases in projects folder.
