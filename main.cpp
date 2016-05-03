#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/Interpreter.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/LinkAllAsmWriterComponents.h"
#include "llvm/CodeGen/LinkAllCodegenComponents.h"
#include "llvm/CodeGen/MIRParser/MIRParser.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PluginLoader.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetSubtargetInfo.h"
#include <memory>

using namespace llvm;

int readNValue(std::string matrixName) {
    int n;
    std::ifstream infoFile;
    infoFile.open("../" + matrixName + "/" + matrixName + "_CSRbyNZ/info.csv");
    std::string token;
    while(getline(infoFile, token, ',')) {
        if(token == " n") {
            getline(infoFile, token, ',');
            n = std::stoi(token);
            return n;
        }
    }
    return 0;
}

static std::unique_ptr<tool_output_file>
GetOutputStream(const char *TargetName, Triple::OSType OS,
                const char *ProgName, std::string InputFilename) {
    // If we don't yet have an output filename, make one.
    std::string OutputFilename;
    if (OutputFilename.empty()) {
        if (InputFilename == "-")
            OutputFilename = "-";
        else {
            // If InputFilename ends in .bc or .ll, remove it.
            StringRef IFN = InputFilename;
            if (IFN.endswith(".bc") || IFN.endswith(".ll"))
                OutputFilename = IFN.drop_back(3);
            else if (IFN.endswith(".mir"))
                OutputFilename = IFN.drop_back(4);
            else
                OutputFilename = IFN;

            switch (FileType) {
                case TargetMachine::CGFT_AssemblyFile:
                    if (TargetName[0] == 'c') {
                        if (TargetName[1] == 0)
                            OutputFilename += ".cbe.c";
                        else if (TargetName[1] == 'p' && TargetName[2] == 'p')
                            OutputFilename += ".cpp";
                        else
                            OutputFilename += ".s";
                    } else
                        OutputFilename += ".s";
                    break;
                case TargetMachine::CGFT_ObjectFile:
                    if (OS == Triple::Win32)
                        OutputFilename += ".obj";
                    else
                        OutputFilename += ".o";
                    break;
                case TargetMachine::CGFT_Null:
                    OutputFilename += ".null";
                    break;
            }
        }
    }

    // Decide if we need "binary" output.
    bool Binary = false;
    switch (FileType) {
        case TargetMachine::CGFT_AssemblyFile:
            break;
        case TargetMachine::CGFT_ObjectFile:
        case TargetMachine::CGFT_Null:
            Binary = true;
            break;
    }

    // Open the file.
    std::error_code EC;
    sys::fs::OpenFlags OpenFlags = sys::fs::F_None;
    if (!Binary)
        OpenFlags |= sys::fs::F_Text;
    auto FDOut = llvm::make_unique<tool_output_file>(OutputFilename, EC,
                                                     OpenFlags);
    if (EC) {
        errs() << EC.message() << '\n';
        return nullptr;
    }

    return FDOut;
}

int main(int argc, char** argv) {

    if(argc != 2) {
        errs() << "No matrix name given!";
        return 1;
    }

    FileType = TargetMachine::CGFT_ObjectFile;

    std::string matrixName = argv[1];
//    outs() << "Running benchmarks on " << matrixName << ".\n";

    InitializeNativeTarget();
    InitializeAllTargetMCs();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    LLVMContext Context;
    SMDiagnostic diag;
    std::unique_ptr<MIRParser> MIR;


    std::string filePath = "../" + matrixName + "/" + matrixName + "_CSRbyNZ/generated_merged.ll";

    std::unique_ptr<Module> M = parseIRFile(filePath, diag, Context);
    if (!M) {
        errs() << "No such matrix";
        return 1;
    }

    //begin llc-like implementation
    if (verifyModule(*M, &errs())) {
        errs() << argv[0] << ": " << filePath
        << ": error: input module is broken!\n";
        return 1;
    }

    Triple TheTriple = Triple(M->getTargetTriple());

    std::string Error;
    const Target *TheTarget = TargetRegistry::lookupTarget(MArch, TheTriple,
                                                           Error);

    std::string CPUStr = getCPUStr(), FeaturesStr = getFeaturesStr();

    CodeGenOpt::Level OLvl = CodeGenOpt::Default;
    switch ('0') {
        default:
            errs() << argv[0] << ": invalid optimization level.\n";
            return 1;
        case ' ': break;
        case '0': OLvl = CodeGenOpt::None; break;
        case '1': OLvl = CodeGenOpt::Less; break;
        case '2': OLvl = CodeGenOpt::Default; break;
        case '3': OLvl = CodeGenOpt::Aggressive; break;
    }

    TargetOptions Options = InitTargetOptionsFromCodeGenFlags();
//    Options.DisableIntegratedAS = NoIntegratedAssembler;
//    Options.MCOptions.ShowMCEncoding = ShowMCEncoding;
//    Options.MCOptions.MCUseDwarfDirectory = EnableDwarfDirectory;
//    Options.MCOptions.AsmVerbose = AsmVerbose;

    std::unique_ptr<TargetMachine> Target(
            TheTarget->createTargetMachine(TheTriple.getTriple(), CPUStr, FeaturesStr,
                                           Options, RelocModel , CMModel, OLvl));

    assert(Target && "Could not allocate target machine!");

    std::unique_ptr<tool_output_file> Out =
            GetOutputStream(TheTarget->getName(), TheTriple.getOS(), argv[0], matrixName);
    if (!Out) return 1;

    legacy::PassManager PM;

    TargetLibraryInfoImpl TLII(Triple(M->getTargetTriple()));

//    if (DisableSimplifyLibCalls)
//        TLII.disableAllFunctions();

    PM.add(new TargetLibraryInfoWrapperPass(TLII));

    if (const DataLayout *DL = Target->getDataLayout())
        M->setDataLayout(*DL);

    setFunctionAttributes(CPUStr, FeaturesStr, *M);


    if (RelaxAll.getNumOccurrences() > 0 &&
        FileType != TargetMachine::CGFT_ObjectFile)
        errs() << argv[0]
        << ": warning: ignoring -mc-relax-all because filetype != obj";

    {
        SmallVector<char, 1024*1024*4> *smallVector = new SmallVector<char, 1024*1024*4>();
        raw_svector_ostream svectorOS(*smallVector);

        FileType = TargetMachine::CGFT_ObjectFile;

        raw_pwrite_stream *OS = &svectorOS;
        std::unique_ptr<buffer_ostream> BOS;
        if (FileType != TargetMachine::CGFT_AssemblyFile &&
            !Out->os().supportsSeeking()) {
            BOS = make_unique<buffer_ostream>(*OS);
            OS = BOS.get();
        }

        AnalysisID StartBeforeID = nullptr;
        AnalysisID StartAfterID = nullptr;
        AnalysisID StopAfterID = nullptr;
        const PassRegistry *PR = PassRegistry::getPassRegistry();
        if (!RunPass.empty()) {
            if (!StartAfter.empty() || !StopAfter.empty()) {
                errs() << argv[0] << ": start-after and/or stop-after passes are "
                        "redundant when run-pass is specified.\n";
                return 1;
            }
            const PassInfo *PI = PR->getPassInfo(RunPass);
            if (!PI) {
                errs() << argv[0] << ": run-pass pass is not registered.\n";
                return 1;
            }
            StopAfterID = StartBeforeID = PI->getTypeInfo();
        } else {
            if (!StartAfter.empty()) {
                const PassInfo *PI = PR->getPassInfo(StartAfter);
                if (!PI) {
                    errs() << argv[0] << ": start-after pass is not registered.\n";
                    return 1;
                }
                StartAfterID = PI->getTypeInfo();
            }
            if (!StopAfter.empty()) {
                const PassInfo *PI = PR->getPassInfo(StopAfter);
                if (!PI) {
                    errs() << argv[0] << ": stop-after pass is not registered.\n";
                    return 1;
                }
                StopAfterID = PI->getTypeInfo();
            }
        }

        // Ask the target to add backend passes as necessary.
        /* Wrote "true" in place of "NoVerify" */
        if (Target->addPassesToEmitFile(PM, *OS, TargetMachine::CGFT_AssemblyFile, true, StartBeforeID,
                                        StartAfterID, StopAfterID, MIR.get())) {
            errs() << argv[0] << ": target does not support generation of this"
            << " file type!\n";
            return 1;
        }

        // Before executing passes, print the final values of the LLVM options.
        cl::PrintOptionValues();

        PM.run(*M);

        outs() << svectorOS.str().str();
    }


    llvm_shutdown();
    return 0;
}

