#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/LinkAllAsmWriterComponents.h"
#include "llvm/CodeGen/LinkAllCodegenComponents.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
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
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/Target/TargetMachine.h"
#include <memory>

#include "llvm/ADT/StringMap.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/ExecutionEngine/ObjectBuffer.h"
#include "llvm/ExecutionEngine/ObjectImage.h"
#include "llvm/ExecutionEngine/RuntimeDyld.h"
#include "llvm/ExecutionEngine/RuntimeDyldChecker.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Object/MachO.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Memory.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include <system_error>


using namespace llvm;
using namespace llvm::object;

int readNValue(std::string matrixName) {
    int n;
    std::ifstream infoFile;
    infoFile.open("data/" + matrixName + "/" + matrixName + "_CSRbyNZ/info.csv");
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

// A trivial memory manager that doesn't do anything fancy, just uses the
// support library allocation routines directly.
class TrivialMemoryManager : public RTDyldMemoryManager {
public:
    SmallVector<sys::MemoryBlock, 16> FunctionMemory;
    SmallVector<sys::MemoryBlock, 16> DataMemory;
    
    uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                                 unsigned SectionID,
                                 StringRef SectionName) override;
    uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                                 unsigned SectionID, StringRef SectionName,
                                 bool IsReadOnly) override;
    
    void *getPointerToNamedFunction(const std::string &Name,
                                    bool AbortOnFailure = true) override {
        return nullptr;
    }
    
    bool finalizeMemory(std::string *ErrMsg) override { return false; }
    
    // Invalidate instruction cache for sections with execute permissions.
    // Some platforms with separate data cache and instruction cache require
    // explicit cache flush, otherwise JIT code manipulations (like resolved
    // relocations) will get to the data cache but not to the instruction cache.
    virtual void invalidateInstructionCache();
};

uint8_t *TrivialMemoryManager::allocateCodeSection(uintptr_t Size,
                                                   unsigned Alignment,
                                                   unsigned SectionID,
                                                   StringRef SectionName) {
    sys::MemoryBlock MB = sys::Memory::AllocateRWX(Size, nullptr, nullptr);
    FunctionMemory.push_back(MB);
    return (uint8_t*)MB.base();
}

uint8_t *TrivialMemoryManager::allocateDataSection(uintptr_t Size,
                                                   unsigned Alignment,
                                                   unsigned SectionID,
                                                   StringRef SectionName,
                                                   bool IsReadOnly) {
    sys::MemoryBlock MB = sys::Memory::AllocateRWX(Size, nullptr, nullptr);
    DataMemory.push_back(MB);
    return (uint8_t*)MB.base();
}

void TrivialMemoryManager::invalidateInstructionCache() {
    for (int i = 0, e = FunctionMemory.size(); i != e; ++i)
        sys::Memory::InvalidateInstructionCache(FunctionMemory[i].base(),
                                                FunctionMemory[i].size());
    
    for (int i = 0, e = DataMemory.size(); i != e; ++i)
        sys::Memory::InvalidateInstructionCache(DataMemory[i].base(),
                                                DataMemory[i].size());
}


int main(int argc, char** argv) {

    if(argc != 2) {
        errs() << "No matrix name given!";
        return 1;
    }

    std::string matrixName = argv[1];
    outs() << "Running benchmarks on " << matrixName << ".\n";

    InitializeNativeTarget();
    InitializeAllTargetMCs();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    LLVMContext Context;
    SMDiagnostic diag;

    std::string filePath = "data/" + matrixName + "/" + matrixName + "_CSRbyNZ/generated_merged.ll";
    std::unique_ptr<Module> M;
    Module *mod = nullptr;
    M.reset(ParseIRFile(filePath, diag, Context));
    mod = M.get();
    
    if (mod == nullptr) {
        errs() << "No such matrix";
        return 1;
    }
    
    Triple TheTriple = Triple(mod->getTargetTriple());

    std::string Error;
    const Target *TheTarget = TargetRegistry::lookupTarget(MArch, TheTriple,
                                                           Error);

    std::string MCPU = "";
    std::string FeaturesStr = "";
    
    CodeGenOpt::Level OLvl = CodeGenOpt::Default;
    FileType = TargetMachine::CGFT_ObjectFile;

    TargetOptions Options = InitTargetOptionsFromCodeGenFlags();
//    Options.DisableIntegratedAS = NoIntegratedAssembler;
//    Options.MCOptions.ShowMCEncoding = ShowMCEncoding;
//    Options.MCOptions.MCUseDwarfDirectory = EnableDwarfDirectory;
//    Options.MCOptions.AsmVerbose = AsmVerbose;

    std::unique_ptr<TargetMachine> target(
            TheTarget->createTargetMachine(TheTriple.getTriple(), MCPU, FeaturesStr,
                                           Options, RelocModel , CMModel, OLvl));

    TargetMachine &Target = *target.get();
    
    PassManager PM;


    TargetLibraryInfo *TLI = new TargetLibraryInfo(TheTriple);

    PM.add(TLI);

    if (const DataLayout *DL = Target.getDataLayout())
        mod->setDataLayout(DL);

    SmallVector<char, 1024*1024*4> *smallVector = new SmallVector<char, 1024*1024*4>();
    raw_svector_ostream svectorOS(*smallVector);
    {
        formatted_raw_ostream FOS(svectorOS);
        
        // Ask the target to add backend passes as necessary.
        /* Wrote "true" in place of "NoVerify" */
        if (Target.addPassesToEmitFile(PM, FOS, FileType, true, nullptr, nullptr)) {
            errs() << argv[0] << ": target does not support generation of this"
            << " file type!\n";
            return 1;
        }
        
        PM.run(*mod);
        
        svectorOS.flush();
    }
    
    //outs() << svectorOS.str().str();
    outs() << "Generated the code.\n";
    
    ///////////////////////// Rtdyld Stuff //////////////////////////////
    
    // Instantiate a dynamic linker.
    TrivialMemoryManager MemMgr;
    RuntimeDyld Dyld(&MemMgr);
    
    // Load the input memory buffer.
    MemoryBuffer *memBuffer = MemoryBuffer::getMemBuffer(svectorOS.str(), "", false);
    ObjectBuffer *Buffer = new ObjectBuffer(memBuffer);
    
    outs() << "InputBuffer created.\n";
    
    // Load the input memory buffer.
    ObjectImage *LoadedObject = Dyld.loadObject(Buffer);
    if (!LoadedObject) {
        errs() << "Dyld error:" << Dyld.getErrorString().str() << "\n";
        exit(1);
    }
    
    outs() << "Object file loaded.\n";
    
    // Resolve all the relocations we can.
    Dyld.resolveRelocations();
    // Clear instruction cache before code will be executed.
    MemMgr.invalidateInstructionCache();
    
    // FIXME: Error out if there are unresolved relocations.
    
    // Get the address of the entry point (_main by default).
    std::string multByMName;
#ifdef __linux__
    multByMName = "multByM";
#else
    multByMName = "_multByM";
#endif
    
    void *MainAddress = Dyld.getSymbolAddress(multByMName);
    if (!MainAddress) {
        errs() << "no definition for '" << multByMName << "'";
        exit(1);
    }
    
    // Invalidate the instruction cache for each loaded function.
    for (unsigned i = 0, e = MemMgr.FunctionMemory.size(); i != e; ++i) {
        sys::MemoryBlock &Data = MemMgr.FunctionMemory[i];
        // Make sure the memory is executable.
        std::string ErrorStr;
        sys::Memory::InvalidateInstructionCache(Data.base(), Data.size());
        if (!sys::Memory::setExecutable(Data, &ErrorStr)) {
            errs() << "unable to mark function executable: '" + ErrorStr + "'";
            exit(1);
        }
    }
    
    // At this point, the function has been loaded.
    
    void (*multByM)(double *, double *) =
    (void(*)(double *, double *)) uintptr_t(MainAddress);
    
    int n = readNValue(matrixName);
    double *v = (double *) malloc(n * sizeof(double));
    double *w = (double *) malloc(n * sizeof(double));
    if (w == NULL || v == NULL) exit(1);
    for (int i = 0; i < n; i++) {
        v[i] = i;
        w[i] = 0;
    }
    
    /* run the function */
    auto start2 = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 5000; i++){
        multByM(v, w);
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2).count();
    outs() << "Run function duration (microseconds): \n" << duration2 / 5000.0 << "\n";
    
    std::chrono::high_resolution_clock::time_point
    llvm_shutdown();
    return 0;
}

