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

#include "llvm/ADT/StringMap.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/ExecutionEngine/RTDyldMemoryManager.h"
#include "llvm/ExecutionEngine/RuntimeDyld.h"
#include "llvm/ExecutionEngine/RuntimeDyldChecker.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Memory.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"


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
    
    void addDummySymbol(const std::string &Name, uint64_t Addr) {
        DummyExterns[Name] = Addr;
    }
    
    RuntimeDyld::SymbolInfo findSymbol(const std::string &Name) override {
        auto I = DummyExterns.find(Name);
        
        if (I != DummyExterns.end())
            return RuntimeDyld::SymbolInfo(I->second, JITSymbolFlags::Exported);
            
            return RTDyldMemoryManager::findSymbol(Name);
            }
    
    void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr,
                          size_t Size) override {}
    void deregisterEHFrames(uint8_t *Addr, uint64_t LoadAddr,
                            size_t Size) override {}
private:
    std::map<std::string, uint64_t> DummyExterns;
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
    std::unique_ptr<MIRParser> MIR;

    std::string filePath = "data/" + matrixName + "/" + matrixName + "_CSRbyNZ/generated_merged.ll";
    std::unique_ptr<Module> M = parseIRFile(filePath, diag, Context);
    if (!M) {
        errs() << "No such matrix";
        return 1;
    }

    // Begin LLC-like implementation
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
    FileType = TargetMachine::CGFT_ObjectFile;

    TargetOptions Options = InitTargetOptionsFromCodeGenFlags();
//    Options.DisableIntegratedAS = NoIntegratedAssembler;
//    Options.MCOptions.ShowMCEncoding = ShowMCEncoding;
//    Options.MCOptions.MCUseDwarfDirectory = EnableDwarfDirectory;
//    Options.MCOptions.AsmVerbose = AsmVerbose;

    std::unique_ptr<TargetMachine> Target(
            TheTarget->createTargetMachine(TheTriple.getTriple(), CPUStr, FeaturesStr,
                                           Options, RelocModel , CMModel, OLvl));

    assert(Target && "Could not allocate target machine!");

    legacy::PassManager PM;


    TargetLibraryInfoImpl TLII(Triple(M->getTargetTriple()));

//    if (DisableSimplifyLibCalls)
//        TLII.disableAllFunctions();

    PM.add(new TargetLibraryInfoWrapperPass(TLII));

    if (const DataLayout *DL = Target->getDataLayout())
        M->setDataLayout(*DL);

    setFunctionAttributes(CPUStr, FeaturesStr, *M);
  
    SmallVector<char, 1024*1024*4> *smallVector = new SmallVector<char, 1024*1024*4>();
    raw_svector_ostream svectorOS(*smallVector);
    raw_pwrite_stream *OS = &svectorOS;
  
    // Ask the target to add backend passes as necessary.
    /* Wrote "true" in place of "NoVerify" */
    if (Target->addPassesToEmitFile(PM, *OS, FileType, true, nullptr,
                                    nullptr, nullptr, MIR.get())) {
        errs() << argv[0] << ": target does not support generation of this"
        << " file type!\n";
        return 1;
    }
    
    PM.run(*M);
    //outs() << svectorOS.str().str();
    
    svectorOS.flush();
    
    outs() << "Generated the code.\n";
    
    ///////////////////////// Rtdyld Stuff //////////////////////////////
    
    // Instantiate a dynamic linker.
    TrivialMemoryManager MemMgr;
    RuntimeDyld Dyld(MemMgr, MemMgr);
    
    // FIXME: Preserve buffers until resolveRelocations time to work around a bug
    //        in RuntimeDyldELF.
    // This fixme should be fixed ASAP. This is a very brittle workaround.
    std::vector<std::unique_ptr<MemoryBuffer>> InputBuffers;
    
    // Load the input memory buffer.
    ErrorOr<std::unique_ptr<MemoryBuffer>> InputBuffer = MemoryBuffer::getMemBuffer(svectorOS.str());
    ErrorOr<std::unique_ptr<ObjectFile>> MaybeObj(ObjectFile::createObjectFile((*InputBuffer)->getMemBufferRef()));
    outs() << "InputBuffer created.\n";
    
    if (std::error_code EC = MaybeObj.getError()) {
        errs() << "unable to create object file: '" + EC.message() + "'";
        exit(1);
    }
    
    ObjectFile &Obj = **MaybeObj;
    InputBuffers.push_back(std::move(*InputBuffer));
    
    // Load the object file
    Dyld.loadObject(Obj);
    if (Dyld.hasError()) {
        errs() << "Dyld error: " << Dyld.getErrorString();
        exit(1);
    }
    
    outs() << "Object file loaded.\n";
    
    // Resolve all the relocations we can.
    Dyld.resolveRelocations();
    // Clear instruction cache before code will be executed.
    MemMgr.invalidateInstructionCache();
    
    // FIXME: Error out if there are unresolved relocations.
    
    // Get the address of the entry point (_main by default).
    void *MainAddress = Dyld.getSymbolLocalAddress("_multByM");
    if (!MainAddress) {
        errs() << "no definition for '_multByM'";
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
    
    
    llvm_shutdown();
    return 0;
}

