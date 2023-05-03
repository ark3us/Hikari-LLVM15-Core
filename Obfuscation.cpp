// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
/*
  Hikari 's own "Pass Scheduler".
  Because currently there is no way to add dependency to transform passes
  Ref : http://lists.llvm.org/pipermail/llvm-dev/2011-February/038109.html
*/
#include "llvm/Transforms/Obfuscation/Obfuscation.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Obfuscation/Utils.h"

using namespace llvm;

// Begin Obfuscator Options
static cl::opt<uint64_t> AesSeed("aesSeed", cl::init(0x1337),
                                 cl::desc("seed for the PRNG"));
static cl::opt<bool> EnableAntiClassDump("enable-acdobf", cl::init(false),
                                         cl::NotHidden,
                                         cl::desc("Enable AntiClassDump."));
static cl::opt<bool> EnableAntiHooking("enable-antihook", cl::init(false),
                                       cl::NotHidden,
                                       cl::desc("Enable AntiHooking."));
static cl::opt<bool> EnableAntiDebugging("enable-adb", cl::init(false),
                                         cl::NotHidden,
                                         cl::desc("Enable AntiDebugging."));
static cl::opt<bool>
    EnableBogusControlFlow("enable-bcfobf", cl::init(false), cl::NotHidden,
                           cl::desc("Enable BogusControlFlow."));
static cl::opt<bool> EnableFlattening("enable-cffobf", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Enable Flattening."));
static cl::opt<bool>
    EnableBasicBlockSplit("enable-splitobf", cl::init(false), cl::NotHidden,
                          cl::desc("Enable BasicBlockSpliting."));
static cl::opt<bool>
    EnableSubstitution("enable-subobf", cl::init(false), cl::NotHidden,
                       cl::desc("Enable Instruction Substitution."));
static cl::opt<bool> EnableAllObfuscation("enable-allobf", cl::init(false),
                                          cl::NotHidden,
                                          cl::desc("Enable All Obfuscation."));
static cl::opt<bool> EnableFunctionCallObfuscate(
    "enable-fco", cl::init(false), cl::NotHidden,
    cl::desc("Enable Function CallSite Obfuscation."));
static cl::opt<bool>
    EnableStringEncryption("enable-strcry", cl::init(false), cl::NotHidden,
                           cl::desc("Enable String Encryption."));
static cl::opt<bool>
    EnableConstantEncryption("enable-constenc", cl::init(false), cl::NotHidden,
                             cl::desc("Enable Constant Encryption."));
static cl::opt<bool>
    EnableIndirectBranching("enable-indibran", cl::init(false), cl::NotHidden,
                            cl::desc("Enable Indirect Branching."));
static cl::opt<bool>
    EnableFunctionWrapper("enable-funcwra", cl::init(false), cl::NotHidden,
                          cl::desc("Enable Function Wrapper."));
// End Obfuscator Options

static void LoadEnv(void) {
  errs() << "LoadEnv\n";
  if (getenv("SPLITOBF")) {
    errs() << "Enable BasicBlockSpliting\n";
    EnableBasicBlockSplit = true;
  }
  if (getenv("SUBOBF")) {
    errs() << "Enable Instruction Substitution\n";
    EnableSubstitution = true;
  }
  if (getenv("ALLOBF")) {
    errs() << "Enable All Obfuscation\n";
    EnableAllObfuscation = true;
  }
  if (getenv("FCO")) {
    errs() << "Enable Function CallSite Obfuscation\n";
    EnableFunctionCallObfuscate = true;
  }
  if (getenv("STRCRY")) {
    errs() << "Enable String Encryption\n";
    EnableStringEncryption = true;
  }
  if (getenv("INDIBRAN")) {
    errs() << "Enable Indirect Branching\n";
    EnableIndirectBranching = true;
  }
  if (getenv("FUNCWRA")) {
    errs() << "Enable Function Wrapper\n";
    EnableFunctionWrapper = true; // Broken
  }
  if (getenv("BCFOBF")) {
    errs() << "Enable BogusControlFlow\n";
    EnableBogusControlFlow = true;
  }
  if (getenv("ACDOBF")) {
    errs() << "Enable AntiClassDump\n";
    EnableAntiClassDump = true;
  }
  if (getenv("CFFOBF")) {
    errs() << "Enable Flattening\n";
    EnableFlattening = true;
  }
  if (getenv("CONSTENC")) {
    errs() << "Enable Constant Encryption\n";
    EnableConstantEncryption = true;
  }
  if (getenv("ANTIHOOK")) {
    errs() << "Enable AntiHooking\n";
    EnableAntiHooking = true;
  }
  if (getenv("ADB")) {
    errs() << "Enable AntiDebugging\n";
    EnableAntiDebugging = true;
  }
}
namespace llvm {
struct Obfuscation : public ModulePass {
  static char ID;
  Obfuscation() : ModulePass(ID) {
    initializeObfuscationPass(*PassRegistry::getPassRegistry());
  }
  StringRef getPassName() const override {
    return "HikariObfuscationScheduler";
  }
  bool runOnModule(Module &M) override {
    TimerGroup *tg =
        new TimerGroup("Obfuscation Timer Group", "Obfuscation Timer Group");
    Timer *timer = new Timer("Obfuscation Timer", "Obfuscation Timer", *tg);
    timer->startTimer();

    errs() << "Running Hikari On " << M.getSourceFileName() << "\n";

    annotation2Metadata(M);

    ModulePass *MP = createAntiHookPass(EnableAntiHooking);
    MP->doInitialization(M);
    MP->runOnModule(M);
    delete MP;
    // Initial ACD Pass
    if (EnableAllObfuscation || EnableAntiClassDump) {
      ModulePass *P = createAntiClassDumpPass();
      P->doInitialization(M);
      P->runOnModule(M);
      delete P;
    }
    // Now do FCO
    FunctionPass *FP = createFunctionCallObfuscatePass(
        EnableAllObfuscation || EnableFunctionCallObfuscate);
    for (Function &F : M)
      if (!F.isDeclaration())
        FP->runOnFunction(F);
    delete FP;
    MP = createAntiDebuggingPass(EnableAntiDebugging);
    MP->runOnModule(M);
    delete MP;
    // Now Encrypt Strings
    MP = createStringEncryptionPass(EnableAllObfuscation ||
                                    EnableStringEncryption);
    MP->runOnModule(M);
    delete MP;
    // Now perform Function-Level Obfuscation
    for (Function &F : M)
      if (!F.isDeclaration()) {
        FunctionPass *P = nullptr;
        P = createSplitBasicBlockPass(EnableAllObfuscation ||
                                      EnableBasicBlockSplit);
        P->runOnFunction(F);
        delete P;
        P = createBogusControlFlowPass(EnableAllObfuscation ||
                                       EnableBogusControlFlow);
        P->runOnFunction(F);
        delete P;
        P = createFlatteningPass(EnableAllObfuscation || EnableFlattening);
        P->runOnFunction(F);
        delete P;
        P = createSubstitutionPass(EnableAllObfuscation || EnableSubstitution);
        P->runOnFunction(F);
        delete P;
      }
    MP = createConstantEncryptionPass(EnableConstantEncryption);
    MP->runOnModule(M);
    delete MP;
    errs() << "Doing Post-Run Cleanup\n";
    FunctionPass *P = createIndirectBranchPass(EnableAllObfuscation ||
                                               EnableIndirectBranching);
    for (Function &F : M)
      if (!F.isDeclaration())
        P->runOnFunction(F);
    delete P;
    MP = createFunctionWrapperPass(EnableAllObfuscation ||
                                   EnableFunctionWrapper);
    MP->runOnModule(M);
    delete MP;
    // Cleanup Flags
    std::vector<Function *> toDelete;
    for (Function &F : M)
      if (F.isDeclaration() && F.hasName() && F.getName().contains("hikari_")) {
        for (User *U : F.users())
          if (Instruction *Inst = dyn_cast<Instruction>(U))
            Inst->eraseFromParent();
        toDelete.emplace_back(&F);
      }
    for (Function *F : toDelete)
      F->eraseFromParent();

    timer->stopTimer();
    errs() << "Hikari Out\n";
    errs() << "Spend Time: "
           << format("%.7f", timer->getTotalTime().getWallTime()) << "s"
           << "\n";
    tg->clearAll();
    return true;
  } // End runOnModule
};
ModulePass *createObfuscationLegacyPass() {
  LoadEnv();
  if (AesSeed != 0x1337) {
    cryptoutils->prng_seed(AesSeed);
  } else {
    cryptoutils->prng_seed();
  }
  errs() << "Initializing Hikari Core with Revision ID:" << GIT_COMMIT_HASH
         << "\n";
  return new Obfuscation();
}

PreservedAnalyses ObfuscationPass::run(Module &M, ModuleAnalysisManager &MAM) {
  if (createObfuscationLegacyPass()->runOnModule(M)) {
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

} // namespace llvm
char Obfuscation::ID = 0;
INITIALIZE_PASS_BEGIN(Obfuscation, "obfus", "Enable Obfuscation", false, false)
INITIALIZE_PASS_DEPENDENCY(AntiClassDump);
INITIALIZE_PASS_DEPENDENCY(BogusControlFlow);
INITIALIZE_PASS_DEPENDENCY(Flattening);
INITIALIZE_PASS_DEPENDENCY(FunctionCallObfuscate);
INITIALIZE_PASS_DEPENDENCY(IndirectBranch);
INITIALIZE_PASS_DEPENDENCY(SplitBasicBlock);
INITIALIZE_PASS_DEPENDENCY(StringEncryption);
INITIALIZE_PASS_DEPENDENCY(Substitution);
INITIALIZE_PASS_END(Obfuscation, "obfus", "Enable Obfuscation", false, false)
