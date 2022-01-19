//===---- X86IndirectBranchTracking.cpp - Enables CET IBT mechanism -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines a pass that enables Indirect Branch Tracking (IBT) as part
// of Control-Flow Enforcement Technology (CET).
// The pass adds ENDBR (End Branch) machine instructions at the beginning of
// each basic block or function that is referenced by an indrect jump/call
// instruction.
// The ENDBR instructions have a NOP encoding and as such are ignored in
// targets that do not support CET IBT mechanism.
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"

using namespace llvm;

#define DEBUG_TYPE "x86-indirect-branch-tracking"

cl::opt<bool> IndirectBranchTracking(
    "x86-indirect-branch-tracking", cl::init(false), cl::Hidden,
    cl::desc("Enable X86 indirect branch tracking pass."));

STATISTIC(NumEndBranchAdded, "Number of ENDBR instructions added");

namespace {
class X86IndirectBranchTrackingPass : public MachineFunctionPass {
public:
  X86IndirectBranchTrackingPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "X86 Indirect Branch Tracking";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;

  /// Machine instruction info used throughout the class.
  const X86InstrInfo *TII = nullptr;

  /// Endbr opcode for the current machine function.
  unsigned int EndbrOpcode = 0;

  /// Adds a new ENDBR instruction to the beginning of the MBB.
  /// The function will not add it if already exists.
  /// It will add ENDBR32 or ENDBR64 opcode, depending on the target.
  /// \returns true if the ENDBR was added and false otherwise.
  bool addENDBR(MachineBasicBlock &MBB, MachineBasicBlock::iterator I) const;

  /// Add endbr instruction as the first instruction in functions that can
  /// be reached through indirect calls. This is a coarse-grained IBT scheme.
  bool applyCoarseIBT(MachineFunction &MF);

  /// Add endbr + hash checks as first instructions in functions that can be
  /// reached through indirect calls. This is a fine-grained IBT scheme.
  bool applyFineIBT(MachineFunction &MF);

  /// Spawn FineIBT hash set operations using R11 before indirect calls. Also
  /// swap register if If R11 is used as function pointer for the indirect call.
  bool fixIndirectCalls(MachineFunction &MF);
};

} // end anonymous namespace

char X86IndirectBranchTrackingPass::ID = 0;

FunctionPass *llvm::createX86IndirectBranchTrackingPass() {
  return new X86IndirectBranchTrackingPass();
}

bool X86IndirectBranchTrackingPass::addENDBR(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator I) const {
  assert(TII && "Target instruction info was not initialized");
  assert((X86::ENDBR64 == EndbrOpcode || X86::ENDBR32 == EndbrOpcode) &&
         "Unexpected Endbr opcode");

  // If the MBB/I is empty or the current instruction is not ENDBR,
  // insert ENDBR instruction to the location of I.
  if (I == MBB.end() || I->getOpcode() != EndbrOpcode) {
    BuildMI(MBB, I, MBB.findDebugLoc(I), TII->get(EndbrOpcode));
    ++NumEndBranchAdded;
    return true;
  }
  return false;
}

static bool IsCallReturnTwice(llvm::MachineOperand &MOp) {
  if (!MOp.isGlobal())
    return false;
  const Function *CalleeFn = dyn_cast<Function>(MOp.getGlobal());
  if (!CalleeFn)
    return false;
  AttributeList Attrs = CalleeFn->getAttributes();
  return Attrs.hasFnAttr(Attribute::ReturnsTwice);
}

static unsigned grabR11Replacement(MachineBasicBlock *BB, MachineInstr *I) {
  unsigned AuxReg = 0;
  RegScavenger RS;
  RS.enterBasicBlock(*BB);
  RS.forward(I);
  AuxReg = RS.FindUnusedReg(&X86::GR64RegClass);
  if (!AuxReg) {
    MachineFunction *MF = BB->getParent();
    WithColor::warning()
      << "FineIBT: No register available in " << MF->getName() << ".\n";
  }
  return AuxReg;
}

// Lists functions that should not get an endbr in its prologue.
static bool ignoreList(StringRef Name) {
  if (Name.startswith("__llvm_retpoline_")) return true;
  return false;
}

static bool isKernelInit(Function &F) {
  return (F.hasSection() && F.getSection().startswith(".init.text"));
}

// Checks if function should have an ENDBR in its prologue
static bool needsPrologueENDBR(MachineFunction &MF) {
  Function &F = MF.getFunction();
  Module *M = F.getParent();

  if (F.doesNoCfCheck())
    return false;

  const X86TargetMachine *TM =
      static_cast<const X86TargetMachine *>(&MF.getTarget());
  Metadata *IBTSeal = M->getModuleFlag("ibt-seal");

  switch (TM->getCodeModel()) {
  // Large code model functions always reachable through indirect calls.
  case CodeModel::Large:
    return true;
  // Only address taken functions in LTO'ed kernel are reachable indirectly.
  // IBTSeal implies LTO, thus only check if function is address taken.
  case CodeModel::Kernel:
    // Check if function is in the ignore list.
    if (ignoreList(F.getName()))
      return false;

    // Check if ibt-seal was enabled (implies LTO is being used).
    if (IBTSeal)
      return F.hasAddressTaken();

    // Fall into default case.
    LLVM_FALLTHROUGH;
    // Address taken or externally linked functions may be reachable.
  default:
    return (F.hasAddressTaken() || !F.hasLocalLinkage());
  }
}

bool X86IndirectBranchTrackingPass::fixIndirectCalls(MachineFunction &MF) {
  bool Changed = false;
  unsigned AuxReg;

  for (MachineBasicBlock &BB : MF) {
    for (MachineInstr &I : BB) {
      unsigned Opcode = I.getOpcode();

      switch (Opcode) {
        // If this is an indirect call, we need to set the FineIBT hash.
        case X86::CALL64r:
        case X86::CALL64m:
        case X86::TAILJMPr64:
        case X86::TAILJMPr:
        case X86::TAILJMPm64:
        case X86::TAILJMPm:
        case X86::TAILJMPm64_REX:
        case X86::TAILJMPr64_REX:
          break;
        // Otherwise go to next instruction.
        default:
          continue;
      }

      // Instructions with attribute CoarseCfCheck have Hash == 0. Skip them.
      if (I.getPrototypeHash() == 0) {
        LLVM_DEBUG(WithColor::warning()
                     << "FineIBT: NULL Hash in " << MF.getName() << "\n");
        continue;
      }

      // if R11 is used as a pointer, we need to use a different register.
      MachineOperand &MO = I.getOperand(0);
      if (MO.isReg() && MO.getReg() == X86::R11) {
        AuxReg = grabR11Replacement(&BB, &I);
        if (!AuxReg)
          continue;
        MO.setReg(AuxReg);
        BuildMI(BB, I, DebugLoc(), TII->get(X86::MOV64rr), AuxReg)
          .addReg(X86::R11);
      }

      // for CALL64m/TAILJMPm we need to also check the second register.
      if (Opcode == X86::CALL64m || Opcode == X86::TAILJMPm64) {
        MachineOperand &MO = I.getOperand(2);
        if (MO.isReg() && MO.getReg() == X86::R11) {
          AuxReg = grabR11Replacement(&BB, &I);
          if (!AuxReg)
            continue;
          MO.setReg(AuxReg);
          BuildMI(BB, I, DebugLoc(), TII->get(X86::MOV64rr), AuxReg)
            .addReg(X86::R11);
        }
      }
      Changed = true;
      // Emit the FineIBT hash set operation.
      BuildMI(BB, I, DebugLoc(), TII->get(X86::MOV32ri), X86::R11)
        .addImm(I.getPrototypeHash());
    }
  }
  return Changed;
}

bool X86IndirectBranchTrackingPass::applyFineIBT(MachineFunction &MF) {
  Function &F = MF.getFunction();

  if (!needsPrologueENDBR(MF))
    return false;

  // Get the function's entry block
  MachineBasicBlock *Entry = &MF.front();
  Entry->addLiveIn(X86::R11);

  if (!F.doesCoarseCfCheck() && !isKernelInit(F)) {
    // Create and organize new basic blocks
    // ChkMBB will hold the ENDBR + Hash check
    MachineBasicBlock *ChkMBB = MF.CreateMachineBasicBlock();
    MachineBasicBlock *VltMBB = MF.CreateMachineBasicBlock();

    MF.push_front(VltMBB);
    MF.push_front(ChkMBB);
    MF.RenumberBlocks();

    for (const auto &LI : Entry->liveins()) {
      ChkMBB->addLiveIn(LI);
    }
    ChkMBB->addLiveIn(X86::R11);
    ChkMBB->addSuccessor(Entry);
    ChkMBB->addSuccessor(VltMBB);

    addENDBR(*ChkMBB, ChkMBB->begin());

    uint32_t Hash = F.getFunctionType()->getPrototypeHash();
    BuildMI(ChkMBB, DebugLoc(), TII->get(X86::SUB32ri), X86::R11D)
      .addReg(X86::R11D, RegState::Kill)
      .addImm(Hash);

    MachineInstr *MI = BuildMI(ChkMBB, DebugLoc(), TII->get(X86::JCC_1))
      .addMBB(Entry)
      .addImm(X86::COND_E);
    MI->setDoNotRelax(true);

    // If the check fails, we need to fail. In the long run, we'll replace
    // call __fineibt_handler with an ud2, for less space overhead. For now
    // use call for debugging.
    //BuildMI(VltMBB, DebugLoc(), TII->get(X86::TRAP));
    //BuildMI(VltMBB, DebugLoc(), TII->get(X86::NOOP));
    BuildMI(VltMBB, DebugLoc(), TII->get(X86::CALL64pcrel32))
      .addExternalSymbol("__fineibt_handler");
  } else if (!isKernelInit(F)) {

    MachineBasicBlock *XorMBB = MF.CreateMachineBasicBlock();
    MF.push_front(XorMBB);
    for (const auto &LI : Entry->liveins()) {
      XorMBB->addLiveIn(LI);
    }
    XorMBB->addLiveIn(X86::R11);
    XorMBB->addSuccessor(Entry);
    MF.RenumberBlocks();

    addENDBR(*XorMBB, XorMBB->begin());

    // Zero R11 so it doesn't contain left-over hashes.
    BuildMI(XorMBB, DebugLoc(), TII->get(X86::XOR64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R11);
  } else {
    addENDBR(*Entry, Entry->begin());
  }

  return true;
}

bool X86IndirectBranchTrackingPass::applyCoarseIBT(MachineFunction &MF) {
  // If function is reachable indirectly, mark the first BB with ENDBR.
  if (needsPrologueENDBR(MF)) {
    MachineFunction::iterator MBB = MF.begin();
    return addENDBR(*MBB, MBB->begin());
  }
  return false;
}

bool X86IndirectBranchTrackingPass::runOnMachineFunction(MachineFunction &MF) {
  const X86Subtarget &SubTarget = MF.getSubtarget<X86Subtarget>();

  const Module *M = MF.getMMI().getModule();
  // Check that the cf-protection-branch is enabled.
  Metadata *isCFProtectionSupported = M->getModuleFlag("cf-protection-branch");

  // Check that FineIBT is enabled.
  Metadata *FineIBT = M->getModuleFlag("fine-ibt");

  // NB: We need to enable IBT in jitted code if JIT compiler is CET
  // enabled.
  const X86TargetMachine *TM =
    static_cast<const X86TargetMachine *>(&MF.getTarget());
#ifdef __CET__
  bool isJITwithCET = TM->isJIT();
#else
  bool isJITwithCET = false;
#endif
  if (!isCFProtectionSupported && !IndirectBranchTracking && !isJITwithCET)
    return false;

  // True if the current MF was changed and false otherwise.
  bool Changed = false;

  TII = SubTarget.getInstrInfo();
  EndbrOpcode = SubTarget.is64Bit() ? X86::ENDBR64 : X86::ENDBR32;

  if (FineIBT) {
    Changed |= applyFineIBT(MF);
    Changed |= fixIndirectCalls(MF);
  } else {
    Changed |= applyCoarseIBT(MF);
  }

  // If function is reachable indirectly, mark the first BB with ENDBR.
  if (needsPrologueENDBR(MF)) {
    MachineFunction::iterator MBB = MF.begin();
    Changed |= addENDBR(*MBB, MBB->begin());
  }

  for (MachineBasicBlock &MBB : MF) {
    // Find all basic blocks that their address was taken (for example
    // in the case of indirect jump) and add ENDBR instruction.
    if (MBB.hasAddressTaken())
      Changed |= addENDBR(MBB, MBB.begin());

    for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
      if (I->isCall() && I->getNumOperands() > 0 &&
          IsCallReturnTwice(I->getOperand(0))) {
        Changed |= addENDBR(MBB, std::next(I));
      }
    }

    // Exception handle may indirectly jump to catch pad, So we should add
    // ENDBR before catch pad instructions. For SjLj exception model, it will
    // create a new BB(new landingpad) indirectly jump to the old landingpad.
    if (TM->Options.ExceptionModel == ExceptionHandling::SjLj) {
      for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
        // New Landingpad BB without EHLabel.
          if (MBB.isEHPad()) {
            if (I->isDebugInstr())
              continue;
            Changed |= addENDBR(MBB, I);
            break;
          } else if (I->isEHLabel()) {
            // Old Landingpad BB (is not Landingpad now) with
            // the the old "callee" EHLabel.
              MCSymbol *Sym = I->getOperand(0).getMCSymbol();
            if (!MF.hasCallSiteLandingPad(Sym))
              continue;
            Changed |= addENDBR(MBB, std::next(I));
            break;
          }
      }
    } else if (MBB.isEHPad()){
      for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
        if (!I->isEHLabel())
          continue;
        Changed |= addENDBR(MBB, std::next(I));
        break;
      }
    }
  }
  return Changed;
}
