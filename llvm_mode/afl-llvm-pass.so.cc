/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Michal Zalewski <lcamtuf@google.com> and
              Christian Holler <choller@mozilla.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault. Partial instrumentation support added by
   Christian Holler.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { 
        char* instWhiteListFilename = getenv("AFL_INST_WHITELIST");
        if (instWhiteListFilename) {
          std::ifstream fileStream;
          fileStream.open(instWhiteListFilename);
          if (!fileStream) report_fatal_error("Unable to open AFL_INST_WHITELIST");

          std::string line;
          getline(fileStream, line);
          while (fileStream) {
            myWhitelist.push_back(line);
            getline(fileStream, line);
          }
        }

        myWriteCoverageMap = !!getenv("AFL_WRITE_COVERAGE_MAP");
      }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

    protected:

      std::list<std::string> myWhitelist;
      bool myWriteCoverageMap;
  };

}


char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (getenv("AFL_CC_VERBOSE") || (isatty(2) && !getenv("AFL_QUIET"))) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  GlobalVariable *AFLFuncIdPtr =
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_func_id_ptr");

  /* Instrument all the things! */

  int inst_blocks = 0;

  /* Output file for coverage map, only used if requested */
  std::ofstream covMapStream;

  for (auto &F : M) {

    /* Make up an ID for this function */
    unsigned int cur_func = R(MAP_SIZE);

    /* Iterate over all blocks and just store them in a vector because
     * we will be modifying the basic blocks in F as we go, so iterating
     * over F while instrumenting won't work */
    std::vector<BasicBlock *> targetBlocks;
    for (auto &BB : F)
      targetBlocks.push_back(&BB);

    for (auto *BB : targetBlocks) {
      BasicBlock::iterator IP = BB->getFirstInsertionPt();

      unsigned int instLine;
      StringRef instFilename;

      /* Only do filename and line resolving when we actually need it */
      if (myWriteCoverageMap || !myWhitelist.empty()) {

          /* Get the current location using debug information.
           * For now, just instrument the block if we are not able
           * to determine our location. */
          DebugLoc Loc = IP->getDebugLoc();
#ifdef LLVM_OLD_DEBUG_API
          if ( !Loc.isUnknown() ) {
#else
          if ( Loc ) {
#endif /* LLVM_OLD_DEBUG_API */

#ifdef LLVM_OLD_DEBUG_API
              DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
              DILocation oDILoc = cDILoc.getOrigLocation();

              instLine = oDILoc.getLineNumber();
              instFilename = oDILoc.getFilename();
              

              if (instFilename.str().empty()) {
                  /* If the original location is empty, use the actual location */
                  instFilename = cDILoc.getFilename();
                  instLine = cDILoc.getLineNumber();
              }
#else
              DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

              instLine = cDILoc->getLine();
              instFilename = cDILoc->getFilename();

              if (instFilename.str().empty()) {
                  /* If the original location is empty, try using the inlined location */
                  DILocation *oDILoc = cDILoc->getInlinedAt();
                  if (oDILoc) {
                      instFilename = oDILoc->getFilename();
                      instLine = oDILoc->getLine();
                  }
              }
#endif /* LLVM_OLD_DEBUG_API */
          }
      }

      if (!myWhitelist.empty()) {
          bool instrumentBlock = false;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {
              for (std::list<std::string>::iterator it = myWhitelist.begin(); it != myWhitelist.end(); ++it) {
                  /* We don't check for filename equality here because
                   * filenames might actually be full paths. Instead we
                   * check that the actual filename ends in the filename
                   * specified in the list. */
                  if (instFilename.str().length() >= it->length()) {
                      if (instFilename.str().compare(instFilename.str().length() - it->length(), it->length(), *it) == 0) {
                          instrumentBlock = true;
                          break;
                      }
                  }
              }
          }

          /* Either we couldn't figure out our location or the location is
           * not whitelisted, so we skip instrumentation. */
          if (!instrumentBlock) continue;
      }

      if (R(100) >= inst_ratio) continue;

      /* By now, we know that we are supposed to instrument this basic block */

      /* Step 1: Write conditional code into BB */

      IRBuilder<> IRB(&(*IP));

      /* 1a: Dereference __afl_func_id_ptr */

      Value *AFLFuncId = IRB.CreateLoad(AFLFuncIdPtr);

      /* 1b: Load __afl_func_id_ptr value and compare it to our function id */

      Value *funcIDA = IRB.CreateLoad(AFLFuncId);
      Value *funcIDB = ConstantInt::get(Int32Ty, cur_func);
      Value *cond1 = IRB.CreateICmpEQ(funcIDA, funcIDB);
      Value *cond2 = IRB.CreateICmpEQ(funcIDA, ConstantInt::get(Int8Ty, 0));
      Value *cond = IRB.CreateOr(cond1, cond2);

      /* Step 2: Split the basic block into two so we can branch */
      
      TerminatorInst* thenInst = SplitBlockAndInsertIfThen(cond, &(*IP), false);

      /* Step 3: Write coverage code into our new then block */

      IRB.SetInsertPoint(thenInst);

      /* 3a: Make up cur_loc */

      unsigned int cur_loc = R(MAP_SIZE);
      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* 3b: Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* 3c: Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* 3d: Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* 3f: Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Done, pfew... */

      inst_blocks++;

      /* Write coverage map data */
      if (myWriteCoverageMap) {
          /* Open output file for coverage map, if not open yet */
          if (!covMapStream.is_open()) {
              /* Randomize the identifier for the current CU */
              unsigned int cur_cu = R(MAP_SIZE);
              std::string covMapFilename = std::to_string(cur_cu) + ".covmap";
              covMapStream.open(covMapFilename);
              if (!covMapStream)
                  report_fatal_error("Unable to open AFL_COVERAGE_MAP for writing");
          }

          covMapStream << cur_loc << " " << cur_func;

          if (F.hasName())
              covMapStream << " " << F.getName().str();

          if (!instFilename.str().empty())
              covMapStream << " " << instLine << " " << instFilename.str();

          covMapStream << std::endl;
      }
    }
  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
             inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
