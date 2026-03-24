"use client";

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Sidebar from './orchestrator/Sidebar';
import UserIntent from './orchestrator/UserIntent';
import HITLPanel from './HITLPanel';
import { usePipeline } from '@/context/socket_context';
import ResultPanel from './ResultModal';

const SdlcOrchestrator = () => {
  const [activeStage, setActiveStage] = useState('intent_agent');
  const {status,pausedAt,gateContext,decide,result} = usePipeline();
  // const getView = () => {
  //   switch (activeStage) {
  //     case 'intent_agent':return <UserIntent setActiveStage={setActiveStage}/>
  //     case 'ip_guard_agent': return <RequirementsView />;
  //     case 'planning': return <PlanningView />;
  //     case 'development': return <DevelopmentConsoleView />;
  //     case 'feedback': return <FeedbackView />;
  //     default: return (
  //       <div className="h-full flex items-center justify-center text-zinc-500 flex-col gap-4">
  //         <Activity size={32} className="opacity-50" />
  //         <p>AI is processing this stage in the background...</p>
  //       </div>
  //     );
  //   }
  // };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 flex overflow-hidden font-sans selection:bg-emerald-500/30">
      
      <Sidebar />

      {/* Main Container */}
      <main className="flex-1 flex flex-col min-w-0 bg-[#0a0a0a]">
        
        {/* <ProgressTracker activeStage={activeStage} setActiveStage={setActiveStage} /> */}

        {/* Workspace Canvas (Main Area) */}
        <div className="flex-1 p-6 lg:p-8 overflow-y-auto relative">
          <div className="max-w-5xl mx-auto h-full flex flex-col">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeStage}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className="flex-1"
              >
                {/* {getView()} */}
                
                  {status === "paused" && pausedAt && (
                    <>
                    <div className='absolute p-4 bg-gray-500/30 rounded-md backdrop-blur-md left-0 w-full h-full flex justify-center z-50 items-center'>
                      <HITLPanel
                        pausedAt={pausedAt}
                        gateContext={gateContext}
                        decide={decide}
                      />
                    </div>
                    </>
                    
                  )
                  }
                  {status === "complete" && result && (
                    <>
                    <div className='absolute p-4 bg-gray-500/30 rounded-md backdrop-blur-md left-0 w-full h-full flex justify-center z-50 items-center'>
                      <ResultPanel result={result}/>
                      <button className='w-lg bg-emerald-500' onClick={()=>{setActiveStage('intent_agent');}}>
                        Return
                      </button>
                    </div>
                    </>
                  )}
              
                <UserIntent setActiveStage={setActiveStage}/>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </main>

      {/* Notification Card Fire when event is triggered.  */}
      {/* <InterventionHub /> */}

    </div>
  );
};

export default SdlcOrchestrator;
