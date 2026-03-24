"use client";

import Link from 'next/link';
import { motion } from 'framer-motion';
import { ArrowRight, Workflow, Zap, Code2, GitMerge, FileText, CheckCircle2, Terminal } from 'lucide-react';

const Features = [
  {
    icon: FileText,
    title: "AI-Driven Requirements",
    description: "Chat with our intelligent agents to instantly generate comprehensive PRDs and architecture plans."
  },
  {
    icon: Code2,
    title: "Autonomous Development",
    description: "Watch as AI writes production-ready code in real-time. Pause, review, and edit at any moment."
  },
  {
    icon: GitMerge,
    title: "Human-in-the-Loop",
    description: "Retain complete control. Approve architecture changes, review unsure logic, and guide the AI when needed."
  }
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 font-sans selection:bg-emerald-500/30">
      
      {/* Navigation Layer */}
      <nav className="fixed top-0 inset-x-0 h-16 border-b border-zinc-800/60 bg-zinc-950/80 backdrop-blur-md z-50 flex items-center justify-between px-6 lg:px-12">
        <div className="flex items-center gap-2 text-emerald-500">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <Workflow size={18} />
          </div>
          <span className="font-bold tracking-tight text-lg text-white">SDLC<span className="text-zinc-500">.ai</span></span>
        </div>
        <div className="flex items-center gap-6">
          <Link href="/docs" className="text-sm text-zinc-400 hover:text-white transition-colors hidden md:block">Documentation</Link>
          <Link href="/login" className="text-sm text-zinc-400 hover:text-white transition-colors">Sign In</Link>
          <Link href="/orchestrator" className="text-sm font-medium bg-zinc-100 text-zinc-900 px-4 py-2 rounded-full hover:bg-white transition-colors">
            Start Building
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 md:pt-48 md:pb-32 px-6 lg:px-12 overflow-hidden flex flex-col items-center text-center">
        
        {/* Background Gradients */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-3xl h-[400px] bg-emerald-500/10 blur-[120px] rounded-full point-events-none" />
        <div className="absolute top-32 left-1/2 -translate-x-1/2 w-full max-w-md h-[300px] bg-indigo-500/10 blur-[100px] rounded-full point-events-none" />

        <div className="relative z-10 max-w-4xl mx-auto">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-900/80 border border-zinc-800 text-xs text-zinc-300 mb-8"
          >
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            Introducing SDLC Orchestrator Beta
          </motion.div>
          
          <motion.h1 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-5xl md:text-7xl font-bold tracking-tight mb-8 leading-tight"
          >
            The Next-Generation <br className="hidden md:block"/>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-indigo-400">Software Factory.</span>
          </motion.h1>
          
          <motion.p 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg md:text-xl text-zinc-400 mb-10 max-w-2xl mx-auto leading-relaxed"
          >
            Automate your entire development lifecycle from requirements to deployment. Retain absolute control with our Human-in-the-Loop philosophy.
          </motion.p>
          
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link 
              href="/orchestrator" 
              className="flex items-center gap-2 h-12 px-8 rounded-full bg-emerald-500 text-zinc-950 font-medium hover:bg-emerald-400 transition-all hover:scale-105 active:scale-95"
            >
              Enter Workspace <ArrowRight size={18} />
            </Link>
            <button className="flex items-center gap-2 h-12 px-8 rounded-full bg-zinc-900 text-zinc-300 font-medium hover:bg-zinc-800 border border-zinc-800 transition-all">
              Watch Demo <Zap size={18} className="text-zinc-500" />
            </button>
          </motion.div>
        </div>
      </section>

      {/* Feature Section */}
      <section className="py-24 px-6 lg:px-12 bg-zinc-950 border-t border-zinc-900 border-b relative">
        <div className="max-w-6xl mx-auto relative z-10">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Command the AI. Don't let it command you.</h2>
            <p className="text-zinc-400 max-w-2xl mx-auto">Our orchestrator is built around constant feedback loops, ensuring every line of code aligns with your architecture.</p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {Features.map((feature, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="bg-zinc-900/30 border border-zinc-800/50 p-8 rounded-2xl hover:bg-zinc-900/60 transition-colors group"
              >
                <div className="w-12 h-12 rounded-xl bg-zinc-800 flex items-center justify-center mb-6 text-zinc-400 group-hover:text-emerald-400 group-hover:bg-emerald-500/10 transition-colors border border-zinc-700/50 group-hover:border-emerald-500/20">
                  <feature.icon size={24} />
                </div>
                <h3 className="text-xl font-semibold text-zinc-200 mb-3">{feature.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Proof Point / Mini Demo Section */}
      <section className="py-32 px-6 lg:px-12 relative overflow-hidden">
        <div className="max-w-6xl mx-auto flex flex-col lg:flex-row items-center gap-16 relative z-10">
          <div className="flex-1 space-y-8">
            <h2 className="text-3xl md:text-4xl font-bold leading-tight">
              Visibility at <br/> Every Stage.
            </h2>
            <p className="text-zinc-400 text-lg">
              SDLC.ai visualizes the entire process in a single, unified workspace. See exactly what the AI is focused on, step-by-step.
            </p>
            <ul className="space-y-4">
              {[
                "Linear progress tracking across all SDLC phases",
                "Live streaming file-system modifications",
                "Instant rollback capability on questionable iterations"
              ].map((item, i) => (
                <li key={i} className="flex items-start gap-3 text-zinc-300">
                  <CheckCircle2 size={20} className="text-emerald-500 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="flex-1 w-full">
            <div className="relative rounded-2xl border border-zinc-800 bg-zinc-900/50 p-2 shadow-2xl">
              {/* Fake UI Header */}
              <div className="flex items-center gap-2 mb-4 px-2 pt-2">
                 <div className="w-3 h-3 rounded-full bg-zinc-700"/>
                 <div className="w-3 h-3 rounded-full bg-zinc-700"/>
                 <div className="w-3 h-3 rounded-full bg-zinc-700"/>
              </div>
              <div className="bg-black rounded-xl border border-zinc-800 h-64 flex flex-col p-4 relative overflow-hidden">
                <div className="flex items-center gap-2 mb-4">
                   <div className="w-4 h-4 rounded bg-emerald-500/20 flex items-center justify-center text-emerald-500"><Terminal size={10}/></div>
                   <span className="text-xs text-zinc-500 font-mono">Building Feature...</span>
                </div>
                {/* Fake code scroll */}
                <div className="space-y-2 opacity-50">
                  <div className="h-2 w-3/4 bg-zinc-800 rounded"/>
                  <div className="h-2 w-1/2 bg-zinc-800 rounded ml-4"/>
                  <div className="h-2 w-5/6 bg-zinc-800 rounded ml-4"/>
                  <div className="h-2 w-2/3 bg-zinc-800 rounded ml-8"/>
                  <div className="h-2 w-1/3 bg-zinc-800 rounded ml-8"/>
                  <div className="h-2 w-1/2 bg-zinc-800 rounded"/>
                </div>
                
                {/* Overlay Intervention Hub Fake */}
                <div className="absolute bottom-4 right-4 bg-zinc-900 border border-amber-500/30 p-3 rounded-lg shadow-xl w-48 backdrop-blur-md">
                   <div className="text-[10px] text-amber-500 font-bold mb-1 flex items-center gap-1">
                     <span className="flex h-1.5 w-1.5 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-amber-500"></span>
                      </span> 
                      HUMAN REQUIRED
                    </div>
                   <div className="text-xs text-zinc-300">Approval needed.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-900 py-12 px-6 lg:px-12 text-center text-zinc-600 text-sm">
        <p>© 2026 SDLC.ai Platform. Built with next-generation agentic workflows.</p>
      </footer>
    </div>
  );
}
