import { PipelineProvider } from '../../context/socket_context.jsx';
import SdlcOrchestrator from '../../components/SdlcOrchestrator';

export default function OrchestratorPage() {
  return (
    <main className="min-h-screen bg-zinc-950">
      <PipelineProvider apiBase="https://sdlc-ai-2kpe.onrender.com">
        <SdlcOrchestrator />
      </PipelineProvider>
      
    </main>
  );
}
