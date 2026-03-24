import { PipelineProvider } from '../../context/socket_context.jsx';
import SdlcOrchestrator from '../../components/SdlcOrchestrator';

export default function OrchestratorPage() {
  return (
    <main className="min-h-screen bg-zinc-950">
      <PipelineProvider apiBase="http://127.0.0.1:8000">
        <SdlcOrchestrator />
      </PipelineProvider>
      
    </main>
  );
}
