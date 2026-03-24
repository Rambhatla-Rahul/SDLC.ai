
import { PipelineProvider } from '@/context/socket_context';
import LandingPage from '../components/LandingPage';


export default function Home() {
  return (
    <main className="min-h-screen bg-zinc-950">
      
      <PipelineProvider apiBase="https://sdlc-ai-2kpe.onrender.com/">
        
        <LandingPage />
      </PipelineProvider>
    </main>
  );
}
