
import { PipelineProvider } from '@/context/socket_context';
import LandingPage from '../components/LandingPage';


export default function Home() {
  return (
    <main className="min-h-screen bg-zinc-950">
      
      <PipelineProvider apiBase="http://127.0.0.1:8000">
        
        <LandingPage />
      </PipelineProvider>
    </main>
  );
}
