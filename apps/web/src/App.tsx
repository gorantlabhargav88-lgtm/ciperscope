import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider } from './components/ui/tooltip';
import { AppRoutes } from './routes';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={200}>
        <AppRoutes />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
