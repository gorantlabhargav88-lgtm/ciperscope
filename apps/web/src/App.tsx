import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider } from './components/ui/tooltip';
import { AppRoutes } from './routes';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      // Default was unset (0) — every remount of a query (e.g. navigating
      // away from Cases and back) re-fetched immediately even if data was
      // seconds old. 15s balances avoiding redundant request storms from
      // routine navigation against never serving meaningfully stale
      // security/threat data. Pages needing tighter freshness (e.g.
      // Overview's dashboard stats) already set their own shorter
      // `refetchInterval`, which is unaffected by this.
      staleTime: 15_000,
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
