import { Loader2 } from 'lucide-react';

/** Suspense fallback for lazy-loaded routes — matches the Loader2 spinner pattern already used for data loading (Cases.tsx, CaseDetail.tsx, etc). */
export function RouteLoading() {
  return (
    <div className="flex justify-center items-center py-20">
      <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
    </div>
  );
}
