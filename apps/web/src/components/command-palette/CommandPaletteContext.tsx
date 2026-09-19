import { createContext, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

interface CommandPaletteContextType {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const CommandPaletteContext = createContext<CommandPaletteContextType | undefined>(undefined);

export const CommandPaletteProvider = ({ children }: { children: ReactNode }) => {
  const [open, setOpen] = useState(false);
  const value = useMemo(() => ({ open, setOpen }), [open]);
  return <CommandPaletteContext.Provider value={value}>{children}</CommandPaletteContext.Provider>;
};

export const useCommandPalette = () => {
  const ctx = useContext(CommandPaletteContext);
  if (!ctx) throw new Error('useCommandPalette must be used within a CommandPaletteProvider');
  return ctx;
};
