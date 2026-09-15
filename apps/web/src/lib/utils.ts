import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function defangUrl(url: string | null | undefined): string {
  if (!url) return '';

  // Replace http and https with hxxp and hxxps
  let defanged = url.replace(/^http(s?):\/\//i, 'hxxp$1://');

  // Replace 'javascript:' with 'javascr!pt:'
  defanged = defanged.replace(/^javascript:/i, 'javascr!pt:');

  // Defang dots in the domain (but keep the slashes untouched as much as possible)
  // For simplicity, defang dots in the whole string after scheme
  // A safer approach: defang the first dot before the path, or just replace all dots with [.]
  defanged = defanged.replace(/\./g, '[.]');

  return defanged;
}
