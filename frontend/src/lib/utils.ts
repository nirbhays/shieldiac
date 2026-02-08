import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: "text-red-500",
    HIGH: "text-orange-500",
    MEDIUM: "text-yellow-500",
    LOW: "text-blue-500",
    INFO: "text-gray-400",
  };
  return map[severity] || "text-gray-500";
}

export function gradeColor(grade: string): string {
  const map: Record<string, string> = {
    A: "text-green-600",
    B: "text-blue-600",
    C: "text-yellow-600",
    D: "text-orange-600",
    F: "text-red-600",
  };
  return map[grade] || "text-gray-600";
}
